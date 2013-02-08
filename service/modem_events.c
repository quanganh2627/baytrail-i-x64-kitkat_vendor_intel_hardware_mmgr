/* Modem Manager - modem events source file
 **
 ** Copyright (C) Intel 2012
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 **
 */

#include <errno.h>
#include <linux/mdm_ctrl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "crash_logger.h"
#include "errors.h"
#include "file.h"
#include "java_intent.h"
#include "logs.h"
#include "modem_events.h"
#include "mux.h"
#include "timer_events.h"
#include "tty.h"

/* wakelocks declaration */
#define WAKE_LOCK_SYSFS "/sys/power/wake_lock"
#define WAKE_UNLOCK_SYSFS "/sys/power/wake_unlock"

#define READ_SIZE 1024

/**
 * update mcd poll
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
inline e_mmgr_errors_t set_mcd_poll_states(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    LOG_DEBUG("update mcd states filter: 0x%.2X", mmgr->info.polled_states);
    if (ioctl(mmgr->info.fd_mcd, MDM_CTRL_SET_POLLED_STATES,
              &mmgr->info.polled_states) == -1) {
        LOG_DEBUG("failed to set Modem Control Driver polled states: %s",
                  strerror(errno));
        ret = E_ERR_FAILED;
    }

out:
    return ret;
}

/**
 * add new tty file descriptor to epoll
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
static e_mmgr_errors_t update_modem_tty(mmgr_data_t *mmgr)
{
    struct epoll_event ev;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    ev.events = EPOLLIN;
    ev.data.fd = mmgr->fd_tty;
    if (epoll_ctl(mmgr->epollfd, EPOLL_CTL_ADD, mmgr->fd_tty, &ev) == -1) {
        LOG_ERROR("Error during epoll_ctl. fd=%d (%s)",
                  mmgr->fd_tty, strerror(errno));
        ret = E_ERR_FAILED;
        goto out;
    }

    mmgr->info.polled_states = MDM_CTRL_STATE_COREDUMP | MDM_CTRL_STATE_OFF;

    ret = set_mcd_poll_states(mmgr);

out:
    return ret;
}

/**
 * handle E_EL_MODEM_WARM_RESET pre reset escalation state
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr or/and modem_started is/are NULL
 * @return E_ERR_FAILED if reset not performed
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t state_modem_warm_reset(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->reset.state != E_OPERATION_SKIP) {
        inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_WARM_RESET);
        broadcast_msg(E_MSG_INTENT_MODEM_WARM_RESET);
    }
out:
    return ret;
}

/**
 * handle E_EL_MODEM_COLD_RESET pre reset escalation state
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr or/and modem_started is/are NULL
 * @return E_ERR_FAILED if reset not performed
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t state_modem_cold_reset(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->reset.state == E_OPERATION_WAIT) {
        mmgr->client_notification = E_MMGR_NOTIFY_MODEM_COLD_RESET;
        inform_all_clients(&mmgr->clients, mmgr->client_notification);
        LOG_DEBUG("need to ack all clients");
        mmgr->events.inform_down = false;
        start_timer(&mmgr->timer, E_TIMER_COLD_RESET_ACK);
        ret = E_ERR_FAILED;
    } else {
        broadcast_msg(E_MSG_INTENT_MODEM_COLD_RESET);
        reset_cold_ack(&mmgr->clients);
        stop_timer(&mmgr->timer, E_TIMER_COLD_RESET_ACK);
    }
out:
    return ret;
}

/**
 * handle E_EL_PLATFORM_REBOOT pre reset escalation state
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr or/and modem_started is/are NULL
 * @return E_ERR_FAILED if reset not performed
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t state_platform_reboot(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    create_empty_file(CL_REBOOT_FILE, CL_FILE_PERMISSIONS);
    /* inform crashloger that the platform will be rebooted */
    mmgr->client_notification = E_MMGR_NOTIFY_PLATFORM_REBOOT;
    inform_all_clients(&mmgr->clients, mmgr->client_notification);
    broadcast_msg(E_MSG_INTENT_PLATFORM_REBOOT);
    sleep(mmgr->config.delay_before_reboot);
out:
    return ret;
}

/**
 * handle E_EL_MODEM_OUT_OF_SERVICE pre reset escalation state
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr or/and modem_started is/are NULL
 * @return E_ERR_FAILED if reset not performed
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t state_modem_out_of_service(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->client_notification = E_MMGR_EVENT_MODEM_OUT_OF_SERVICE;
    inform_all_clients(&mmgr->clients, mmgr->client_notification);
    broadcast_msg(E_MSG_INTENT_MODEM_OUT_OF_SERVICE);
    mmgr->info.polled_states = 0;
    ret = set_mcd_poll_states(mmgr);
out:
    return ret;
}

/**
 * handle E_EL_MODEM_SHUTDOWN pre reset escalation state
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr or/and modem_started is/are NULL
 * @return E_ERR_FAILED if reset not performed
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t state_modem_shutdown(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    reset_shutdown_ack(&mmgr->clients);
    stop_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
out:
    return ret;
}

/**
 * try fo perform a modem escalation recovery
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr or/and modem_started is/are NULL
 * @return E_ERR_FAILED if reset not performed
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t reset_modem(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->events.inform_down = true;
    ret = pre_modem_escalation_recovery(&mmgr->reset);
    if (ret != E_ERR_SUCCESS)
        LOG_ERROR("reset escalation fails");

    if (mmgr->hdler_modem[mmgr->reset.level.id] != NULL)
        ret = mmgr->hdler_modem[mmgr->reset.level.id] (mmgr);

    if (mmgr->events.inform_down) {
        if (mmgr->reset.level.id != E_EL_MODEM_OUT_OF_SERVICE) {
            mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN);
        }
        if (mmgr->info.ev & E_EV_AP_RESET)
            usleep(mmgr->config.delay_before_reset * 1000);
    }
    if ((mmgr->reset.state != E_OPERATION_SKIP) &&
        (mmgr->reset.state != E_OPERATION_WAIT)) {

        modem_escalation_recovery(&mmgr->reset);

        if ((mmgr->reset.level.id != E_EL_MODEM_OUT_OF_SERVICE) &&
            (mmgr->reset.level.id != E_EL_MODEM_SHUTDOWN)) {

            mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
            ret = set_mcd_poll_states(mmgr);

            mmgr->info.ev |= E_EV_WAIT_FOR_IPC_READY;
            start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
        }
    }

out:
    return ret;
}

/**
 * open TTY and configure MUX
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t configure_modem(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);
    ret = open_tty(mmgr->config.modem_port, &mmgr->fd_tty);
    if (ret != E_ERR_SUCCESS) {
        LOG_ERROR("open fails");
        mmgr->info.ev |= E_EV_OPEN_FAILED;
        goto out;
    }
    ret = switch_to_mux(&mmgr->fd_tty, &mmgr->config, &mmgr->info,
                        mmgr->info.restore_timeout);
    if (ret == E_ERR_SUCCESS) {
        LOG_VERBOSE("Switch to MUX succeed");
        mmgr->client_notification = E_MMGR_EVENT_MODEM_UP;
    } else {
        LOG_ERROR("MUX INIT FAILED. reason=%d", ret);
    }
out:
    return ret;
}

/**
 * restore the modem. This function retrieves the core dump if available,
 * reset the modem if needed and configure it
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_TTY_BAD_FD if open fails
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t restore_modem(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    e_modem_events_type_t state;

    write_to_file(WAKE_LOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));

    ret = get_modem_state(mmgr->info.fd_mcd, &state);
    if (ret != E_ERR_SUCCESS)
        goto out;

    mmgr->info.ev |= state;
    if (state & E_EV_MODEM_OFF && !mmgr->reset.modem_shutdown) {
        LOG_DEBUG("Modem is OFF and should not be: powering on modem");
        if ((ret = modem_up(&mmgr->info)) != E_ERR_SUCCESS)
            goto out;
    }
    if (mmgr->info.ev != E_EV_NONE) {
        if (mmgr->fd_tty != CLOSED_FD)
            close_tty(&mmgr->fd_tty);
    }

    if (state & E_EV_CORE_DUMP) {
        inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP);
        broadcast_msg(E_MSG_INTENT_CORE_DUMP_WARNING);

        mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
        inform_all_clients(&mmgr->clients, mmgr->client_notification);

        mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
        ret = set_mcd_poll_states(mmgr);

        manage_core_dump(&mmgr->config, &mmgr->info);
        broadcast_msg(E_MSG_INTENT_CORE_DUMP_COMPLETE);
    }

    if (mmgr->info.ev != E_EV_NONE) {
        if (mmgr->info.ev & E_EV_CORE_DUMP_SUCCEED) {
            LOG_DEBUG("specific timeout after core dump detection");
            mmgr->info.restore_timeout = TIMEOUT_HANDSHAKE_AFTER_CD;
        } else {
            mmgr->info.restore_timeout = mmgr->config.max_retry_time;
        }
        ret = reset_modem(mmgr);
        if (ret != E_ERR_SUCCESS)
            goto out;
    }

out:
    write_to_file(WAKE_UNLOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));
    return ret;
}

/**
 * handle modem event
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if config or events is/are NULL
 * @return E_ERR_TTY_BAD_FD failed to open tty. perform a modem reset
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t modem_event(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    size_t data_size = READ_SIZE;
    char data[READ_SIZE];
    ssize_t read_size;

    CHECK_PARAM(mmgr, ret, out);

    /* clean event by reading data */
    do {
        read_size = read(mmgr->fd_tty, data, data_size);
    } while (read_size > 0);

    if (epoll_ctl(mmgr->epollfd, EPOLL_CTL_DEL, mmgr->fd_tty, NULL) == -1)
        LOG_DEBUG("epoll remove (%s)", strerror(errno));

    mmgr->events.do_restore_modem = true;
out:
    return ret;
}

/**
 * handle modem control event
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if config or events is/are NULL
 * @return E_ERR_TTY_BAD_FD failed to open tty. perform a modem reset
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t modem_control_event(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    e_modem_events_type_t state;

    CHECK_PARAM(mmgr, ret, out);

    get_modem_state(mmgr->info.fd_mcd, &state);
    mmgr->info.ev |= state;

    /* if the IPC is not ready, consider a reset of the modem
       modem_event does that just fine.
       if IPC is ready, start HSIC and remove wait on IPC_READY */
    if (state & E_EV_IPC_READY) {

        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);

        ret = configure_modem(mmgr);
        crash_logger(&mmgr->info);
        if (ret == E_ERR_SUCCESS) {
            mmgr->info.ev = E_EV_NONE;
            if (mmgr->reset.level.id != E_EL_MODEM_SHUTDOWN) {
                update_modem_tty(mmgr);
                inform_all_clients(&mmgr->clients, mmgr->client_notification);
            }
        } else {
            LOG_DEBUG("Failed to configure modem. Reset on-going");
            mmgr->info.ev = E_EV_FORCE_RESET;
            mmgr->events.do_restore_modem = true;
        }
    } else if ((state & E_EV_MODEM_OFF) && mmgr->reset.modem_shutdown) {
        /* modem electrical shutdown requested, do nothing but wait on
           IPC_READY */
        LOG_DEBUG("Modem is OFF and modem_shutdown has been requested, "
                  "just wait for IPC_READY");
        mmgr->info.polled_states = MDM_CTRL_STATE_IPC_READY;
        ret = set_mcd_poll_states(mmgr);
    } else {
        /* Signal a Modem Event */
        ret = modem_event(mmgr);
    }

out:
    return ret;
}

/**
 * initialize modem events handler
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t modem_events_init(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->hdler_modem[E_EL_MODEM_WARM_RESET] = state_modem_warm_reset;
    mmgr->hdler_modem[E_EL_MODEM_COLD_RESET] = state_modem_cold_reset;
    mmgr->hdler_modem[E_EL_PLATFORM_REBOOT] = state_platform_reboot;
    mmgr->hdler_modem[E_EL_MODEM_OUT_OF_SERVICE] = state_modem_out_of_service;
    mmgr->hdler_modem[E_EL_MODEM_SHUTDOWN] = state_modem_shutdown;

out:
    return ret;
}
