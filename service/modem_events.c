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
#include <sys/epoll.h>
#include "crash_logger.h"
#include "errors.h"
#include "file.h"
#include "java_intent.h"
#include "logs.h"
#include "modem_events.h"
#include "mux.h"
#include "tty.h"

/* wakelocks declaration */
#define WAKE_LOCK_SYSFS "/sys/power/wake_lock"
#define WAKE_UNLOCK_SYSFS "/sys/power/wake_unlock"

#define READ_SIZE 1024

/**
 * add new tty file descriptor to epoll
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
static int update_modem_tty(mmgr_data_t *mmgr)
{
    struct epoll_event ev;
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    ev.events = EPOLLIN;
    ev.data.fd = mmgr->fd_tty;
    if (epoll_ctl(mmgr->epollfd, EPOLL_CTL_ADD, mmgr->fd_tty, &ev) == -1) {
        LOG_ERROR("Error during epoll_ctl. fd=%d (%s)",
                  mmgr->fd_tty, strerror(errno));
        ret = E_ERR_FAILED;
        goto out;
    }

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
static int state_modem_warm_reset(mmgr_data_t *mmgr)
{
    int ret = E_ERR_SUCCESS;

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
static int state_modem_cold_reset(mmgr_data_t *mmgr)
{
    int ret = E_ERR_SUCCESS;
    int timeout = TIMEOUT_EPOLL_ACK;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->reset.state == E_OPERATION_WAIT) {
        mmgr->modem_state = E_MMGR_NOTIFY_MODEM_COLD_RESET;
        inform_all_clients(&mmgr->clients, mmgr->modem_state);
        LOG_DEBUG("need to ack all clients");
        mmgr->events.inform_down = false;
        START_TIMER(mmgr->timer, timeout);
        ret = E_ERR_FAILED;
    } else {
        broadcast_msg(E_MSG_INTENT_MODEM_COLD_RESET);
        reset_cold_ack(&mmgr->clients);
        STOP_TIMER(mmgr->timer);
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
static int state_platform_reboot(mmgr_data_t *mmgr)
{
    int ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    create_empty_file(CL_REBOOT_FILE, CL_FILE_PERMISSIONS);
    /* inform crashloger that the platform will be rebooted */
    mmgr->modem_state = E_MMGR_NOTIFY_PLATFORM_REBOOT;
    inform_all_clients(&mmgr->clients, mmgr->modem_state);
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
static int state_modem_out_of_service(mmgr_data_t *mmgr)
{
    int ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->modem_state = E_MMGR_EVENT_MODEM_OUT_OF_SERVICE;
    inform_all_clients(&mmgr->clients, mmgr->modem_state);
    broadcast_msg(E_MSG_INTENT_MODEM_OUT_OF_SERVICE);
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
static int state_modem_shutdown(mmgr_data_t *mmgr)
{
    int ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    reset_shutdown_ack(&mmgr->clients);
    STOP_TIMER(mmgr->timer);
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
static int reset_modem(mmgr_data_t *mmgr)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->events.inform_down = true;
    ret = pre_modem_escalation_recovery(&mmgr->reset);
    if (ret != E_ERR_SUCCESS)
        LOG_ERROR("reset escalation fails");

    if (mmgr->hdler_modem[mmgr->reset.level.id] != NULL)
        ret = mmgr->hdler_modem[mmgr->reset.level.id] (mmgr);

    if (mmgr->events.inform_down) {
        if (mmgr->reset.level.id != E_EL_MODEM_OUT_OF_SERVICE) {
            mmgr->modem_state = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN);
        }
        if (mmgr->info.ev & E_EV_AP_RESET)
            usleep(mmgr->config.delay_before_reset * 1000);
    }
    if ((mmgr->reset.state != E_OPERATION_SKIP) &&
        (mmgr->reset.state != E_OPERATION_WAIT)) {
        close_tty(&mmgr->fd_tty);
        modem_escalation_recovery(&mmgr->reset);
    }
out:
    return ret;
}

/**
 * open TTY and configure MUX
 *
 * @param [in,out] mmgr mmgr context
 * @param [in] timeout switch to mux timeout
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static int configure_modem(mmgr_data_t *mmgr, int timeout)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);
    ret = open_tty(mmgr->config.modem_port, &mmgr->fd_tty);
    if (ret != E_ERR_SUCCESS) {
        LOG_ERROR("open fails");
        mmgr->info.ev |= E_EV_OPEN_FAILED;
        goto out;
    }
    ret = switch_to_mux(&mmgr->fd_tty, &mmgr->config, &mmgr->info, timeout);
    if (ret == E_ERR_SUCCESS) {
        LOG_VERBOSE("switched to MUX Success");
        mmgr->modem_state = E_MMGR_EVENT_MODEM_UP;
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
int restore_modem(mmgr_data_t *mmgr)
{
    int ret = E_ERR_SUCCESS;
    int timeout = mmgr->config.max_retry_time;

    write_to_file(WAKE_LOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));

    /* @TODO remove close tty once hsi issue solved:
       if a get_hangup_reason is done before closing the tty,
       the driver hangs */
    if (!mmgr->reset.modem_shutdown)
        close_tty(&mmgr->fd_tty);

    do {
        ret = check_modem_state(&mmgr->config, &mmgr->info);
        if (ret != E_ERR_SUCCESS)
            goto out;

        if (mmgr->info.ev & E_EV_CORE_DUMP) {
            inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP);
            broadcast_msg(E_MSG_INTENT_CORE_DUMP_WARNING);

            mmgr->modem_state = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, mmgr->modem_state);
            manage_core_dump(&mmgr->config, &mmgr->info);
            broadcast_msg(E_MSG_INTENT_CORE_DUMP_COMPLETE);
        }

        if (mmgr->info.ev != E_EV_NONE) {
            if (mmgr->info.ev & E_EV_CORE_DUMP_SUCCEED) {
                LOG_DEBUG("specific timeout after core dump detection");
                timeout = TIMEOUT_HANDSHAKE_AFTER_CD;
            } else {
                timeout = mmgr->config.max_retry_time;
            }
            ret = reset_modem(mmgr);
            if (ret != E_ERR_SUCCESS)
                goto out;
        }
        ret = configure_modem(mmgr, timeout);
        crash_logger(&mmgr->info);
    } while (ret != E_ERR_SUCCESS);

out:
    if ((ret == E_ERR_SUCCESS) && (mmgr->reset.level.id != E_EL_MODEM_SHUTDOWN)) {
        update_modem_tty(mmgr);
        inform_all_clients(&mmgr->clients, mmgr->modem_state);
    }
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
int modem_event(mmgr_data_t *mmgr)
{
    int ret = E_ERR_SUCCESS;
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

    mmgr->events.restore_modem = true;
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
int modem_events_init(mmgr_data_t *mmgr)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->hdler_modem[E_EL_MODEM_WARM_RESET] = state_modem_warm_reset;
    mmgr->hdler_modem[E_EL_MODEM_COLD_RESET] = state_modem_cold_reset;
    mmgr->hdler_modem[E_EL_PLATFORM_REBOOT] = state_platform_reboot;
    mmgr->hdler_modem[E_EL_MODEM_OUT_OF_SERVICE] = state_modem_out_of_service;
    mmgr->hdler_modem[E_EL_MODEM_SHUTDOWN] = state_modem_shutdown;

out:
    return ret;
}
