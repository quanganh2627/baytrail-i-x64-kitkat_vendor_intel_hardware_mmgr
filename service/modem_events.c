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

#define READ_SIZE 64

static e_mmgr_errors_t do_flash(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret;

    if (mmgr->config.is_flashless) {

        mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);

        ret = flash_modem(&mmgr->info);

        //@TODO: fix that into flash_modem/modem_specific
        if (strcmp(mmgr->config.link_layer, "hsic") == 0) {
            //@TODO: wait for ttyACM0 to appear after flash
            sleep(4);
        }

        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
    }

    return ret;
}

static void read_core_dump(mmgr_data_t *mmgr)
{
    /* CRITICAL section: */
    write_to_file(WAKE_LOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));

    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP);
    broadcast_msg(E_MSG_INTENT_CORE_DUMP_WARNING);

    manage_core_dump(&mmgr->config, &mmgr->info);
    broadcast_msg(E_MSG_INTENT_CORE_DUMP_COMPLETE);

    mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
    set_mcd_poll_states(&mmgr->info);

    if (!mmgr->config.is_flashless) {
        mmgr->info.ev |= E_EV_WAIT_FOR_IPC_READY;
        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
    }
    if (strcmp(mmgr->config.link_layer, "hsic") == 0) {
        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.modem_state = E_MDM_STATE_NONE;
    }

    mmgr->info.ev |= E_EV_FORCE_RESET;
    write_to_file(WAKE_UNLOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));
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
    mmgr->info.polled_states |=
        MDM_CTRL_STATE_WARM_BOOT | MDM_CTRL_STATE_COLD_BOOT;

    ret = set_mcd_poll_states(&mmgr->info);

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

    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_WARM_RESET);
    broadcast_msg(E_MSG_INTENT_MODEM_WARM_RESET);

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

    if (mmgr->clients.connected == 0)
        mmgr->reset.state = E_OPERATION_CONTINUE;

    if (mmgr->reset.state == E_OPERATION_WAIT) {
        mmgr->client_notification = E_MMGR_NOTIFY_MODEM_COLD_RESET;
        inform_all_clients(&mmgr->clients, mmgr->client_notification);
        LOG_DEBUG("need to ack all clients");
        start_timer(&mmgr->timer, E_TIMER_COLD_RESET_ACK);
    } else {
        broadcast_msg(E_MSG_INTENT_MODEM_COLD_RESET);
        reset_cold_ack(&mmgr->clients);
        mmgr->request.accept_request = false;
        start_timer(&mmgr->timer, E_TIMER_ACCEPT_CLIENT_RQUEST);
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

    /* inform crashloger that the platform will be rebooted */
    create_empty_file(CL_REBOOT_FILE, CL_FILE_PERMISSIONS);

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

    if (ioctl(mmgr->info.fd_mcd, MDM_CTRL_SET_STATE, MDM_CTRL_STATE_OFF) == -1) {
        LOG_DEBUG("couldn't set MCD state: %s", strerror(errno));
        ret = E_ERR_FAILED;
    }

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

    ret = pre_modem_escalation_recovery(&mmgr->reset);
    if (ret != E_ERR_SUCCESS)
        LOG_ERROR("reset escalation fails");

    if (mmgr->reset.state != E_OPERATION_SKIP) {
        if (mmgr->fd_tty != CLOSED_FD) {
            mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN);

        }

        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
        if (strcmp(mmgr->config.link_layer, "hsic") == 0) {
            stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        }
    }

    mmgr->info.polled_states = 0;
    ret = set_mcd_poll_states(&mmgr->info);
    if (mmgr->hdler_modem[mmgr->reset.level.id] != NULL)
        ret = mmgr->hdler_modem[mmgr->reset.level.id] (mmgr);

    if (mmgr->info.ev & E_EV_AP_RESET)
        usleep(mmgr->config.delay_before_reset * 1000);

    if ((mmgr->reset.state != E_OPERATION_SKIP) &&
        (mmgr->reset.state != E_OPERATION_WAIT)) {

        close_tty(&mmgr->fd_tty);
        /* re-generates the fls through nvm injection lib if the modem
           is_flashless */
        if (mmgr->config.is_flashless) {
            if ((ret = regen_fls(&mmgr->info)) != E_ERR_SUCCESS)
                goto out;
        }
        //stop hsic if the modem is hsic
        //@TODO: move that to modem_specific
        if (strcmp(mmgr->config.link_layer, "hsic") == 0)
            stop_hsic(&mmgr->info);

        modem_escalation_recovery(&mmgr->reset);
    }

    if (mmgr->reset.state != E_OPERATION_WAIT) {

        if ((mmgr->reset.level.id != E_EL_MODEM_OUT_OF_SERVICE) &&
            (mmgr->reset.level.id != E_EL_MODEM_SHUTDOWN)) {

            if (mmgr->config.is_flashless)
                mmgr->info.polled_states = MDM_CTRL_STATE_FW_DOWNLOAD_READY;
            else
                mmgr->info.polled_states = MDM_CTRL_STATE_IPC_READY;
            ret = set_mcd_poll_states(&mmgr->info);
        }

        if ((mmgr->reset.level.id != E_EL_MODEM_OUT_OF_SERVICE) &&
            (mmgr->reset.level.id != E_EL_MODEM_SHUTDOWN)) {

            if (!mmgr->config.is_flashless) {
                mmgr->info.ev |= E_EV_WAIT_FOR_IPC_READY;
                start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
            }
            if (strcmp(mmgr->config.link_layer, "hsic") == 0) {
                start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
                mmgr->events.modem_state = E_MDM_STATE_NONE;
            }
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
        mmgr->info.ev |= E_EV_CONF_FAILED;
        goto out;
    }
    ret = switch_to_mux(&mmgr->fd_tty, &mmgr->config, &mmgr->info,
                        mmgr->info.restore_timeout);
    if (ret == E_ERR_SUCCESS) {
        LOG_VERBOSE("Switch to MUX succeed");
        mmgr->client_notification = E_MMGR_EVENT_MODEM_UP;
    } else {
        LOG_ERROR("MUX INIT FAILED. reason=%d", ret);
        mmgr->info.ev |= E_EV_CONF_FAILED;
        goto out;
    }

    crash_logger(&mmgr->info);
    mmgr->info.ev = E_EV_NONE;
    if (mmgr->reset.level.id != E_EL_MODEM_SHUTDOWN) {
        update_modem_tty(mmgr);
        inform_all_clients(&mmgr->clients, mmgr->client_notification);
    }

    return ret;
out:
    LOG_DEBUG("Failed to configure modem. Reset on-going");
    mmgr->info.ev = E_EV_FORCE_RESET;
    return ret;
}

/**
 * restore the modem. This function resets the modem if needed and
 * configures it
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

    /* CRITICAL section: */
    write_to_file(WAKE_LOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));

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

    if (mmgr->fd_tty != CLOSED_FD) {
        mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
        inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN);
        close_tty(&mmgr->fd_tty);
    }

    mmgr->info.ev |= E_EV_FORCE_RESET;
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

    /* do not report a modem self-reset in case of
       a core dump */
    if (mmgr->info.ev & E_EV_CORE_DUMP)
        mmgr->info.ev &= ~E_EV_MODEM_SELF_RESET;

    if (state & E_EV_FW_DOWNLOAD_READY) {
        /* manage fw update request */
        LOG_DEBUG("current state: E_EV_FW_DOWNLOAD_READY");
        mmgr->events.modem_state |= E_MDM_STATE_FW_DL_READY;
        mmgr->events.modem_state &= ~E_MDM_STATE_IPC_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_FW_DOWNLOAD_READY;
        mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);

        if (mmgr->events.modem_state & E_MDM_STATE_FLASH_READY) {
            ret = do_flash(mmgr);
        }
    } else if (state & E_EV_IPC_READY) {

        LOG_DEBUG("current state: E_EV_IPC_READY");
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);

        mmgr->events.modem_state |= E_MDM_STATE_IPC_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);
        if (mmgr->events.modem_state & E_MDM_STATE_BB_READY)
            ret = configure_modem(mmgr);

    } else if (state & E_EV_CORE_DUMP) {
        LOG_DEBUG("current state: E_EV_CORE_DUMP");

        if (mmgr->fd_tty != CLOSED_FD) {
            mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN);

            close_tty(&mmgr->fd_tty);
        }

        mmgr->events.modem_state |= E_MDM_STATE_CORE_DUMP_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_COREDUMP;
        set_mcd_poll_states(&mmgr->info);

        //TODO
        if ((strcmp(mmgr->config.link_layer, "hsic") == 0) &&
            !(mmgr->events.modem_state & E_MDM_STATE_CORE_DUMP_READ_READY)) {
            LOG_DEBUG("waiting for bus enumeration");
        } else {
            read_core_dump(mmgr);
        }
    } else if ((state & E_EV_MODEM_OFF) && mmgr->reset.modem_shutdown) {
        /* modem electrical shutdown requested, do nothing but wait on
           IPC_READY */
        LOG_DEBUG("Modem is OFF and modem_shutdown has been requested, "
                  "just wait for IPC_READY");
        mmgr->info.polled_states = MDM_CTRL_STATE_IPC_READY;
        mmgr->events.modem_state &= ~E_MDM_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);
        if (strcmp(mmgr->config.link_layer, "hsic") == 0)
            stop_hsic(&mmgr->info);
    } else if ((state & E_EV_MODEM_OFF) && (state & E_EV_MODEM_SELF_RESET)) {
        /* modem is booting up, do nothing */
        LOG_DEBUG("Modem is booting up");
    } else if (state & E_EV_MODEM_OFF && !mmgr->reset.modem_shutdown) {
        LOG_DEBUG("Modem is OFF and should not be: powering on modem");

        //@TODO: workaround since start_hsic in modem_up does nothing
        // and stop_hsic makes a restart of hsic.
        if (!strcmp("hsic", mmgr->config.link_layer)) {
            stop_hsic(&mmgr->info);
        }

        if ((ret = modem_up(&mmgr->info, mmgr->config.is_flashless,
                            !strcmp("hsic", mmgr->config.link_layer)))
            != E_ERR_SUCCESS)
            goto out;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_IPC_READY;
        ret = set_mcd_poll_states(&mmgr->info);
    } else {

        /* Signal a Modem Event */
        ret = modem_event(mmgr);
    }

out:
    return ret;
}

e_mmgr_errors_t bus_events(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);
    LOG_DEBUG("Modem event triggered");

    bus_read_events(&mmgr->events.bus_events);
    bus_handle_events(&mmgr->events.bus_events);
    if (get_bus_state(&mmgr->events.bus_events) & MDM_BB_READY) {
        // ready to configure modem
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.modem_state &= ~E_MDM_STATE_FLASH_READY;
        mmgr->events.modem_state |= E_MDM_STATE_BB_READY;
        if (mmgr->events.modem_state & E_MDM_STATE_IPC_READY)
            ret = configure_modem(mmgr);
    } else if (get_bus_state(&mmgr->events.bus_events) & MDM_FLASH_READY) {
        // ready to flash modem
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.modem_state |= E_MDM_STATE_FLASH_READY;
        mmgr->events.modem_state &= ~E_MDM_STATE_BB_READY;

        if (1) {                //@TODO: REVERT ME mmgr->events.modem_state & E_MDM_STATE_FW_DL_READY) {
            ret = do_flash(mmgr);
        }
    } else if (get_bus_state(&mmgr->events.bus_events) & MDM_CD_READY) {
        //ready to read a core dump
        if (mmgr->fd_tty != CLOSED_FD) {
            mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN);

            close_tty(&mmgr->fd_tty);
        }

        mmgr->events.modem_state |= E_MDM_STATE_CORE_DUMP_READ_READY;
        if (mmgr->events.modem_state & E_MDM_STATE_CORE_DUMP_READY)
            read_core_dump(mmgr);
    } else
        LOG_DEBUG("Unhandled usb event");

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
