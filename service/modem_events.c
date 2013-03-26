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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "at.h"
#include "errors.h"
#include "file.h"
#include "java_intent.h"
#include "logs.h"
#include "modem_events.h"
#include "mux.h"
#include "security.h"
#include "timer_events.h"
#include "tty.h"

/* wakelocks declaration */
#define WAKE_LOCK_SYSFS "/sys/power/wake_lock"
#define WAKE_UNLOCK_SYSFS "/sys/power/wake_unlock"

/* AT command to shutdown modem */
#define POWER_OFF_MODEM "AT+CFUN=0\r"

#define READ_SIZE 64

/**
 * do flashing modem procedure
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
static e_mmgr_errors_t do_flash(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mmgr_cli_fw_update_result_t result = {.id = E_MODEM_FW_ERROR_UNSPECIFIED };
    char *flashing_interface = NULL;
    bool ch_hw_sw = true;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->config.is_flashless) {

        mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);

        toggle_flashing_mode(&mmgr->info, mmgr->config.link_layer, true);
        if (strcmp(mmgr->config.link_layer, "hsi") == 0) {
            flashing_interface = "/dev/ttyIFX1";
            ch_hw_sw = true;
        } else if (strcmp(mmgr->config.link_layer, "hsic") == 0) {
            flashing_interface = mmgr->events.bus_events.modem_flash_path;
            ch_hw_sw = false;
        }

        ret =
            flash_modem(&mmgr->info, flashing_interface, ch_hw_sw, &mmgr->secur,
                        &result.id);
        toggle_flashing_mode(&mmgr->info, mmgr->config.link_layer, false);
        inform_all_clients(&mmgr->clients, E_MMGR_RESPONSE_MODEM_FW_RESULT,
                           &result);
        if (result.id == E_MODEM_FW_BAD_FAMILY) {
            modem_shutdown(mmgr);
            mmgr->client_notification = E_MMGR_EVENT_MODEM_OUT_OF_SERVICE;
            broadcast_msg(E_MSG_INTENT_MODEM_FW_BAD_FAMILY);
        } else if (result.id == E_MODEM_FW_SUCCEED) {

            /* @TODO: fix that into flash_modem/modem_specific */
            if (strcmp(mmgr->config.link_layer, "hsic") == 0) {
                /* @TODO: wait for ttyACM0 to appear after flash */
                sleep(4);
                start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
            }
        }

        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
    }

out:
    return ret;
}

static void read_core_dump(mmgr_data_t *mmgr)
{
    if (!mmgr->info.mcdr.enabled)
        goto out;

    /* CRITICAL section: */
    write_to_file(WAKE_LOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));

    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP, NULL);
    broadcast_msg(E_MSG_INTENT_CORE_DUMP_WARNING);

    retrieve_core_dump(&mmgr->info.mcdr);
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

    write_to_file(WAKE_UNLOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));
out:
    mmgr->info.ev |= E_EV_FORCE_RESET;
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
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    ret = add_fd_ev(mmgr->epollfd, mmgr->fd_tty, EPOLLIN);
    if (ret != E_ERR_SUCCESS)
        goto out;

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

    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_WARM_RESET, NULL);
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
        inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);
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

    mmgr->client_notification = E_MMGR_NOTIFY_PLATFORM_REBOOT;
    inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);
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
    inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);
    broadcast_msg(E_MSG_INTENT_MODEM_OUT_OF_SERVICE);

out:
    return ret;
}

/**
 * shutdown the modem
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr or/and modem_started is/are NULL
 * @return E_ERR_FAILED if reset not performed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t modem_shutdown(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    int err;
    int fd;
    int mdm_state;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->info.polled_states = 0;
    ret = set_mcd_poll_states(&mmgr->info);

    mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
    inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);

    mdm_state = MDM_CTRL_STATE_OFF;
    if (ioctl(mmgr->info.fd_mcd, MDM_CTRL_SET_STATE, &mdm_state) == -1)
        LOG_DEBUG("couldn't set MCD state: %s", strerror(errno));

    err = open_tty(mmgr->config.shtdwn_dlc, &fd);
    if (fd < 0) {
        LOG_ERROR("operation FAILED");
    } else {
        err = send_at_timeout(fd, POWER_OFF_MODEM, strlen(POWER_OFF_MODEM),
                              mmgr->config.max_retry_time);
        if (err != E_ERR_SUCCESS) {
            LOG_ERROR("Unable to send (%s)", POWER_OFF_MODEM);
        }
        close_tty(&fd);
    }

    close_tty(&mmgr->fd_tty);
    ret = modem_down(&mmgr->info);
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
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);

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
        secur_stop(&mmgr->secur);

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

    if ((mmgr->reset.state != E_OPERATION_WAIT) &&
        (mmgr->reset.level.id != E_EL_MODEM_OUT_OF_SERVICE) &&
        (mmgr->reset.level.id != E_EL_PLATFORM_REBOOT)) {

        if (mmgr->config.is_flashless)
            mmgr->info.polled_states = MDM_CTRL_STATE_FW_DOWNLOAD_READY;
        else
            mmgr->info.polled_states = MDM_CTRL_STATE_IPC_READY;
        /* do not subscribe to CORE DUMP event if a core dump already occurs
           AND reset operation has been skipped. Otherwise, MMGR will receive
           a fake core dump event as MCD is still in core dump state */
        if (!(mmgr->info.ev & E_EV_CORE_DUMP) &&
            !(mmgr->reset.state == E_OPERATION_SKIP))
            mmgr->info.polled_states |= MDM_CTRL_STATE_COREDUMP;
        ret = set_mcd_poll_states(&mmgr->info);

        if (!mmgr->config.is_flashless) {
            mmgr->info.ev |= E_EV_WAIT_FOR_IPC_READY;
            start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
        }
        if (strcmp(mmgr->config.link_layer, "hsic") == 0) {
            start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
            mmgr->events.modem_state = E_MDM_STATE_NONE;
        }
    }

out:
    return ret;
}

static e_mmgr_errors_t notify_core_dump(mmgr_data_t *mmgr)
{
    mmgr_cli_core_dump_t cd;
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    cd.state = mmgr->info.mcdr.state;
    cd.panic_id = mmgr->info.mcdr.panic_id;
    cd.len = strnlen(mmgr->info.mcdr.data.coredump_file, PATH_MAX) +
        strnlen(mmgr->info.mcdr.data.path, PATH_MAX) + 2;

    cd.path = malloc(sizeof(char) * cd.len);
    if (cd.path == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    snprintf(cd.path, cd.len, "%s/%s", mmgr->info.mcdr.data.path,
             mmgr->info.mcdr.data.coredump_file);
    LOG_DEBUG("path:%s len:%d", cd.path, cd.len);
    ret = inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP_COMPLETE,
                             &cd);
    free(cd.path);
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
        if ((mmgr->info.mcdr.enabled) && (mmgr->info.ev & E_EV_CORE_DUMP)) {
            notify_core_dump(mmgr);
            mmgr->info.ev &= ~E_EV_CORE_DUMP;
        }
        LOG_VERBOSE("Switch to MUX succeed");
        mmgr->client_notification = E_MMGR_EVENT_MODEM_UP;
    } else {
        LOG_ERROR("MUX INIT FAILED. reason=%d", ret);
        mmgr->info.ev |= E_EV_CONF_FAILED;
        goto out;
    }

    mmgr->info.ev = E_EV_NONE;
    update_modem_tty(mmgr);
    inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);

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
        if (mmgr->info.mcdr.state == E_CD_SUCCEED_WITHOUT_PANIC_ID) {
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
        inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);
        close_tty(&mmgr->fd_tty);
    }

    mmgr->info.ev |= E_EV_FORCE_RESET;
out:
    return ret;
}

static e_mmgr_errors_t launch_secur(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int fd;

    CHECK_PARAM(mmgr, ret, out);

    if ((ret = secur_register(&mmgr->secur, &fd) != E_ERR_SUCCESS))
        goto out;

    if (fd != CLOSED_FD) {
        add_fd_ev(mmgr->epollfd, fd, EPOLLIN);
        ret = secur_start(&mmgr->secur);
    }
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

    if (state & E_EV_FW_DOWNLOAD_READY) {
        /* manage fw update request */
        LOG_DEBUG("current state: E_EV_FW_DOWNLOAD_READY");
        mmgr->events.modem_state |= E_MDM_STATE_FW_DL_READY;
        mmgr->events.modem_state &= ~E_MDM_STATE_IPC_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_FW_DOWNLOAD_READY;
        mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);

        if (((strcmp(mmgr->config.link_layer, "hsic") == 0) &&
             mmgr->events.modem_state & E_MDM_STATE_FLASH_READY) ||
            (strcmp(mmgr->config.link_layer, "hsi") == 0)) {
            ret = do_flash(mmgr);
        }

    } else if (state & E_EV_IPC_READY) {

        LOG_DEBUG("current state: E_EV_IPC_READY");
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);

        mmgr->events.modem_state |= E_MDM_STATE_IPC_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);
        if (mmgr->events.modem_state & E_MDM_STATE_BB_READY) {
            if ((ret = configure_modem(mmgr)) == E_ERR_SUCCESS)
                ret = launch_secur(mmgr);
        }
    } else if (state & E_EV_CORE_DUMP) {
        LOG_DEBUG("current state: E_EV_CORE_DUMP");

        if (mmgr->fd_tty != CLOSED_FD) {
            mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);

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
    } else if (state & E_EV_MODEM_OFF) {
        if (state & E_EV_MODEM_SELF_RESET) {
            LOG_DEBUG("Modem is booting up. Do nothing");
        } else if ((state & E_EV_FORCE_MODEM_OFF)
                   && (mmgr->info.ev & E_EV_MODEM_OFF)) {
            LOG_DEBUG("Modem is OFF and should be. Do nothing");
        } else {
            LOG_DEBUG("Modem is OFF and should not be: powering on modem");

            //@TODO: workaround since start_hsic in modem_up does nothing
            // and stop_hsic makes a restart of hsic.
            if (!strcmp("hsic", mmgr->config.link_layer)) {
                stop_hsic(&mmgr->info);
            }

            if ((ret = modem_up(&mmgr->info, mmgr->config.is_flashless,
                                !strcmp("hsic", mmgr->config.link_layer))))
                goto out;
            mmgr->info.polled_states &= ~MDM_CTRL_STATE_IPC_READY;
            ret = set_mcd_poll_states(&mmgr->info);
        }
    } else {
        if (state & E_EV_MODEM_SELF_RESET)
            inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_SELF_RESET, NULL);

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
        if (mmgr->events.modem_state & E_MDM_STATE_IPC_READY) {
            if ((ret = configure_modem(mmgr)) == E_ERR_SUCCESS)
                ret = launch_secur(mmgr);
        }
    } else if (get_bus_state(&mmgr->events.bus_events) & MDM_FLASH_READY) {
        // ready to flash modem
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.modem_state |= E_MDM_STATE_FLASH_READY;
        mmgr->events.modem_state &= ~E_MDM_STATE_BB_READY;
        if (mmgr->events.modem_state & E_MDM_STATE_FW_DL_READY) {
            ret = do_flash(mmgr);
        }
    } else if (get_bus_state(&mmgr->events.bus_events) & MDM_CD_READY) {
        //ready to read a core dump
        if (mmgr->fd_tty != CLOSED_FD) {
            mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);

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
out:
    return ret;
}
