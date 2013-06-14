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
#include "property.h"
#include "security.h"
#include "timer_events.h"
#include "tty.h"

/* AT command to shutdown modem */
#define POWER_OFF_MODEM "AT+CFUN=0\r"

#define READ_SIZE 64

#define AT_CFUN_RETRY 0
#define WAIT_FOR_WARM_BOOT_TIMEOUT 30000
static e_mmgr_errors_t pre_modem_out_of_service(mmgr_data_t *mmgr);

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
    bool pm_state = false;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->config.is_flashless) {
        mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);

        if (mmgr->info.mdm_link == E_LINK_HSI) {
            flashing_interface = "/dev/ttyIFX1";
            ch_hw_sw = true;
        } else if (mmgr->info.mdm_link == E_LINK_HSIC) {
            flashing_interface = mmgr->events.bus_events.modem_flash_path;
            ch_hw_sw = false;
        }

        toggle_flashing_mode(&mmgr->info, true);
        mdm_get_ipc_pm(&mmgr->info, &pm_state);
        if (pm_state)
            mdm_set_ipc_pm(&mmgr->info, false);

        ret = flash_modem(&mmgr->info, flashing_interface, ch_hw_sw,
                          &mmgr->secur, &result.id);

        toggle_flashing_mode(&mmgr->info, false);
        if (pm_state)
            mdm_set_ipc_pm(&mmgr->info, true);

        inform_all_clients(&mmgr->clients, E_MMGR_RESPONSE_MODEM_FW_RESULT,
                           &result);
        if (result.id == E_MODEM_FW_BAD_FAMILY) {
            modem_shutdown(mmgr);
            mmgr->client_notification = E_MMGR_EVENT_MODEM_OUT_OF_SERVICE;
            broadcast_msg(E_MSG_INTENT_MODEM_FW_BAD_FAMILY);
        } else if (result.id == E_MODEM_FW_SUCCEED) {

            /* @TODO: fix that into flash_modem/modem_specific */
            if (mmgr->info.mdm_link == E_LINK_HSIC) {
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
    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP, NULL);
    broadcast_msg(E_MSG_INTENT_CORE_DUMP_WARNING);

    mdm_set_cd_ipc_pm(&mmgr->info, false);
    retrieve_core_dump(&mmgr->info.mcdr);
    mdm_set_cd_ipc_pm(&mmgr->info, true);
    broadcast_msg(E_MSG_INTENT_CORE_DUMP_COMPLETE);

    mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
    set_mcd_poll_states(&mmgr->info);

    if (!mmgr->config.is_flashless) {
        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
    }
    if (mmgr->info.mdm_link == E_LINK_HSIC) {
        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.link_state = E_MDM_LINK_NONE;
    }

out:
    set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
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
static e_mmgr_errors_t pre_mdm_warm_reset(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_WARM_RESET, NULL);
    broadcast_msg(E_MSG_INTENT_MODEM_WARM_RESET);
    set_mmgr_state(mmgr, E_MMGR_MDM_CONF_ONGOING);

    if (!(mmgr->info.ev & E_EV_CONF_FAILED) &&
        ((mmgr->info.ev & E_EV_MODEM_SELF_RESET) ||
         ((mmgr->info.ev & E_EV_CORE_DUMP) &&
          (mmgr->info.mcdr.state != E_CD_SUCCEED)))) {
        LOG_DEBUG("WARM RESET: skipped");
        mmgr->reset.state = E_OPERATION_SKIP;
    } else
        mmgr->reset.state = E_OPERATION_CONTINUE;
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
static e_mmgr_errors_t pre_mdm_cold_reset(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->clients.connected == 0) {
        mmgr->reset.state = E_OPERATION_CONTINUE;
        mmgr->reset.wait_operation = false;
    } else {
        if (mmgr->reset.wait_operation) {
            LOG_DEBUG("need to ack all clients");

            mmgr->reset.wait_operation = false;
            mmgr->reset.state = E_OPERATION_WAIT;

            mmgr->client_notification = E_MMGR_NOTIFY_MODEM_COLD_RESET;
            inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);
            set_mmgr_state(mmgr, E_MMGR_WAIT_CLI_ACK);

            start_timer(&mmgr->timer, E_TIMER_COLD_RESET_ACK);
        } else {
            mmgr->reset.wait_operation = true;
            mmgr->reset.state = E_OPERATION_CONTINUE;

            broadcast_msg(E_MSG_INTENT_MODEM_COLD_RESET);
            reset_cold_ack(&mmgr->clients);
            mmgr->request.accept_request = false;
            set_mmgr_state(mmgr, E_MMGR_MDM_CONF_ONGOING);

            stop_timer(&mmgr->timer, E_TIMER_COLD_RESET_ACK);
        }
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
static e_mmgr_errors_t pre_platform_reboot(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    int reboot_counter = recov_get_reboot();

    CHECK_PARAM(mmgr, ret, out);

    mmgr->reset.state = E_OPERATION_CONTINUE;
    if (reboot_counter >=
        mmgr->reset.process[E_EL_PLATFORM_REBOOT].retry_allowed) {
        /* go to next level */
        LOG_INFO("Reboot cancelled. Max value reached");
        recov_next(&mmgr->reset);
        pre_modem_out_of_service(mmgr);
    } else {
        recov_set_reboot(++reboot_counter);

        mmgr->client_notification = E_MMGR_NOTIFY_PLATFORM_REBOOT;
        inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);
        broadcast_msg(E_MSG_INTENT_PLATFORM_REBOOT);
        sleep(mmgr->config.delay_before_reboot);
        set_mmgr_state(mmgr, E_MMGR_WAIT_CLI_ACK);
    }
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
static e_mmgr_errors_t pre_modem_out_of_service(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    LOG_INFO("MODEM OUT OF SERVICE");
    mmgr->client_notification = E_MMGR_EVENT_MODEM_OUT_OF_SERVICE;
    inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);
    broadcast_msg(E_MSG_INTENT_MODEM_OUT_OF_SERVICE);
    set_mmgr_state(mmgr, E_MMGR_MDM_OOS);
    mmgr->reset.state = E_OPERATION_CONTINUE;

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
    int fd = CLOSED_FD;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->info.polled_states = 0;
    ret = set_mcd_poll_states(&mmgr->info);

    open_tty(mmgr->config.shtdwn_dlc, &fd);
    if (fd < 0) {
        LOG_ERROR("operation FAILED");
    } else {
        struct mdm_ctrl_cmd mdm_cmd;
        mdm_cmd.timeout = WAIT_FOR_WARM_BOOT_TIMEOUT;
        mdm_cmd.param = MDM_CTRL_STATE_WARM_BOOT;
        modem_info_t *info = &mmgr->info;

        err = send_at_retry(fd, POWER_OFF_MODEM, strlen(POWER_OFF_MODEM),
                            AT_CFUN_RETRY, AT_ANSWER_NO_TIMEOUT);

        LOG_DEBUG("Waiting for MDM_CTRL_STATE_WARM_BOOT");

        if (ioctl(info->fd_mcd, MDM_CTRL_WAIT_FOR_STATE, &mdm_cmd) <= 0) {
            LOG_DEBUG("Waiting for MDM_CTRL_STATE_WARM_BOOT failed");
        } else {
            LOG_DEBUG("MDM_CTRL_STATE_WARM_BOOT received");
        }
        close_tty(&fd);
    }

    mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
    inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);

    close_tty(&mmgr->fd_tty);
    ret = mdm_down(&mmgr->info);
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
e_mmgr_errors_t reset_modem(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    e_escalation_level_t level;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->client_notification != E_MMGR_EVENT_MODEM_DOWN) {
        mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
        inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);
    }

    /* Do pre-process operation */
    recov_start(&mmgr->reset);
    recov_get_level(&mmgr->reset, &level);
    CHECK_PARAM(mmgr->hdler_pre_mdm[level], ret, out);
    mmgr->hdler_pre_mdm[level] (mmgr);
    if (mmgr->reset.state == E_OPERATION_SKIP) {
        close_tty(&mmgr->fd_tty);
        goto out_mdm_ev;
    } else if (mmgr->reset.state == E_OPERATION_WAIT)
        goto out;

    /* Clear all events */
    mmgr->info.polled_states = 0;
    set_mcd_poll_states(&mmgr->info);
    stop_all_timers(&mmgr->timer);

    /* initialize modules */
    close_tty(&mmgr->fd_tty);
    secur_stop(&mmgr->secur);
    mdm_prepare(&mmgr->info);

    /* restart modem */
    mdm_prepare_link(&mmgr->info);
    recov_get_level(&mmgr->reset, &level);
    CHECK_PARAM(mmgr->hdler_mdm[level], ret, out);
    mmgr->hdler_mdm[level] (&mmgr->info);

    /* configure events handling */
    if ((level == E_EL_PLATFORM_REBOOT) ||
        (mmgr->reset.level.id == E_EL_MODEM_OUT_OF_SERVICE))
        goto out;

out_mdm_ev:
    recov_done(&mmgr->reset);

    /* do not subscribe to CORE DUMP event if a core dump already occurs AND
     * reset operation has been skipped. Otherwise, MMGR will receive a fake
     * core dump event as MCD is still in core dump state */
    mdm_subscribe_start_ev(&mmgr->info, !((mmgr->info.ev & E_EV_CORE_DUMP) &&
                                          (mmgr->reset.state ==
                                           E_OPERATION_SKIP)));
    if (!mmgr->config.is_flashless)
        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
    if (mmgr->info.mdm_link == E_LINK_HSIC) {
        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.link_state = E_MDM_LINK_NONE;
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
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
        goto out;
    }
    ret = switch_to_mux(&mmgr->fd_tty, &mmgr->config, &mmgr->info,
                        mmgr->config.max_retry);
    if (ret == E_ERR_SUCCESS) {
        if ((mmgr->info.mcdr.enabled) && (mmgr->info.ev & E_EV_CORE_DUMP)) {
            notify_core_dump(mmgr);
            mmgr->info.ev &= ~E_EV_CORE_DUMP;
        }
        LOG_VERBOSE("Switch to MUX succeed");
        mmgr->client_notification = E_MMGR_EVENT_MODEM_UP;
    } else {
        LOG_ERROR("MUX INIT FAILED. reason=%d", ret);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
        goto out;
    }

    mmgr->info.ev = E_EV_NONE;
    set_mmgr_state(mmgr, E_MMGR_MDM_UP);
    update_modem_tty(mmgr);
    inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);

    return ret;
out:
    LOG_DEBUG("Failed to configure modem. Reset on-going");
    mmgr->info.ev |= E_EV_CONF_FAILED;
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

    set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
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

    mdm_get_state(mmgr->info.fd_mcd, &state);
    mmgr->info.ev |= state;

    if (state & E_EV_FW_DOWNLOAD_READY) {
        /* manage fw update request */
        LOG_DEBUG("current state: E_EV_FW_DOWNLOAD_READY");
        mmgr->events.link_state |= E_MDM_LINK_FW_DL_READY;
        mmgr->events.link_state &= ~E_MDM_LINK_IPC_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_FW_DOWNLOAD_READY;
        mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);

        if (((mmgr->info.mdm_link == E_LINK_HSIC) &&
             mmgr->events.link_state & E_MDM_LINK_FLASH_READY) ||
            (mmgr->info.mdm_link == E_LINK_HSI)) {
            ret = do_flash(mmgr);
        }

    } else if (state & E_EV_IPC_READY) {

        LOG_DEBUG("current state: E_EV_IPC_READY");
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);

        mmgr->events.link_state |= E_MDM_LINK_IPC_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);
        if (mmgr->events.link_state & E_MDM_LINK_BB_READY) {
            if ((ret = configure_modem(mmgr)) == E_ERR_SUCCESS)
                ret = launch_secur(mmgr);
        }
    } else if (state & E_EV_CORE_DUMP) {
        LOG_DEBUG("current state: E_EV_CORE_DUMP");
        set_mmgr_state(mmgr, E_MMGR_MDM_CORE_DUMP);

        if (mmgr->fd_tty != CLOSED_FD) {
            mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);

            close_tty(&mmgr->fd_tty);
        }

        mmgr->events.link_state |= E_MDM_LINK_CORE_DUMP_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_COREDUMP;
        set_mcd_poll_states(&mmgr->info);

        if ((mmgr->info.mdm_link == E_LINK_HSIC) &&
            !(mmgr->events.link_state & E_MDM_LINK_CORE_DUMP_READ_READY)) {
            LOG_DEBUG("waiting for bus enumeration");
        } else {
            read_core_dump(mmgr);
        }
    } else if (state & E_EV_MODEM_OFF) {
        if (state & E_EV_MODEM_SELF_RESET) {
            LOG_DEBUG("Modem is booting up. Do nothing");
        } else if ((state & E_EV_MODEM_OFF) &&
                   (mmgr->events.cli_req & E_CLI_REQ_OFF)) {
            LOG_DEBUG("Modem is OFF and should be. Do nothing");
        } else {
            LOG_DEBUG("Modem is OFF and should not be: powering on modem");

            if ((ret = mdm_up(&mmgr->info)) != E_ERR_SUCCESS)
                goto out;

            mmgr->info.polled_states &= ~MDM_CTRL_STATE_IPC_READY;
            ret = set_mcd_poll_states(&mmgr->info);
            set_mmgr_state(mmgr, E_MMGR_MDM_CONF_ONGOING);
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
        /* ready to configure modem */
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.link_state &= ~E_MDM_LINK_FLASH_READY;
        mmgr->events.link_state |= E_MDM_LINK_BB_READY;
        if (mmgr->events.link_state & E_MDM_LINK_IPC_READY) {
            if ((ret = configure_modem(mmgr)) == E_ERR_SUCCESS)
                ret = launch_secur(mmgr);
        }
    } else if (get_bus_state(&mmgr->events.bus_events) & MDM_FLASH_READY) {
        /* ready to flash modem */
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.link_state |= E_MDM_LINK_FLASH_READY;
        mmgr->events.link_state &= ~E_MDM_LINK_BB_READY;
        if (mmgr->events.link_state & E_MDM_LINK_FW_DL_READY) {
            ret = do_flash(mmgr);
        }
    } else if (get_bus_state(&mmgr->events.bus_events) & MDM_CD_READY) {
        /* ready to read a core dump */
        if (mmgr->fd_tty != CLOSED_FD) {
            mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);

            close_tty(&mmgr->fd_tty);
        }

        mmgr->events.link_state |= E_MDM_LINK_CORE_DUMP_READ_READY;
        if (mmgr->events.link_state & E_MDM_LINK_CORE_DUMP_READY)
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
    mmgr->hdler_pre_mdm[E_EL_MODEM_WARM_RESET] = pre_mdm_warm_reset;
    mmgr->hdler_pre_mdm[E_EL_MODEM_COLD_RESET] = pre_mdm_cold_reset;
    mmgr->hdler_pre_mdm[E_EL_PLATFORM_REBOOT] = pre_platform_reboot;
    mmgr->hdler_pre_mdm[E_EL_MODEM_OUT_OF_SERVICE] = pre_modem_out_of_service;

    mmgr->hdler_mdm[E_EL_MODEM_WARM_RESET] = mdm_warm_reset;
    mmgr->hdler_mdm[E_EL_MODEM_COLD_RESET] = mdm_cold_reset;
    mmgr->hdler_mdm[E_EL_PLATFORM_REBOOT] = platform_reboot;
    mmgr->hdler_mdm[E_EL_MODEM_OUT_OF_SERVICE] = out_of_service;
out:
    return ret;
}
