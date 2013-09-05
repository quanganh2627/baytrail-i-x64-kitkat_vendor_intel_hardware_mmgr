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
#include "modem_specific.h"
#include "mux.h"
#include "security.h"
#include "timer_events.h"
#include "tty.h"
#include "mmgr.h"
#include "link_pm.h"

/* AT command to shutdown modem */
#define POWER_OFF_MODEM "AT+CFUN=0\r"

#define READ_SIZE 64

#define ERROR_ID   1
#define ERROR_REASON "IPC error"

#define AT_CFUN_RETRY 0
#define WAIT_FOR_WARM_BOOT_TIMEOUT 30000
static e_mmgr_errors_t pre_modem_out_of_service(mmgr_data_t *mmgr);

static inline void mdm_close_fds(mmgr_data_t *mmgr)
{
    secur_stop(&mmgr->secur);
    close_tty(&mmgr->fd_tty);
}

static e_mmgr_errors_t notify_core_dump(client_list_t *clients,
                                        mcdr_lib_t *mcdr,
                                        e_core_dump_state_t state)
{
    mmgr_cli_core_dump_t cd;
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(clients, ret, out);

    memset(&cd, 0, sizeof(cd));

    cd.state = state;
    if (mcdr != NULL) {
        cd.path_len = strnlen(mcdr->data.coredump_file, PATH_MAX) +
                      strnlen(mcdr->data.path, PATH_MAX) + 2;

        cd.path = malloc(sizeof(char) * cd.path_len);
        if (cd.path == NULL) {
            LOG_ERROR("memory allocation fails");
            goto out;
        }
        snprintf(cd.path, cd.path_len, "%s/%s", mcdr->data.path,
                 mcdr->data.coredump_file);

        if (E_CD_TIMEOUT == state) {
            cd.reason = "Timeout. Operation aborted";
            cd.reason_len = strlen(cd.reason);
        } else if (E_CD_SUCCEED != state) {
            cd.reason = mcdr->get_reason();
            cd.reason_len = strlen(cd.reason);
        } else {
            cd.reason = NULL;
            cd.reason_len = 0;
        }
    }
    ret = inform_all_clients(clients, E_MMGR_NOTIFY_CORE_DUMP_COMPLETE, &cd);
    free(cd.path);

out:
    return ret;
}

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
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_fw_update_result_t fw_result =
    { .id = E_MODEM_FW_ERROR_UNSPECIFIED };
    char *flashing_interface = NULL;
    bool ch_hw_sw = true;

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
        pm_on_mdm_flash(&mmgr->info);

        flash_modem_fw(&mmgr->info, flashing_interface, ch_hw_sw,
                       &mmgr->secur, &fw_result.id);

        toggle_flashing_mode(&mmgr->info, false);
        /* the IPC power management will be enabled when the modem is UP */

        inform_all_clients(&mmgr->clients, E_MMGR_RESPONSE_MODEM_FW_RESULT,
                           &fw_result);

        switch (fw_result.id) {
        case E_MODEM_FW_BAD_FAMILY:
            modem_shutdown(mmgr);
            inform_all_clients(&mmgr->clients,
                               E_MMGR_EVENT_MODEM_OUT_OF_SERVICE, NULL);
            broadcast_msg(E_MSG_INTENT_MODEM_FW_BAD_FAMILY);
            /* Set MMGR state to MDM_RESET to call the recovery module and
             * force modem recovery to OOS. By doing so, MMGR will turn off the
             * modem and declare the modem OOS. Clients will not be able to turn
             * on the modem */
            recov_force(mmgr->reset, E_FORCE_OOS);
            set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
            break;

        case E_MODEM_FW_SUCCEED:
            /* @TODO: fix that into flash_modem/modem_specific */
            if (mmgr->info.mdm_link == E_LINK_HSIC) {
                /* @TODO: wait for IPC to appear after flash */
                sleep(4);
                timer_start(mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
            }
            timer_start(mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
            ret = E_ERR_SUCCESS;
            break;

        case E_MODEM_FW_SW_CORRUPTED:
            /* Set MMGR state to MDM_RESET to call the recovery module and
             * force modem recovery to OOS. By doing so, MMGR will turn off the
             * modem and declare the modem OOS. Clients will not be able to turn
             * on the modem */
            recov_force(mmgr->reset, E_FORCE_OOS);
            set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
            break;

        case E_MODEM_FW_ERROR_UNSPECIFIED:
        case E_MODEM_FW_READY_TIMEOUT:
            set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
            break;

        case E_MODEM_FW_OUTDATED:
            broadcast_msg(E_MSG_INTENT_MODEM_FW_OUTDATED);
            /* Set MMGR state to MDM_RESET to call the recovery module and
             * force modem recovery to OOS. By doing so, MMGR will turn off the
             * modem and declare the modem OOS. Clients will not be able to turn
             * on the modem */
            recov_force(mmgr->reset, E_FORCE_OOS);
            set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
            break;

        case E_MODEM_FW_SECURITY_CORRUPTED:
            broadcast_msg(E_MSG_INTENT_MODEM_FW_SECURITY_CORRUPTED);
            /* Set MMGR state to MDM_RESET to call the recovery module and
             * force modem recovery to OOS. By doing so, MMGR will turn off the
             * modem and declare the modem OOS. Clients will not be able to turn
             * on the modem */
            recov_force(mmgr->reset, E_FORCE_OOS);
            set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
            break;

        case E_MODEM_FW_NUM:
            /* nothing to do */
            break;
        }
    }

out:
    return ret;
}

/**
 * do modem customization procedure
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
static e_mmgr_errors_t do_nvm_customization(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_nvm_update_result_t nvm_result = { .id =
                                                    E_MODEM_NVM_ERROR_UNSPECIFIED };

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->config.is_flashless) {
        LOG_DEBUG("checking for nvm patch existence at %s",
                  mmgr->info.fl_conf.nvm_patch);

        if (is_file_exists(mmgr->info.fl_conf.nvm_patch, 0) == E_ERR_SUCCESS) {
            LOG_DEBUG("nvm patch found");
            ret =
                flash_modem_nvm(&mmgr->info, mmgr->config.nvm_custo_dlc,
                                &nvm_result.id, &nvm_result.sub_error_code);
        } else {
            ret = E_ERR_FAILED;
            nvm_result.id = E_MODEM_NVM_NO_NVM_PATCH;
            LOG_DEBUG("no nvm patch found at %s; skipping nvm update",
                      mmgr->info.fl_conf.nvm_patch);
        }
        inform_all_clients(&mmgr->clients, E_MMGR_RESPONSE_MODEM_NVM_RESULT,
                           &nvm_result);
    }

out:
    return ret;
}

static void read_core_dump(mmgr_data_t *mmgr)
{
    e_core_dump_state_t state;

    if (!mmgr->info.mcdr.enabled)
        goto out;

    timer_stop(mmgr->timer, E_TIMER_WAIT_CORE_DUMP_READY);

    retrieve_core_dump(&mmgr->info.mcdr, &state);
    pm_on_mdm_cd_complete(&mmgr->info);

    broadcast_msg(E_MSG_INTENT_CORE_DUMP_COMPLETE);
    notify_core_dump(&mmgr->clients, &mmgr->info.mcdr, state);

    mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
    mmgr->info.polled_states &= ~MDM_CTRL_STATE_WARM_BOOT;
    set_mcd_poll_states(&mmgr->info);

    if (!mmgr->config.is_flashless)
        timer_start(mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
    if (mmgr->info.mdm_link == E_LINK_HSIC) {
        timer_start(mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
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
    static bool wait_operation = true;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->clients.connected == 0) {
        recov_set_state(mmgr->reset, E_OPERATION_CONTINUE);
        wait_operation = false;
    } else {
        if (wait_operation) {
            LOG_DEBUG("need to ack all clients");

            wait_operation = false;
            recov_set_state(mmgr->reset, E_OPERATION_WAIT);

            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);
            inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_COLD_RESET,
                               NULL);
            set_mmgr_state(mmgr, E_MMGR_WAIT_COLD_ACK);
            timer_start(mmgr->timer, E_TIMER_COLD_RESET_ACK);
        } else {
            wait_operation = true;
            recov_set_state(mmgr->reset, E_OPERATION_CONTINUE);

            broadcast_msg(E_MSG_INTENT_MODEM_COLD_RESET);
            reset_cold_ack(&mmgr->clients);
            mmgr->request.accept_request = false;
            if ((mmgr->info.mdm_link == E_LINK_HSIC) && mmgr->info.is_flashless)
                set_mmgr_state(mmgr, E_MMGR_MDM_START);
            else
                set_mmgr_state(mmgr, E_MMGR_MDM_CONF_ONGOING);

            timer_stop(mmgr->timer, E_TIMER_COLD_RESET_ACK);
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

    recov_set_state(mmgr->reset, E_OPERATION_CONTINUE);
    if (reboot_counter >= recov_get_retry_allowed(mmgr->reset)) {
        /* go to next level */
        LOG_INFO("Reboot cancelled. Max value reached");
        recov_next(mmgr->reset);
        pre_modem_out_of_service(mmgr);
    } else {
        recov_set_reboot(++reboot_counter);

        inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_PLATFORM_REBOOT, NULL);
        broadcast_msg(E_MSG_INTENT_PLATFORM_REBOOT);

        sleep(mmgr->config.delay_before_reboot);
        /* pretend that the modem is OOS to reject all clients' requests */
        set_mmgr_state(mmgr, E_MMGR_MDM_OOS);
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
    inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_OUT_OF_SERVICE, NULL);
    broadcast_msg(E_MSG_INTENT_MODEM_OUT_OF_SERVICE);

    set_mmgr_state(mmgr, E_MMGR_MDM_OOS);
    recov_set_state(mmgr->reset, E_OPERATION_CONTINUE);

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

        send_at_retry(fd, POWER_OFF_MODEM, strlen(POWER_OFF_MODEM),
                      AT_CFUN_RETRY, AT_ANSWER_NO_TIMEOUT);

        LOG_DEBUG("Waiting for MDM_CTRL_STATE_WARM_BOOT");

        if (ioctl(info->fd_mcd, MDM_CTRL_WAIT_FOR_STATE, &mdm_cmd) <= 0)
            LOG_DEBUG("Waiting for MDM_CTRL_STATE_WARM_BOOT failed");
        else
            LOG_DEBUG("MDM_CTRL_STATE_WARM_BOOT received");
        close_tty(&fd);
    }

    inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);

    mdm_close_fds(mmgr);
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
    e_escalation_level_t level = E_EL_UNKNOWN;
    e_reset_operation_state_t state = E_OPERATION_UNKNOWN;

    CHECK_PARAM(mmgr, ret, out);

    /* Do pre-process operation */
    recov_start(mmgr->reset);
    level = recov_get_level(mmgr->reset);
    CHECK_PARAM(mmgr->hdler_pre_mdm[level], ret, out);
    mmgr->hdler_pre_mdm[level] (mmgr);

    state = recov_get_state(mmgr->reset);
    if (state == E_OPERATION_SKIP) {
        mdm_close_fds(mmgr);
        goto out_mdm_ev;
    } else if (state == E_OPERATION_WAIT) {
        goto out;
    }

    /* Keep only CORE DUMP state */
    mmgr->info.polled_states = MDM_CTRL_STATE_COREDUMP;
    set_mcd_poll_states(&mmgr->info);
    timer_stop_all(mmgr->timer);

    /* initialize modules */
    mdm_close_fds(mmgr);
    if ((level != E_EL_PLATFORM_REBOOT) &&
        (level != E_EL_MODEM_OUT_OF_SERVICE)) {
        if (E_ERR_SUCCESS != mdm_prepare(&mmgr->info)) {
            LOG_ERROR("modem fw is corrupted. Declare modem OOS");
            /* Set MMGR state to MDM_RESET to call the recovery module and
             * force modem recovery to OOS. By doing so, MMGR will turn off the
             * modem and declare the modem OOS. Clients will not be able to turn
             * on the modem */
            recov_force(mmgr->reset, E_FORCE_OOS);
            return reset_modem(mmgr);
        }
    }

    /* restart modem */
    mdm_prepare_link(&mmgr->info);

    /* The level can change between the pre operation and the operation in a
     * specific case: if we are in PLATFORM_REBOOT state and we reached the
     * maximum allowed attempts */
    level = recov_get_level(mmgr->reset);
    CHECK_PARAM(mmgr->hdler_mdm[level], ret, out);
    mmgr->hdler_mdm[level] (&mmgr->info);

    /* configure events handling */
    if ((level == E_EL_PLATFORM_REBOOT) || (level == E_EL_MODEM_OUT_OF_SERVICE))
        goto out;

out_mdm_ev:
    recov_done(mmgr->reset);

    mdm_subscribe_start_ev(&mmgr->info);
    if (!mmgr->config.is_flashless)
        timer_start(mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
    if (mmgr->info.mdm_link == E_LINK_HSIC) {
        timer_start(mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.link_state = E_MDM_LINK_NONE;
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
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
        goto out;
    }
    ret = switch_to_mux(&mmgr->fd_tty, &mmgr->config, &mmgr->info,
                        mmgr->config.max_retry);
    if (ret == E_ERR_SUCCESS) {
        LOG_VERBOSE("Switch to MUX succeed");
    } else {
        LOG_ERROR("MUX INIT FAILED. reason=%d", ret);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
        goto out;
    }

    set_mmgr_state(mmgr, E_MMGR_MDM_UP);
    update_modem_tty(mmgr);

    return ret;
out:
    LOG_DEBUG("Failed to configure modem. Reset on-going");
    return ret;
}

static e_mmgr_errors_t cleanup_ipc_event(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    size_t data_size = READ_SIZE;
    char data[READ_SIZE];
    ssize_t read_size;

    CHECK_PARAM(mmgr, ret, out);

    /* clean event by reading data */
    do
        read_size = read(mmgr->fd_tty, data, data_size);
    while (read_size > 0);

    mdm_close_fds(mmgr);

out:
    return ret;
}

/**
 * handle ipc events
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if config or events is/are NULL
 * @return E_ERR_TTY_BAD_FD failed to open tty. perform a modem reset
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t ipc_event(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    cleanup_ipc_event(mmgr);

    inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);

    /* send error notification with reason message */
    if (mmgr->info.mdm_link == E_LINK_HSI) {
        mmgr_cli_error_t err = { .id = ERROR_ID };
        err.len = strlen(ERROR_REASON);
        err.reason = (char *)ERROR_REASON;
        inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_ERROR, &err);
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

static e_mmgr_errors_t do_configure(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    if ((ret = configure_modem(mmgr)) == E_ERR_SUCCESS) {
        if (do_nvm_customization(mmgr) == E_ERR_SUCCESS) {
            timer_start(mmgr->timer, E_TIMER_REBOOT_MODEM_DELAY);
        } else {
            ret = launch_secur(mmgr);
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_UP, NULL);
            pm_on_mdm_up(&mmgr->info);
        }
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
            (mmgr->info.mdm_link == E_LINK_HSI))
            ret = do_flash(mmgr);
    } else if (state & E_EV_IPC_READY) {
        LOG_DEBUG("current state: E_EV_IPC_READY");
        timer_stop(mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
        mmgr->events.link_state |= E_MDM_LINK_IPC_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_IPC_READY;
        set_mcd_poll_states(&mmgr->info);
        if ((mmgr->events.link_state & E_MDM_LINK_BB_READY) &&
            (mmgr->state == E_MMGR_MDM_CONF_ONGOING))
            ret = do_configure(mmgr);
    } else if (state & E_EV_CORE_DUMP) {
        LOG_DEBUG("current state: E_EV_CORE_DUMP");
        set_mmgr_state(mmgr, E_MMGR_MDM_CORE_DUMP);
        timer_stop_all(mmgr->timer);

        if (mmgr->fd_tty != CLOSED_FD) {
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);
            mdm_close_fds(mmgr);
        }

        pm_on_mdm_cd(&mmgr->info);

        mmgr->events.link_state |= E_MDM_LINK_CORE_DUMP_READY;
        mmgr->info.polled_states &= ~MDM_CTRL_STATE_COREDUMP;
        set_mcd_poll_states(&mmgr->info);

        LOG_DEBUG("start timer for core dump ready");
        timer_start(mmgr->timer, E_TIMER_WAIT_CORE_DUMP_READY);

        inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP, NULL);
        broadcast_msg(E_MSG_INTENT_CORE_DUMP_WARNING);

        if ((mmgr->info.mdm_link == E_LINK_HSIC) &&
            !(mmgr->events.link_state & E_MDM_LINK_CORE_DUMP_READ_READY))
            LOG_DEBUG("waiting for bus enumeration");
        else
            read_core_dump(mmgr);
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
            if ((mmgr->info.mdm_link == E_LINK_HSIC) && mmgr->info.is_flashless)
                set_mmgr_state(mmgr, E_MMGR_MDM_START);
            else
                set_mmgr_state(mmgr, E_MMGR_MDM_CONF_ONGOING);
        }
    } else {
        if (state & E_EV_MODEM_SELF_RESET) {
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);
            if (mmgr->state == E_MMGR_MDM_CORE_DUMP)
                notify_core_dump(&mmgr->clients, NULL, E_CD_SELF_RESET);
            else
                inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_SELF_RESET,
                                   NULL);
        }
        cleanup_ipc_event(mmgr);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
    }

out:
    return ret;
}

e_mmgr_errors_t bus_events(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    bus_read_events(&mmgr->events.bus_events);
    if (bus_handle_events(&mmgr->events.bus_events) != E_ERR_SUCCESS) {
        LOG_INFO("bus_handle_events undefined event");
        goto out;
    }
    if ((get_bus_state(&mmgr->events.bus_events) & MDM_BB_READY) &&
        (mmgr->state == E_MMGR_MDM_CONF_ONGOING)) {
        LOG_DEBUG("ready to configure modem");
        timer_stop(mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.link_state &= ~E_MDM_LINK_FLASH_READY;
        mmgr->events.link_state |= E_MDM_LINK_BB_READY;
        if (mmgr->events.link_state & E_MDM_LINK_IPC_READY)
            ret = do_configure(mmgr);
    } else if ((get_bus_state(&mmgr->events.bus_events) & MDM_FLASH_READY) &&
               (mmgr->state == E_MMGR_MDM_START)) {
        LOG_DEBUG("ready to flash modem");
        timer_stop(mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        mmgr->events.link_state |= E_MDM_LINK_FLASH_READY;
        mmgr->events.link_state &= ~E_MDM_LINK_BB_READY;
        if (mmgr->events.link_state & E_MDM_LINK_FW_DL_READY) {
            ret = do_flash(mmgr);
            if (ret != E_ERR_FAILED)
                set_mmgr_state(mmgr, E_MMGR_MDM_CONF_ONGOING);
        }
    } else if ((get_bus_state(&mmgr->events.bus_events) & MDM_CD_READY) &&
               (mmgr->state == E_MMGR_MDM_CORE_DUMP)) {
        LOG_DEBUG("ready to read a core dump");
        if (mmgr->fd_tty != CLOSED_FD) {
            inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);
            mdm_close_fds(mmgr);
        }

        mmgr->events.link_state |= E_MDM_LINK_CORE_DUMP_READ_READY;
        if (mmgr->events.link_state & E_MDM_LINK_CORE_DUMP_READY)
            read_core_dump(mmgr);
    } else {
        LOG_DEBUG("Unhandled usb event");
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
    mmgr->hdler_pre_mdm[E_EL_MODEM_COLD_RESET] = pre_mdm_cold_reset;
    mmgr->hdler_pre_mdm[E_EL_PLATFORM_REBOOT] = pre_platform_reboot;
    mmgr->hdler_pre_mdm[E_EL_MODEM_OUT_OF_SERVICE] = pre_modem_out_of_service;

    mmgr->hdler_mdm[E_EL_MODEM_COLD_RESET] = mdm_cold_reset;
    mmgr->hdler_mdm[E_EL_PLATFORM_REBOOT] = platform_reboot;
    mmgr->hdler_mdm[E_EL_MODEM_OUT_OF_SERVICE] = out_of_service;
out:
    return ret;
}
