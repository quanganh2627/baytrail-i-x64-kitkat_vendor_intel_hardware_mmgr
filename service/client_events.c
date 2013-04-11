/* Modem Manager - client events header file
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

#include <arpa/inet.h>
#include <errno.h>
#include "client.h"
#include "client_events.h"
#include "errors.h"
#include "file.h"
#include "logs.h"
#include "modem_events.h"
#include "modem_specific.h"
#include "timer_events.h"
#include "msg_to_data.h"
#include "tty.h"

const char *g_mmgr_requests[] = {
#undef X
#define X(a) #a
    MMGR_REQUESTS
};

#define RND_CERTIFICATE_FILE  "/logs/modem_rnd_certif.bin"

/**
 * handle REQUEST_MODEM_NVM_GET_ID request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_nvm_get(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    /* @TODO read nvm id */
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle REQUEST_MODEM_FW_UPDATE request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_fw_update(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_fw_update_t fw = {.fls_path = NULL };

    CHECK_PARAM(mmgr, ret, out);

    if (extract_data_fw_update(&mmgr->request.msg, &fw) != E_ERR_SUCCESS) {
        LOG_ERROR("failed to extract data");
        goto out;
    }
    /* @TODO: save file and restart modem */
    ret = E_ERR_SUCCESS;

out:
    if (fw.fls_path != NULL)
        free(fw.fls_path);
    return ret;
}

/**
 * handle REQUEST_MODEM_NVM_UPDATE request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_nvm_update(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_nvm_update_t nvm;

    CHECK_PARAM(mmgr, ret, out);

    if (extract_data_nvm_update(&mmgr->request.msg, &nvm) != E_ERR_SUCCESS) {
        LOG_ERROR("failed to extract data");
        goto out;
    }

    /* @TODO: manage nvm update request */
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_RND_ERASE request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_rnd_erase(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    /* @TODO: launch erase RND */
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_RND_GET request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_rnd_get(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    /* @ŦODO: launch get rnd process */
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_FUSE_INFO request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_fuse_info(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    /* @TODO: launch get fuse info */
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_GET_HW_ID request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_get_hw_id(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    /* @TODO: launch get hw id */
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_NVM_PROGRESS request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_nvm_progress(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_nvm_update_progress_t progress;

    CHECK_PARAM(mmgr, ret, out);

    /* @TODO: get flashing rate */
    progress.rate = 100;

    /* @TODO: when is it relevant to answer */
    ret = inform_client(mmgr->request.client,
                        E_MMGR_RESPONSE_MODEM_NVM_PROGRESS, &progress, false);
out:
    return ret;
}

/**
 * handle REQUEST_GET_BACKUP_FILE_PATH request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_backup_file_path(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_backup_path_t bkup = {.path = NULL };

    CHECK_PARAM(mmgr, ret, out);

    /* @TODO: get bkup path */

    /* @TODO: when is it relevant to answer */
    ret = inform_client(mmgr->request.client,
                        E_MMGR_RESPONSE_GET_BACKUP_FILE_PATH, &bkup, false);

out:
    return ret;
}

/**
 * handle REQUEST_MODEM_FW_PROGRESS request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_fw_progress(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_fw_update_progress_t progress;

    CHECK_PARAM(mmgr, ret, out);

    /* @TODO: get flashing rate */
    progress.rate = 100;

    /* @TODO: when is it relevant to answer */
    ret = inform_client(mmgr->request.client,
                        E_MMGR_RESPONSE_MODEM_FW_PROGRESS, &progress, false);
out:
    return ret;
}

/**
 * handle E_MMGR_SET_NAME request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_set_name(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret;

    CHECK_PARAM(mmgr, ret, out);

    ret = set_client_name(mmgr->request.client, mmgr->request.msg.data,
                          mmgr->request.msg.hdr.len);

    if (ret != E_ERR_SUCCESS)
        ret = E_ERR_DISCONNECTED;
    /* inform client that connection has succeed */
    inform_client(mmgr->request.client, E_MMGR_ACK, NULL, true);
    mmgr->request.answer = E_MMGR_NUM_EVENTS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_BACKUP_PRODUCTION request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_bkup_prod(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    /* @TODO: launch get hw id */
out:
    return ret;
}

/**
 * handle E_MMGR_SET_EVENTS request
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_set_events(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    uint32_t filter;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->request.msg.hdr.len == sizeof(uint32_t)) {
        memcpy(&filter, mmgr->request.msg.data, sizeof(uint32_t));
        filter = ntohl(filter);
        ret = set_client_filter(mmgr->request.client, filter);

        /* inform client that connection has succeed */
        inform_client(mmgr->request.client, E_MMGR_ACK, NULL, true);
        /* client is registered and accepted. So, MMGR should provide
           the current modem status if client has subsribed to it */
        ret = inform_client(mmgr->request.client, mmgr->client_notification,
                            NULL, false);
    } else {
        LOG_ERROR("bad filter size");
    }
out:
    return ret;
}

/**
 * handle E_MMGR_RESOURCE_ACQUIRE request if state is MDM_OFF
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t resource_acquire_wakeup_modem(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->request.client->cnx &= ~E_CNX_RESOURCE_RELEASED;
    /* the modem is off, then wake up the modem */
    LOG_DEBUG("wake up modem");
    /* @TODO: workaround since start_hsic in mdm_up does nothing
     * and stop_hsic makes a restart of hsic. */
    if (mmgr->info.link == E_LINK_HSIC) {
        stop_hsic(&mmgr->info);
    }

    if (mmgr->config.is_flashless)
        mmgr->info.polled_states = MDM_CTRL_STATE_FW_DOWNLOAD_READY;
    else
        mmgr->info.polled_states = MDM_CTRL_STATE_IPC_READY;
    set_mcd_poll_states(&mmgr->info);

    if ((ret = mdm_up(&mmgr->info)) == E_ERR_SUCCESS) {
        set_mmgr_state(mmgr, E_MMGR_MDM_CONF_ONGOING);
        mmgr->events.cli_req = E_CLI_REQ_NONE;
        recov_reinit(&mmgr->reset);
        if (!mmgr->config.is_flashless)
            start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
        /* if the modem is hsic, add wait_for_bus_ready */
        /* @TODO: push that into modem_specific */
        if (mmgr->info.link == E_LINK_HSIC)
            start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
    }
out:
    return ret;
}

/**
 * handle E_MMGR_RESOURCE_ACQUIRE request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t resource_acquire(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->request.client->cnx &= ~E_CNX_RESOURCE_RELEASED;

out:
    return ret;
}

/**
 * handle E_MMGR_RESOURCE_ACQUIRE request if state is WAIT_CLI_ACK
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t resource_acquire_stop_down(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->request.client->cnx &= ~E_CNX_RESOURCE_RELEASED;

    if (mmgr->events.cli_req & E_CLI_REQ_OFF) {
        /* At least one client has acquired the resource and modem shutdown
         * procedure is on going. Stop it */
        mmgr->events.cli_req &= ~E_CLI_REQ_OFF;
        stop_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
        mmgr->client_notification = E_MMGR_EVENT_MODEM_UP;
        inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);
        set_mmgr_state(mmgr, E_MMGR_MDM_UP);
    }

out:
    return ret;
}

/**
 * handle E_MMGR_RESOURCE_RELEASE request if state not MDM_OOS
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_resource_release(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->request.client->cnx |= E_CNX_RESOURCE_RELEASED;

    if (check_resource_released(&mmgr->clients, true) == E_ERR_SUCCESS) {
        LOG_INFO("notify clients that modem will be shutdown");
        mmgr->client_notification = E_MMGR_NOTIFY_MODEM_SHUTDOWN;
        inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_SHUTDOWN, NULL);
        /* if we have a current modem start procedure, stop all its timers */
        stop_all_timers(&mmgr->timer);
        start_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
        set_mmgr_state(mmgr, E_MMGR_WAIT_CLI_ACK);
    }
out:
    return ret;
}

static e_mmgr_errors_t notify_ap_reset(mmgr_data_t *mmgr)
{
    mmgr_cli_ap_reset_t ap_rst;
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(mmgr, ret, out);

    ap_rst.len = strnlen(mmgr->request.client->name, CLIENT_NAME_LEN);
    ap_rst.name = malloc(sizeof(char) * ap_rst.len);
    if (ap_rst.name == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    strncpy(ap_rst.name, mmgr->request.client->name, ap_rst.len);
    ret = inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_AP_RESET, &ap_rst);
    free(ap_rst.name);
out:
    return ret;
}

/**
 * handle E_MMGR_REQUEST_MODEM_RECOVERY request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_recovery(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int32_t sec;

    CHECK_PARAM(mmgr, ret, out);

    memcpy(&sec, &mmgr->request.msg.hdr.ts, sizeof(uint32_t));
    if (sec > mmgr->reset.last_reset_time.tv_sec) {
        mmgr->events.cli_req = E_CLI_REQ_RESET;
        notify_ap_reset(mmgr);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
    } else {
        LOG_DEBUG("skipped. Request older than last recovery");
    }
out:
    return ret;
}

/**
 * handle E_MMGR_REQUEST_MODEM_RESTART request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_restart(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->events.cli_req = E_CLI_REQ_RESET;
    mmgr->reset.modem_restart = E_FORCE_RESET_ENABLED;
    notify_ap_reset(mmgr);
    set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
out:
    return ret;
}

/**
 * handle request ACK_COLD_RESET if state is WAIT_CLI_ACK
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_ack_cold_reset(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->request.answer = E_MMGR_NUM_EVENTS;
    if (mmgr->client_notification == E_MMGR_NOTIFY_MODEM_COLD_RESET) {
        mmgr->request.client->cnx |= E_CNX_COLD_RESET;
        if (check_cold_ack(&mmgr->clients, false) == E_ERR_SUCCESS) {
            LOG_DEBUG("All clients agreed cold reset");
            mmgr->events.cli_req = E_CLI_REQ_RESET;
            set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
        }
    }
out:
    return ret;
}

/**
 * handle request ACK_MODEM_SHUTDOWN if state is WAIT_CLI_ACK
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_ack_modem_shutdown(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->request.answer = E_MMGR_NUM_EVENTS;
    if (mmgr->client_notification == E_MMGR_NOTIFY_MODEM_SHUTDOWN) {
        mmgr->request.client->cnx |= E_CNX_MODEM_SHUTDOWN;
        if (check_shutdown_ack(&mmgr->clients, false) == E_ERR_SUCCESS) {
            LOG_DEBUG("All clients agreed modem shutdown");
            mmgr->events.cli_req = E_CLI_REQ_OFF;
            stop_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
            set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
        }
    }
out:
    return ret;
}

/**
 * handle E_MMGR_REQUEST_FORCE_MODEM_SHUTDOWN request if state is MDM_UP
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_force_modem_shutdown(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->client_notification = E_MMGR_NOTIFY_MODEM_SHUTDOWN;
    mmgr->request.additional_info = E_MMGR_NOTIFY_MODEM_SHUTDOWN;
    start_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
    set_mmgr_state(mmgr, E_MMGR_WAIT_CLI_ACK);
out:
    return ret;
}

/**
 * handle client request
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_FAILED if an error occurs
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t client_request(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->request.answer = E_MMGR_ACK;
    mmgr->request.additional_info = E_MMGR_NUM_EVENTS;
    mmgr->request.msg.data = NULL;

    size = mmgr->request.msg.hdr.len;

    if (size > 0) {
        mmgr->request.msg.data = calloc(size, sizeof(char));
        if (mmgr->request.msg.data == NULL)
            goto out;
        ret = read_cnx(mmgr->request.client->fd, mmgr->request.msg.data, &size);
        if ((ret != E_ERR_SUCCESS) || (size != mmgr->request.msg.hdr.len)) {
            LOG_ERROR("Client (fd=%d name=%s) Failed to read data",
                      mmgr->request.client->fd, mmgr->request.client->name);
            goto out_free;
        }
    }

    if (mmgr->request.msg.hdr.id < E_MMGR_NUM_REQUESTS) {
        LOG_INFO("Request (%s) received from client (fd=%d name=%s)",
                 g_mmgr_requests[mmgr->request.msg.hdr.id],
                 mmgr->request.client->fd, mmgr->request.client->name);

        if (mmgr->hdler_client[mmgr->state][mmgr->request.msg.hdr.id] != NULL)
            ret = mmgr->hdler_client[mmgr->state][mmgr->request.msg.hdr.id]
                (mmgr);

        if (mmgr->request.answer < E_MMGR_NUM_EVENTS)
            inform_client(mmgr->request.client, mmgr->request.answer, NULL,
                          false);
        if (mmgr->request.additional_info < E_MMGR_NUM_EVENTS)
            inform_all_clients(&mmgr->clients, mmgr->request.additional_info,
                               NULL);
    }

out_free:
    if (mmgr->request.msg.data != NULL)
        free(mmgr->request.msg.data);
out:
    return ret;
}

/**
 * handle known client request
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED if client not found or cnx disconnection fails or
 *                       client banned
 */
e_mmgr_errors_t known_client(mmgr_data_t *mmgr)
{
    client_t *client = NULL;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    ret = find_client(&mmgr->clients,
                      mmgr->events.ev[mmgr->events.cur_ev].data.fd, &client);
    if ((ret != E_ERR_SUCCESS) || (client == NULL)) {
        LOG_ERROR("failed to find client (fd=%d)",
                  mmgr->events.ev[mmgr->events.cur_ev].data.fd);
        goto out;
    }

    ret = get_header(mmgr->events.ev[mmgr->events.cur_ev].data.fd,
                     &mmgr->request.msg.hdr);
    if (ret == E_ERR_SUCCESS) {
        mmgr->request.client = client;
        ret = client_request(mmgr);
    } else if (ret == E_ERR_DISCONNECTED) {
        /* client disconnection */
        LOG_DEBUG("Client (fd=%d name=%s) is disconnected", client->fd,
                  client->name);
        ret = remove_client(&mmgr->clients, client);
        /* client must release the locked resource, if any */
        mmgr->request.client = client;
        request_resource_release(mmgr);
    } else
        LOG_ERROR("Client (fd=%d name=%s) bad message", client->fd,
                  client->name);
out:
    return ret;
}

/**
 * handle new cnx connection and add client in client list
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_FAILED if cnx connection fails or client rejected
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t new_client(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    int conn_sock;
    client_t *client = NULL;
    int fd;

    CHECK_PARAM(mmgr, ret, out);

    fd = mmgr->events.ev[mmgr->events.cur_ev].data.fd;

    if (mmgr->clients.connected <= mmgr->config.max_clients) {
        LOG_DEBUG("try to subscribe new client fd=%d", fd);
        conn_sock = accept_cnx(fd);
        if (conn_sock < 0) {
            LOG_ERROR("Error during accept (%s)", strerror(errno));
        } else {
            if (add_fd_ev(mmgr->epollfd, conn_sock, EPOLLIN) == E_ERR_SUCCESS) {
                ret = add_client(&mmgr->clients, conn_sock, &client);
                if (ret != E_ERR_SUCCESS)
                    LOG_ERROR("failed to add new client");
                /* do not provide modem status as long as client has not
                   provided its name */
            }
        }
    } else {
        LOG_INFO("client rejected: max client reached");
    }
out:
    return ret;
}

static e_mmgr_errors_t request_fake_up(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    CHECK_PARAM(mmgr, ret, out);
    inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_UP, NULL);
out:
    return ret;
}

static e_mmgr_errors_t request_fake_down(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    CHECK_PARAM(mmgr, ret, out);
    inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_DOWN, NULL);
out:
    return ret;
}

static e_mmgr_errors_t request_fake_shtdwn(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    CHECK_PARAM(mmgr, ret, out);
    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_SHUTDOWN, NULL);
out:
    return ret;
}

static e_mmgr_errors_t request_fake_oos(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    CHECK_PARAM(mmgr, ret, out);
    inform_all_clients(&mmgr->clients, E_MMGR_EVENT_MODEM_OUT_OF_SERVICE, NULL);
out:
    return ret;
}

static e_mmgr_errors_t request_fake_cdd(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    CHECK_PARAM(mmgr, ret, out);
    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP, NULL);
out:
    return ret;
}

static e_mmgr_errors_t request_fake_ptfrmreboot(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    CHECK_PARAM(mmgr, ret, out);
    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_PLATFORM_REBOOT, NULL);
out:
    return ret;
}

static e_mmgr_errors_t request_fake_self_reset(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    CHECK_PARAM(mmgr, ret, out);
    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_SELF_RESET, NULL);
out:
    return ret;
}

static e_mmgr_errors_t request_fake_cdd_complete(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mmgr_cli_core_dump_t cd;
    char filename[PATH_MAX];

    CHECK_PARAM(mmgr, ret, out);

    snprintf(filename, PATH_MAX - 1, "%s/%s",
             mmgr->info.mcdr.data.path, FAKE_CD_FILENAME);
    create_empty_file(filename,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH |
                      S_IWOTH);

    cd.state = E_CD_SUCCEED;
    cd.panic_id = FAKE_CD_ID;
    cd.len = strnlen(filename, PATH_MAX);

    cd.path = malloc(sizeof(char) * cd.len);
    if (cd.path == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    memcpy(cd.path, filename, cd.len);
    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP_COMPLETE, &cd);
    free(cd.path);
out:
    return ret;
}

static e_mmgr_errors_t request_fake_ap_reset(mmgr_data_t *mmgr)
{
    return notify_ap_reset(mmgr);
}

static e_mmgr_errors_t request_fake_error(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mmgr_cli_error_t err = {.id = FAKE_ERROR_ID };

    CHECK_PARAM(mmgr, ret, out);

    err.len = strlen(FAKE_ERROR_REASON);
    err.reason = malloc(sizeof(char) * err.len);
    if (err.reason == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    strncpy(err.reason, FAKE_ERROR_REASON, err.len);
    inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_ERROR, &err);
    free(err.reason);
out:
    return ret;
}

e_mmgr_errors_t client_nack(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);
    mmgr->request.answer = E_MMGR_NACK;

out:
    return ret;
}

/**
 * initialize the client events handlers
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t client_events_init(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int i, j;

    CHECK_PARAM(mmgr, ret, out);

    /* Configure FSM: */

    /* NB: Never accept client request during MDM_RESET or MDM_CONF_ONGOING
     * event */

    /* set default behavior */
    for (i = 0; i < E_MMGR_NUM; i++)
        for (j = 0; j < E_MMGR_NUM_REQUESTS; j++)
            mmgr->hdler_client[i][j] = client_nack;

    /* A client is ALWAYS able to establish a connection, except during
     * MDM_RESET and MDM_CONF_ONGOING.
     * fake commands shall be accepted too  */
    for (i = 0; i < E_MMGR_NUM; i++) {
        if ((i == E_MMGR_MDM_RESET) || (i == E_MMGR_MDM_CONF_ONGOING))
            continue;

        mmgr->hdler_client[i][E_MMGR_SET_NAME] = request_set_name;
        mmgr->hdler_client[i][E_MMGR_SET_EVENTS] = request_set_events;
        /* fake requests */
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_DOWN] = request_fake_down;
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_UP] = request_fake_up;
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_MODEM_SHUTDOWN] =
            request_fake_shtdwn;
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_MODEM_OUT_OF_SERVICE] =
            request_fake_oos;
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_CORE_DUMP] = request_fake_cdd;
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_PLATFORM_REBOOT] =
            request_fake_ptfrmreboot;
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_CORE_DUMP_COMPLETE] =
            request_fake_cdd_complete;
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_AP_RESET] =
            request_fake_ap_reset;
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_SELF_RESET] =
            request_fake_self_reset;
        mmgr->hdler_client[i][E_MMGR_REQUEST_FAKE_ERROR] = request_fake_error;
    }

    /* E_MMGR_RESOURCE_ACQUIRE */
    mmgr->hdler_client[E_MMGR_MDM_OFF][E_MMGR_RESOURCE_ACQUIRE] =
        resource_acquire_wakeup_modem;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_RESOURCE_ACQUIRE] =
        resource_acquire;
    mmgr->hdler_client[E_MMGR_WAIT_CLI_ACK][E_MMGR_RESOURCE_ACQUIRE] =
        resource_acquire_stop_down;

    /* E_MMGR_RESOURCE_RELEASE */
    mmgr->hdler_client[E_MMGR_MDM_OFF][E_MMGR_RESOURCE_RELEASE] =
        request_resource_release;
    mmgr->hdler_client[E_MMGR_WAIT_CLI_ACK][E_MMGR_RESOURCE_RELEASE] =
        request_resource_release;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_RESOURCE_RELEASE] =
        request_resource_release;

    /* E_MMGR_REQUEST_MODEM_RECOVERY */
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_RECOVERY] =
        request_modem_recovery;

    /* E_MMGR_REQUEST_MODEM_RESTART */
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_RESTART] =
        request_modem_restart;

    /* E_MMGR_REQUEST_FORCE_MODEM_SHUTDOWN */
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_FORCE_MODEM_SHUTDOWN] =
        request_force_modem_shutdown;

    /* E_MMGR_ACK_MODEM_COLD_RESET */
    mmgr->hdler_client[E_MMGR_WAIT_CLI_ACK][E_MMGR_ACK_MODEM_COLD_RESET] =
        request_ack_cold_reset;

    /* E_MMGR_ACK_MODEM_SHUTDOWN */
    mmgr->hdler_client[E_MMGR_WAIT_CLI_ACK][E_MMGR_ACK_MODEM_SHUTDOWN] =
        request_ack_modem_shutdown;

    /* flashing API: */
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_FW_UPDATE] =
        request_modem_fw_update;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_RND_ERASE] =
        request_modem_rnd_erase;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_RND_GET] =
        request_modem_rnd_get;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_FUSE_INFO] =
        request_modem_fuse_info;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_GET_HW_ID] =
        request_modem_get_hw_id;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_NVM_UPDATE] =
        request_modem_nvm_update;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_NVM_GET_ID] =
        request_modem_nvm_get;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_BACKUP_PRODUCTION] =
        request_bkup_prod;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_NVM_PROGRESS] =
        request_modem_nvm_progress;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_GET_BACKUP_FILE_PATH] =
        request_backup_file_path;
    mmgr->hdler_client[E_MMGR_MDM_UP][E_MMGR_REQUEST_MODEM_FW_PROGRESS] =
        request_modem_fw_progress;
out:
    return ret;
}
