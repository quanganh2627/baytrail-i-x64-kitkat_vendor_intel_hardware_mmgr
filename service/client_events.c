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
#include <sys/epoll.h>
#include "client.h"
#include "client_events.h"
#include "errors.h"
#include "logs.h"
#include "modem_events.h"
#include "modem_specific.h"
#include "timer_events.h"
#include "msg_to_data.h"

const char *g_mmgr_requests[] = {
#undef X
#define X(a) #a
    MMGR_REQUESTS
};

#define RND_CERTIFICATE_FILE  "/logs/modem_rnd_certif.bin"

/**
 * handle REQUEST_MODEM_NVM_GET_ID request
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

    if ((mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
        (mmgr->client_notification == E_MMGR_EVENT_MODEM_DOWN)) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        /* @TODO read nvm id */
    }
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle REQUEST_MODEM_FW_UPDATE request
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

    if ((mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
        (mmgr->client_notification == E_MMGR_EVENT_MODEM_DOWN)) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        if (extract_data_fw_update(&mmgr->request.msg, &fw) != E_ERR_SUCCESS) {
            LOG_ERROR("failed to extract data");
            goto out;
        }
        //TODO: save file and restart modem
    }
    ret = E_ERR_SUCCESS;

out:
    if (fw.fls_path != NULL)
        free(fw.fls_path);
    return ret;
}

/**
 * handle REQUEST_MODEM_NVM_UPDATE request
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

    if ((mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
        (mmgr->client_notification == E_MMGR_EVENT_MODEM_DOWN)) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        if (extract_data_nvm_update(&mmgr->request.msg, &nvm) != E_ERR_SUCCESS) {
            LOG_ERROR("failed to extract data");
            goto out;
        }

        /* @TODO: manage nvm update request */
    }
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_RND_ERASE request
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
 * handle REQUEST_MODEM_RND_GET request
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

    if ((mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
        (mmgr->client_notification == E_MMGR_EVENT_MODEM_DOWN)) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        /* @ŦODO: launch get rnd process */
    }
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_FUSE_INFO request
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

    if ((mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
        (mmgr->client_notification == E_MMGR_EVENT_MODEM_DOWN)) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        /* @TODO: launch get fuse info */
    }
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_GET_HW_ID request
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

    if ((mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
        (mmgr->client_notification == E_MMGR_EVENT_MODEM_DOWN)) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        /* @TODO: launch get hw id */
    }
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_NVM_PROGRESS request
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
 * handle REQUEST_GET_BACKUP_FILE_PATH request
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
    ret =
        inform_client(mmgr->request.client,
                      E_MMGR_RESPONSE_GET_BACKUP_FILE_PATH, &bkup, false);

out:
    return ret;
}

/**
 * handle REQUEST_MODEM_FW_PROGRESS request
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
 * handle E_MMGR_SET_NAME request
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
out:
    return ret;
}

/**
 * handle REQUEST_MODEM_BACKUP_PRODUCTION request
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
    e_mmgr_errors_t ret;

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
 * handle E_MMGR_RESOURCE_ACQUIRE request
 *
 * @private
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_resource_acquire(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        /* At least one client has acquired the resource. So, cancel
           modem shutdown if it's on going */
        stop_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
        mmgr->info.ev &= ~E_EV_FORCE_MODEM_OFF;
        mmgr->request.client->cnx &= ~E_CNX_RESOURCE_RELEASED;

        if (!(mmgr->info.ev & E_EV_MODEM_OFF) &&
            !(mmgr->info.ev & E_EV_FORCE_RESET)) {
            mmgr->client_notification = E_MMGR_EVENT_MODEM_UP;
            inform_all_clients(&mmgr->clients, mmgr->client_notification, NULL);
        } else {
            if (!(mmgr->info.ev & E_EV_WAIT_FOR_IPC_READY)) {
                LOG_DEBUG("wake up modem");
                //@TODO: workaround since start_hsic in modem_up does nothing
                // and stop_hsic makes a restart of hsic.
                if (!strcmp("hsic", mmgr->config.link_layer)) {
                    stop_hsic(&mmgr->info);
                }

                if (mmgr->config.is_flashless)
                    mmgr->info.polled_states = MDM_CTRL_STATE_FW_DOWNLOAD_READY;
                else
                    mmgr->info.polled_states = MDM_CTRL_STATE_IPC_READY;
                set_mcd_poll_states(&mmgr->info);

                ret = modem_up(&mmgr->info, mmgr->config.is_flashless,
                               !strcmp("hsic", mmgr->config.link_layer));
                if (ret == E_ERR_SUCCESS) {
                    mmgr->info.ev |= E_EV_WAIT_FOR_IPC_READY;
                    reset_escalation_counter(&mmgr->reset);
                    start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
                    //if the modem is hsic, add wait_for_bus_ready
                    //@TODO: push that into modem_specific
                    if (strcmp(mmgr->config.link_layer, "hsic") == 0)
                        start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
                }
            }
        }
    }

out:
    return ret;
}

/**
 * handle E_MMGR_RESOURCE_RELEASE request
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

    if ((mmgr->client_notification != E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) &&
        !(mmgr->info.ev & E_EV_MODEM_OFF)) {
        if (check_resource_released(&mmgr->clients, true) == E_ERR_SUCCESS) {
            LOG_INFO("notify clients that modem will be shutdown");
            mmgr->client_notification = E_MMGR_NOTIFY_MODEM_SHUTDOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_SHUTDOWN,
                               NULL);
            start_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
        }
    }
out:
    return ret;
}

/**
 * handle E_MMGR_REQUEST_MODEM_RECOVERY request
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

    if ((mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
        (mmgr->info.ev & E_EV_MODEM_OFF)) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        memcpy(&sec, &mmgr->request.msg.hdr.ts, sizeof(uint32_t));
        if (sec > mmgr->reset.last_reset_time.tv_sec) {
            if (mmgr->client_notification != E_MMGR_NOTIFY_MODEM_COLD_RESET) {
                mmgr->info.ev |= E_EV_AP_RESET | E_EV_FORCE_RESET;
            }
        } else {
            LOG_DEBUG("skipped. Request older than last recovery operation");
        }
    }
out:
    return ret;
}

/**
 * handle E_MMGR_REQUEST_MODEM_RESTART request
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

    if ((mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
        (mmgr->info.ev & E_EV_MODEM_OFF)) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        if (mmgr->client_notification != E_MMGR_NOTIFY_MODEM_COLD_RESET) {
            mmgr->info.ev |= E_EV_AP_RESET | E_EV_FORCE_RESET;
            mmgr->reset.modem_restart = E_FORCE_RESET_ENABLED;
        }
    }
out:
    return ret;
}

/**
 * handle request
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
            mmgr->info.ev |= E_EV_FORCE_RESET;
        }
    }
out:
    return ret;
}

/**
 * handle request
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
            mmgr->info.ev |= E_EV_FORCE_MODEM_OFF;
            stop_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
        }
    }
out:
    return ret;
}

/**
 * handle E_MMGR_REQUEST_FORCE_MODEM_SHUTDOWN request
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

    if (mmgr->info.ev & E_EV_MODEM_OFF) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        mmgr->client_notification = E_MMGR_NOTIFY_MODEM_SHUTDOWN;
        mmgr->request.additional_info = E_MMGR_NOTIFY_MODEM_SHUTDOWN;
        start_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
    }
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

    /* Not accepting client requests for now, NACK ! */
    if (!mmgr->request.accept_request) {
        mmgr->request.answer = E_MMGR_NACK;
        inform_client(mmgr->request.client, mmgr->request.answer, NULL, false);
    }

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

        if (mmgr->hdler_client[mmgr->request.msg.hdr.id] != NULL)
            ret = mmgr->hdler_client[mmgr->request.msg.hdr.id] (mmgr);

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
    if (ret != E_ERR_SUCCESS) {
        LOG_ERROR("failed to find client (fd=%d)", client->fd);
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
    struct epoll_event ev;
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
            ev.data.fd = conn_sock;
            ev.events = EPOLLIN;
            if (epoll_ctl(mmgr->epollfd, EPOLL_CTL_ADD, conn_sock, &ev) == -1) {
                LOG_ERROR("epoll_ctl: conn_sock (%s)", strerror(errno));
            } else {
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
    int i;

    CHECK_PARAM(mmgr, ret, out);

    for (i = 0; i < E_MMGR_NUM_REQUESTS; i++)
        mmgr->hdler_client[i] = NULL;

    mmgr->hdler_client[E_MMGR_SET_NAME] = request_set_name;
    mmgr->hdler_client[E_MMGR_SET_EVENTS] = request_set_events;
    mmgr->hdler_client[E_MMGR_RESOURCE_ACQUIRE] = request_resource_acquire;
    mmgr->hdler_client[E_MMGR_RESOURCE_RELEASE] = request_resource_release;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_RECOVERY] = request_modem_recovery;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_RESTART] = request_modem_restart;
    mmgr->hdler_client[E_MMGR_REQUEST_FORCE_MODEM_SHUTDOWN] =
        request_force_modem_shutdown;
    mmgr->hdler_client[E_MMGR_ACK_MODEM_COLD_RESET] = request_ack_cold_reset;
    mmgr->hdler_client[E_MMGR_ACK_MODEM_SHUTDOWN] = request_ack_modem_shutdown;
    /* flashing API: */
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_FW_UPDATE] =
        request_modem_fw_update;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_RND_ERASE] =
        request_modem_rnd_erase;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_RND_GET] = request_modem_rnd_get;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_FUSE_INFO] =
        request_modem_fuse_info;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_GET_HW_ID] =
        request_modem_get_hw_id;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_NVM_UPDATE] =
        request_modem_nvm_update;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_NVM_GET_ID] = request_modem_nvm_get;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_BACKUP_PRODUCTION] =
        request_bkup_prod;

    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_NVM_PROGRESS] =
        request_modem_nvm_progress;
    mmgr->hdler_client[E_MMGR_REQUEST_GET_BACKUP_FILE_PATH] =
        request_backup_file_path;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_FW_PROGRESS] =
        request_modem_fw_progress;

out:
    return ret;
}
