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
#include <linux/mdm_ctrl.h>
#include "client.h"
#include "client_events.h"
#include "errors.h"
#include "logs.h"
#include "modem_events.h"
#include "modem_specific.h"
#include "socket.h"
#include "timer_events.h"

#define READ_SIZE 1024

const char *g_mmgr_requests[] = {
#undef X
#define X(a) #a
    MMGR_REQUESTS
};

/**
 * handle E_MMGR_RESOURCE_ACQUIRE request
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
        mmgr->info.ev &= ~E_EV_FORCE_MODEM_OFF;
        mmgr->request.client->resource_release = false;
        /* At least one client has acquired the resource. So, cancel
           modem shutdown if it's on going */
        if ((mmgr->info.ev & E_EV_MODEM_OFF) &&
            !(mmgr->info.ev & E_EV_WAIT_FOR_IPC_READY)) {
            LOG_DEBUG("wake up modem");
            mmgr->info.polled_states |= MDM_CTRL_STATE_IPC_READY;
            set_mcd_poll_states(mmgr);
            mmgr->info.ev |= E_EV_WAIT_FOR_IPC_READY;
            reset_escalation_counter(&mmgr->reset);
            ret = modem_up(&mmgr->info);
        }
    }

out:
    return ret;
}

/**
 * handle E_MMGR_RESOURCE_RELEASE request
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

    mmgr->request.client->resource_release = true;

    if ((mmgr->client_notification != E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) &&
        !(mmgr->info.ev & E_EV_MODEM_OFF)) {
        if (check_resource_released(&mmgr->clients, true) == E_ERR_SUCCESS) {
            LOG_INFO("notify clients that modem will be shutdown");
            mmgr->client_notification = E_MMGR_NOTIFY_MODEM_SHUTDOWN;
            inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_SHUTDOWN);
            start_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
        }
    }
out:
    return ret;
}

/**
 * handle E_MMGR_REQUEST_MODEM_RECOVERY request
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_recovery(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        if (mmgr->request.received.ts > mmgr->reset.last_reset_time.tv_sec) {
            mmgr->info.ev |= E_EV_AP_RESET;
            mmgr->events.do_restore_modem = true;
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
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t request_modem_restart(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->client_notification == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) {
        mmgr->request.answer = E_MMGR_NACK;
    } else {
        mmgr->info.ev |= E_EV_AP_RESET;
        mmgr->events.do_restore_modem = true;
        mmgr->reset.modem_restart = E_FORCE_RESET_ENABLED;
    }
out:
    return ret;
}

/**
 * handle request
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
        mmgr->request.client->cold_reset = true;
        if (check_cold_ack(&mmgr->clients, false) == E_ERR_SUCCESS) {
            LOG_DEBUG("All clients agreed cold reset");
            mmgr->info.ev |= E_EV_FORCE_RESET;
            mmgr->events.do_restore_modem = true;
        }
    }
out:
    return ret;
}

/**
 * handle request
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
        mmgr->request.client->modem_shutdown = true;
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
out:
    return ret;
}

/**
 * handle client request
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

    CHECK_PARAM(mmgr, ret, out);

    mmgr->request.answer = E_MMGR_ACK;
    mmgr->request.additional_info = E_MMGR_NUM_EVENTS;

    if (mmgr->request.received.id < E_MMGR_NUM_REQUESTS) {
        LOG_INFO("Request (%s) received from client (name=%s)",
                 g_mmgr_requests[mmgr->request.received.id],
                 mmgr->request.client->name);

        if (mmgr->hdler_client[mmgr->request.received.id] != NULL)
            ret = mmgr->hdler_client[mmgr->request.received.id] (mmgr);

        if (mmgr->request.answer < E_MMGR_NUM_EVENTS)
            inform_client(mmgr->request.client, mmgr->request.answer, false);
        if (mmgr->request.additional_info < E_MMGR_NUM_EVENTS)
            inform_all_clients(&mmgr->clients, mmgr->request.additional_info);
    }
out:
    return ret;
}

/**
 * Check if client has sent too much data, if so, the client will be banned
 *
 * @param [in,out] mmgr mmgr context
 * @param [in,out] client current client
 * @param [in,out] read_size size of last request
 *
 * @return E_ERR_BAD_PARAMETER if mmgr or client is/are NULL
 * @return E_ERR_SUCCESS client not banned
 * @return E_ERR_FAILED client banned or bad client
 */
static e_mmgr_errors_t is_client_banned(mmgr_data_t *mmgr, client_t *client,
                                        size_t read_size)
{
    struct timespec current;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);
    CHECK_PARAM(client, ret, out);

    clock_gettime(CLOCK_MONOTONIC, &current);
    if ((current.tv_sec - client->time.tv_sec) > mmgr->config.time_banned)
        client->received = 0;

    client->received += read_size;
    if (client->received >= (int)
        (mmgr->config.max_requests_banned * REQUEST_SIZE)) {
        LOG_INFO("Too much data received (%d). Client (name=%s) banned",
                 client->received, client->name);
        remove_client(&mmgr->clients, client);
        ret = E_ERR_FAILED;
        goto out;
    }

    client->time = current;
    if (read_size > REQUEST_SIZE) {
        LOG_INFO("request size higher than expected (%d)", read_size);
        ret = E_ERR_FAILED;
        goto out;
    }
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
 * @return E_ERR_FAILED if client not found or socket disconnection fails or
 *                       client banned
 */
e_mmgr_errors_t known_client(mmgr_data_t *mmgr)
{
    size_t read_size = READ_SIZE;
    char data[READ_SIZE];
    client_t *client = NULL;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    uint32_t tmp;
    int fd;

    CHECK_PARAM(mmgr, ret, out);

    fd = mmgr->events.ev[mmgr->events.cur_ev].data.fd;
    if ((ret = read_socket(fd, data, &read_size)) != E_ERR_SUCCESS)
        goto out;

    ret = find_client(&mmgr->clients, fd, &client);
    if (ret != E_ERR_SUCCESS) {
        LOG_ERROR("failed to find client (fd=%d)", fd);
        goto out;
    }
    LOG_DEBUG("Client (fd=%d name=%s) read_size=%d",
              client->fd, client->name, read_size);

    if (read_size == 0) {
        /* client disconnection */
        LOG_DEBUG("Client (fd=%d name=%s) is disconnected", client->fd,
                  client->name);
        ret = remove_client(&mmgr->clients, client);
    } else {
        if (client->received == FIRST_CLIENT_REQUEST) {
            if (read_size != (CLIENT_NAME_LEN + sizeof(uint32_t))) {
                LOG_DEBUG("bad name size=%d. Client rejected", read_size);
                ret = remove_client(&mmgr->clients, client);
                /* inform client that connection has failed */
                inform_client(client, E_MMGR_NACK, true);
            } else {
                set_client_name(client, data);
                memcpy(&tmp, data + CLIENT_NAME_LEN, sizeof(uint32_t));
                set_client_filter(client, tmp);
                /* inform client that connection has succeed */
                inform_client(client, E_MMGR_ACK, true);
                /* client is registered and accepted. So, MMGR should provide
                   the current modem status if client has subsribed to it */
                ret = inform_client(client, mmgr->client_notification, false);
            }
        } else {
            ret = is_client_banned(mmgr, client, read_size);
            if (ret != E_ERR_SUCCESS)
                goto out;
            if (read_size == REQUEST_SIZE) {
                memcpy(&tmp, data, sizeof(e_mmgr_requests_t));
                memcpy(&mmgr->request.received.ts,
                       data + sizeof(e_mmgr_requests_t), sizeof(uint32_t));

                tmp = (e_mmgr_requests_t)ntohl(tmp);
                memcpy(&mmgr->request.received, &tmp,
                       sizeof(e_mmgr_requests_t));
                mmgr->request.received.ts = ntohl(mmgr->request.received.ts);

                mmgr->request.client = client;
                ret = client_request(mmgr);
            }
        }
    }
out:
    return ret;
}

/**
 * handle new socket connection and add client in client list
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_FAILED if socket connection fails or client rejected
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
        LOG_DEBUG("try to subscribe new client");
        conn_sock = accept_socket(fd);
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

    mmgr->hdler_client[E_MMGR_RESOURCE_ACQUIRE] = request_resource_acquire;
    mmgr->hdler_client[E_MMGR_RESOURCE_RELEASE] = request_resource_release;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_RECOVERY] = request_modem_recovery;
    mmgr->hdler_client[E_MMGR_REQUEST_MODEM_RESTART] = request_modem_restart;
    mmgr->hdler_client[E_MMGR_REQUEST_FORCE_MODEM_SHUTDOWN] =
        request_force_modem_shutdown;
    mmgr->hdler_client[E_MMGR_ACK_MODEM_COLD_RESET] = request_ack_cold_reset;
    mmgr->hdler_client[E_MMGR_ACK_MODEM_SHUTDOWN] = request_ack_modem_shutdown;
out:
    return ret;
}
