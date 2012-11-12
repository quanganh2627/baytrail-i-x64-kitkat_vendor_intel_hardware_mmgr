/* Modem Manager - client list source file
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
#include <sys/socket.h>
#include "client.h"
#include "errors.h"
#include "logs.h"
#include "mmgr.h"
#include "socket.h"

#define NEW_CLIENT_NAME "unknown"

const char *g_mmgr_events[] = {
#undef X
#define X(a) #a
    MMGR_EVENTS
};

/**
 * Check all clients acknowledgement
 *
 * @param [in] clients list of clients
 * @param [in] offset specify which element to check
 * @param [in] msg message to display
 * @param [in] listing enable or not displaying
 *
 * @return E_ERR_BAD_PARAMETER if clients or/and client is/are NULL
 * @return E_ERR_FAILED if at least one client has not acknowledge
 * @return E_ERR_SUCCESS if successful
 */
static inline int check_all_clients_ack(client_list_t *clients, size_t offset,
                                        char *msg, bool listing)
{
    int ret = E_ERR_SUCCESS;
    int i;
    bool *ack = NULL;

    CHECK_PARAM(clients, ret, out);

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd != CLOSED_FD) {
            ack = (bool *)((void *)&(clients->list[i]) + offset);
            if (!*ack) {
                ret = E_ERR_FAILED;
                if (listing) {
                    LOG_DEBUG("client (%s) did not %s",
                              clients->list[i].name, msg);
                } else {
                    break;
                }
            }
        }
    }
out:
    return ret;
}

/**
 * Reset all clients acknowledgement
 *
 * @param [in] clients list of clients
 * @param [in] offset specify which element to check
 *
 * @return E_ERR_BAD_PARAMETER if clients or/and client is/are NULL
 * @return E_ERR_FAILED if at least one client has not acknowledge
 * @return E_ERR_SUCCESS if successful
 */
static inline int reset_ack(client_list_t *clients, size_t offset)
{
    int ret = E_ERR_SUCCESS;
    int i;
    bool *ack;

    CHECK_PARAM(clients, ret, out);

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd != CLOSED_FD) {
            ack = ((void *)&(clients->list[i]) + offset);
            *ack = false;
        }
    }
out:
    return ret;
}

/**
 * init current client
 *
 * @param [in] client current client
 * @param [in] fd client file descriptor
 *
 * @return E_ERR_BAD_PARAMETER if clients or/and client is/are NULL
 * @return E_ERR_FAILED if at least one client has not acknowledge
 * @return E_ERR_SUCCESS if successful
 */
static inline int init_client(client_t *client, int fd)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(client, ret, out);

    client->fd = fd;
    client->cold_reset = false;
    client->modem_shutdown = false;
    client->resource_release = true;
    client->received = FIRST_CLIENT_REQUEST;
    client->subscription = 0;
    strncpy(client->name, NEW_CLIENT_NAME, CLIENT_NAME_LEN);
    clock_gettime(CLOCK_MONOTONIC, &client->time);
out:
    return ret;
}

/**
 * remove client from client's list
 *
 * @param [in,out] clients list of clients
 * @param [in,out] client client to remove
 *
 * @return E_ERR_BAD_PARAMETER if clients or/and client is/are NULL
 * @return E_ERR_SUCCESS if successful
 */
static int remove_from_list(client_list_t *clients, client_t *client)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(clients, ret, out);
    CHECK_PARAM(client, ret, out);

    clients->connected--;
    LOG_INFO("client (fd=%d name=%s) removed. still connected: %d",
             client->fd, client->name, clients->connected);
    client->fd = CLOSED_FD;
out:
    return ret;
}

/**
 * initialize client list structure
 *
 * @param [in,out] clients list of clients
 * @param [in] list_size size of clients
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
int initialize_list(client_list_t *clients, int list_size)
{
    int i;
    int ret = E_ERR_FAILED;

    CHECK_PARAM(clients, ret, out);

    clients->list_size = list_size;
    clients->list = malloc(list_size * sizeof(client_t));
    if (clients->list != NULL) {
        for (i = 0; i < list_size; i++)
            init_client(&clients->list[i], CLOSED_FD);
        clients->connected = 0;
        ret = E_ERR_SUCCESS;
    }
out:
    return ret;
}

/**
 * add new client to list
 *
 * @param [in,out] clients list of clients
 * @param [in] fd client file descriptor
 * @param [in,out] client pointer to new client. NULL if failed
 *
 * @return E_ERR_BAD_PARAMETER if clients or/and client is/are NULL
 * @return E_ERR_FAILED no space
 * @return E_ERR_SUCCESS if successful
 */
int add_client(client_list_t *clients, int fd, client_t **client)
{
    int i;
    int ret = E_ERR_FAILED;

    CHECK_PARAM(clients, ret, out);
    CHECK_PARAM(client, ret, out);

    *client = NULL;

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd == CLOSED_FD) {
            init_client(&clients->list[i], fd);
            clients->connected++;
            LOG_DEBUG("client (fd=%d) added. connected: %d",
                      fd, clients->connected);
            *client = &clients->list[i];
            ret = E_ERR_SUCCESS;
            break;
        }

    }
out:
    return ret;
}

/**
 * close socket, remove socket on epoll and remove client from list
 *
 * @param [in,out] clients list of clients
 * @param [in,out] client current client
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
int remove_client(client_list_t *clients, client_t *client)
{
    int ret = E_ERR_SUCCESS;
    int fd;

    CHECK_PARAM(clients, ret, out);
    CHECK_PARAM(client, ret, out);

    /* No needs to unsubscribe the fd from epoll list. It's automatically done
       when the fd is closed. See epoll man page.
       As remove_from_list set fd to CLOSED_FD, do a backup to close it */
    fd = client->fd;
    ret = remove_from_list(clients, client);
    close_socket(&fd);
out:
    return ret;
}

/**
 * Set client name
 *
 * @param [in,out] client client information
 * @param [in] name new client name
 *
 * @return E_ERR_BAD_PARAMETER if client or name is/are NULL
 * @return E_ERR_SUCCESS if successful
 */
int set_client_name(client_t *client, char *name)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(client, ret, out);
    CHECK_PARAM(name, ret, out);

    strncpy(client->name, name, CLIENT_NAME_LEN);
    client->received = 0;
    LOG_DEBUG("client with fd=%d is called %s", client->fd, client->name);
out:
    return ret;
}

/**
 * set client filter events
 *
 * @param [in,out] client client information
 * @param [in] subscription client filter param
 *
 * @return E_ERR_BAD_PARAMETER if client or name is/are NULL
 * @return E_ERR_SUCCESS if successful
 */
int set_client_filter(client_t *client, uint32_t subscription)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(client, ret, out);

    client->subscription = subscription;
    LOG_DEBUG("client (fd=%d name=%s) filter=0x%.8X", client->fd, client->name,
              client->subscription);
out:
    return ret;
}

/**
 * find the client on client list
 *
 * @param [in] clients list of clients
 * @param [in] fd client's file descriptor
 * @param[out] client client found
 *
 * @return E_ERR_BAD_PARAMETER clients or/and client is/are NULL
 * @return E_ERR_SUCCESS if not found
 * @return E_ERR_SUCCESS if successful
 */
int find_client(client_list_t *clients, int fd, client_t **client)
{
    int ret = E_ERR_FAILED;
    int i;

    CHECK_PARAM(clients, ret, out);
    CHECK_PARAM(client, ret, out);

    *client = NULL;

    for (i = 0; i < clients->list_size; i++) {
        if (fd == clients->list[i].fd) {
            *client = &clients->list[i];
            ret = E_ERR_SUCCESS;
            break;
        }
    }

out:
    return ret;
}

/**
 * send state to client
 *
 * @param [in,out] client client info
 * @param [in] state current modem state
 * @param [in] force if true send request even if not subscribed
 *
 * @return E_ERR_BAD_PARAMETER if client is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
int inform_client(client_t *client, e_mmgr_events_t state, bool force)
{
    size_t data_size = sizeof(e_mmgr_events_t);
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(client, ret, out);

    if (force || ((0x01 << state) & client->subscription)) {
        if ((ret = write_socket(client->fd, &state, &data_size)) !=
            E_ERR_SUCCESS)
            goto out;

        if ((data_size <= 0) || (data_size > sizeof(e_mmgr_events_t))) {
            LOG_ERROR("send failed for client (fd=%d name=%s) size=%d (%s)",
                      client->fd, client->name, data_size, strerror(errno));
            ret = E_ERR_FAILED;
        } else {
            LOG_DEBUG("Client (fd=%d name=%s) informed of: %s", client->fd,
                      client->name, g_mmgr_events[state]);
        }
    } else {
        LOG_DEBUG("Client (fd=%d name=%s) NOT informed of: %s",
                  client->fd, client->name, g_mmgr_events[state]);
    }
out:
    return ret;
}

/**
 * inform all clients of modem state
 *
 * @param [in,out] clients list of clients
 * @param [in] state current modem state
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
int inform_all_clients(client_list_t *clients, e_mmgr_events_t state)
{
    int ret = E_ERR_SUCCESS;
    int i;

    CHECK_PARAM(clients, ret, out);

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd != CLOSED_FD)
            ret = inform_client(&clients->list[i], state, false);
    }
out:
    return ret;
}

/**
 * close all socket's client fd
 *
 * @param [in,out] clients list of clients
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_SUCCESS if successful
 */
int close_all_clients(client_list_t *clients)
{
    int ret = E_ERR_SUCCESS;
    int i;

    CHECK_PARAM(clients, ret, out);

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd != CLOSED_FD) {
            LOG_DEBUG("i=%d fd=%d", i, clients->list[i].fd);
            close_socket(&clients->list[i].fd);
        }
    }
out:
    return ret;
}

/**
 * check if all clients have acknowledge the modem cold request
 *
 * @param [in,out] clients list of clients
 * @param [in] listing enable display
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_FAILED if at least one client has not ack
 * @return E_ERR_SUCCESS all clients have released
 */
int check_cold_ack(client_list_t *clients, bool listing)
{
    return check_all_clients_ack(clients, offsetof(client_t, cold_reset),
                                 "ack", listing);
}

/**
 * check if all clients have acknowledge the shutdown request
 *
 * @param [in,out] clients list of clients
 * @param [in] listing enable display
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_FAILED if at least one client has not ack
 * @return E_ERR_SUCCESS all clients have released
 */
int check_shutdown_ack(client_list_t *clients, bool listing)
{
    return check_all_clients_ack(clients, offsetof(client_t, modem_shutdown),
                                 "ack", listing);
}

/**
 * check if all clients have released the resource
 *
 * @param [in,out] clients list of clients
 * @param [in] listing enable display
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_FAILED if at least one client has not released
 * @return E_ERR_SUCCESS all clients have released
 */
int check_resource_released(client_list_t *clients, bool listing)
{
    return check_all_clients_ack(clients, offsetof(client_t, resource_release),
                                 "release", listing);
}

/**
 * reset cold ack flag for all connected clients
 *
 * @param [in,out] clients list of clients
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_SUCCESS if successful
 */
int reset_cold_ack(client_list_t *clients)
{
    return reset_ack(clients, offsetof(client_t, cold_reset));
}

/**
 * reset shutdown ack flag for all connected clients
 *
 * @param [in,out] clients list of clients
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_SUCCESS if successful
 */
int reset_shutdown_ack(client_list_t *clients)
{
    return reset_ack(clients, offsetof(client_t, modem_shutdown));
}
