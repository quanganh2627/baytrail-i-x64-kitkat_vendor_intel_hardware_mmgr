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
#include "client_cnx.h"
#include "errors.h"
#include "logs.h"
#include "mmgr.h"

#define NEW_CLIENT_NAME "unknown"

const char *g_mmgr_events[] = {
#undef X
#define X(a) #a
    MMGR_EVENTS
};

/**
 * Check if the client is fully registered
 *
 * @param [in] client
 * @param [out] state true if registered
 *
 * @return E_ERR_BAD_PARAMETER
 * @return E_ERR_SUCCESS
 */
e_mmgr_errors_t is_registered(client_t *client, bool *state)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(client, ret, out);
    CHECK_PARAM(state, ret, out);

    *state = (client->cnx & E_CNX_NAME) && (client->cnx & E_CNX_FILTER);
out:
    return ret;
}

/**
 * Check all clients acknowledgement registered to the event
 *
 * @private
 *
 * @param [in] clients list of clients
 * @param [in] filter specify which element to check
 * @param [in] ev user should be registered to this event. If not,
 *             MMGR will take into account its ACK.
 * @param [in] listing enable or not displaying
 *
 * @return E_ERR_BAD_PARAMETER if clients or/and client is/are NULL
 * @return E_ERR_FAILED if at least one client has not acknowledge
 * @return E_ERR_SUCCESS if successful
 */
static inline e_mmgr_errors_t check_all_clients_ack(client_list_t *clients,
                                                    e_cnx_requests_t filter,
                                                    e_mmgr_events_t ev,
                                                    bool listing)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int i;

    CHECK_PARAM(clients, ret, out);

    if (ev > E_MMGR_NUM_EVENTS) {
        ret = E_ERR_FAILED;
        goto out;
    }

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd != CLOSED_FD) {
            if ((clients->list[i].subscription & (0x1 << ev)) &&
                ((clients->list[i].cnx & filter) != filter)) {
                ret = E_ERR_FAILED;
                if (listing)
                    LOG_DEBUG("client (%s) did not ack to %s",
                              clients->list[i].name, g_mmgr_events[ev]);
                else
                    break;
            }
        }
    }
out:
    return ret;
}

/**
 * Reset all clients acknowledgement
 *
 * @private
 *
 * @param [in] clients list of clients
 * @param [in] filter specify which element to check
 *
 * @return E_ERR_BAD_PARAMETER if clients or/and client is/are NULL
 * @return E_ERR_FAILED if at least one client has not acknowledge
 * @return E_ERR_SUCCESS if successful
 */
static inline e_mmgr_errors_t reset_ack(client_list_t *clients,
                                        e_cnx_requests_t filter)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int i;

    CHECK_PARAM(clients, ret, out);

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd != CLOSED_FD)
            clients->list[i].cnx &= ~filter;
    }
out:
    return ret;
}

/**
 * init current client
 *
 * @private
 *
 * @param [in] client current client
 * @param [in] fd client file descriptor
 *
 * @return E_ERR_BAD_PARAMETER if clients or/and client is/are NULL
 * @return E_ERR_FAILED if at least one client has not acknowledge
 * @return E_ERR_SUCCESS if successful
 */
static inline e_mmgr_errors_t init_client(client_t *client, int fd)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(client, ret, out);

    client->fd = fd;
    client->cnx = E_CNX_RESOURCE_RELEASED;
    /* users should be registered to these events */
    client->subscription = (0x1 << E_MMGR_ACK) | (0x1 << E_MMGR_NACK);
    strncpy(client->name, NEW_CLIENT_NAME, CLIENT_NAME_LEN);
    clock_gettime(CLOCK_MONOTONIC, &client->time);
out:
    return ret;
}

/**
 * remove client from client's list
 *
 * @private
 *
 * @param [in,out] clients list of clients
 * @param [in,out] client client to remove
 *
 * @return E_ERR_BAD_PARAMETER if clients or/and client is/are NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t remove_from_list(client_list_t *clients,
                                        client_t *client)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

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
e_mmgr_errors_t initialize_list(client_list_t *clients, int list_size)
{
    int i;
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(clients, ret, out);

    clients->list_size = list_size;
    clients->list = malloc(list_size * sizeof(client_t));
    if (clients->list != NULL) {
        for (i = 0; i < list_size; i++) {
            init_client(&clients->list[i], CLOSED_FD);
            clients->list[i].set_data = clients->set_data;
        }
        clients->connected = 0;
        ret = E_ERR_SUCCESS;
    }
    for (i = 0; i < E_MMGR_NUM_EVENTS; i++)
        clients->set_data[i] = set_msg_empty;

    clients->set_data[E_MMGR_RESPONSE_MODEM_HW_ID] = set_msg_modem_hw_id;
    clients->set_data[E_MMGR_RESPONSE_FUSE_INFO] = set_msg_fuse_info;
    clients->set_data[E_MMGR_NOTIFY_AP_RESET] = set_msg_ap_reset;
    clients->set_data[E_MMGR_NOTIFY_CORE_DUMP_COMPLETE] = set_msg_core_dump;
    clients->set_data[E_MMGR_NOTIFY_ERROR] = set_msg_error;
    clients->set_data[E_MMGR_RESPONSE_MODEM_FW_RESULT] =
        set_msg_modem_fw_result;

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
e_mmgr_errors_t add_client(client_list_t *clients, int fd, client_t **client)
{
    int i;
    e_mmgr_errors_t ret = E_ERR_FAILED;

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
 * close connexion, remove connexion on epoll and remove client from list
 *
 * @param [in,out] clients list of clients
 * @param [in,out] client current client
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t remove_client(client_list_t *clients, client_t *client)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int fd;

    CHECK_PARAM(clients, ret, out);
    CHECK_PARAM(client, ret, out);

    /* No needs to unsubscribe the fd from epoll list. It's automatically done
     * when the fd is closed. See epoll man page. As remove_from_list set fd to
     * CLOSED_FD, do a backup to close it */
    fd = client->fd;
    ret = remove_from_list(clients, client);
    close_cnx(&fd);
out:
    return ret;
}

/**
 * Set client name
 *
 * @param [in,out] client client information
 * @param [in] name new client name
 * @param [in] len name length
 *
 * @return E_ERR_BAD_PARAMETER if client or name is/are NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t set_client_name(client_t *client, char *name, size_t len)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(client, ret, out);
    CHECK_PARAM(name, ret, out);

    if (len > CLIENT_NAME_LEN) {
        LOG_ERROR("client name too long");
        len = CLIENT_NAME_LEN;
    }
    strncpy(client->name, name, len);
    client->name[len] = '\0';
    LOG_DEBUG("client with fd=%d is called \"%s\"", client->fd, client->name);
    client->cnx |= E_CNX_NAME;
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
e_mmgr_errors_t set_client_filter(client_t *client, uint32_t subscription)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(client, ret, out);

    client->subscription = subscription;
    client->cnx |= E_CNX_FILTER;
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
e_mmgr_errors_t find_client(client_list_t *clients, int fd, client_t **client)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
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
 * send message with data to client
 *
 * @param [in] client client to inform
 * @param [in] state state to provide
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER clients or/and client is/are NULL
 * @return E_ERR_SUCCESS if not found
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t inform_client(client_t *client, e_mmgr_events_t state,
                              void *data)
{
    size_t size;
    size_t write_size;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mmgr_cli_event_t event = { .id = state, .data = data };
    msg_t msg = { .data = NULL };

    CHECK_PARAM(client, ret, out);
    /* do not check data because it can be NULL on purpose */

    if (client->set_data[state] == NULL) {
        LOG_ERROR("function is NULL");
        ret = E_ERR_FAILED;
        goto out;
    }

    client->set_data[state] (&msg, &event);

    size = SIZE_HEADER + msg.hdr.len;
    write_size = size;
    if ((0x01 << state) & client->subscription) {
        if ((ret = write_cnx(client->fd, msg.data, &write_size)) !=
            E_ERR_SUCCESS)
            goto out;

        if (size != write_size) {
            LOG_ERROR("send failed for client (fd=%d name=%s) send=%d/%d",
                      client->fd, client->name, write_size, size);
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
    delete_msg(&msg);
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
e_mmgr_errors_t inform_all_clients(client_list_t *clients,
                                   e_mmgr_events_t state, void *data)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int i;
    static bool down_state = false;

    if (state == E_MMGR_EVENT_MODEM_DOWN) {
        if (down_state)
            goto out;
        else
            down_state = true;
    } else if (state == E_MMGR_EVENT_MODEM_UP) {
        down_state = false;
    }

    CHECK_PARAM(clients, ret, out);
    /* do not check data because it can be NULL on purpose */

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd != CLOSED_FD)
            ret = inform_client(&clients->list[i], state, data);
    }
out:
    return ret;
}

/**
 * close all connexion's client fd
 *
 * @param [in,out] clients list of clients
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t close_all_clients(client_list_t *clients)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int i;

    CHECK_PARAM(clients, ret, out);

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd != CLOSED_FD) {
            LOG_DEBUG("i=%d fd=%d", i, clients->list[i].fd);
            close_cnx(&clients->list[i].fd);
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
e_mmgr_errors_t check_cold_ack(client_list_t *clients, bool listing)
{
    return check_all_clients_ack(clients, E_CNX_COLD_RESET,
                                 E_MMGR_NOTIFY_MODEM_COLD_RESET, listing);
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
e_mmgr_errors_t check_shutdown_ack(client_list_t *clients, bool listing)
{
    return check_all_clients_ack(clients, E_CNX_MODEM_SHUTDOWN,
                                 E_MMGR_NOTIFY_MODEM_SHUTDOWN, listing);
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
e_mmgr_errors_t check_resource_released(client_list_t *clients, bool listing)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int i;

    CHECK_PARAM(clients, ret, out);

    for (i = 0; i < clients->list_size; i++) {
        if (clients->list[i].fd != CLOSED_FD) {
            if ((clients->list[i].cnx & E_CNX_RESOURCE_RELEASED)
                != E_CNX_RESOURCE_RELEASED) {
                ret = E_ERR_FAILED;
                if (listing)
                    LOG_DEBUG("client (%s) did not release",
                              clients->list[i].name);
                else
                    break;
            }
        }
    }
out:
    return ret;
}

/**
 * reset cold ack flag for all connected clients
 *
 * @param [in,out] clients list of clients
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t reset_cold_ack(client_list_t *clients)
{
    return reset_ack(clients, E_CNX_COLD_RESET);
}

/**
 * reset shutdown ack flag for all connected clients
 *
 * @param [in,out] clients list of clients
 *
 * @return E_ERR_BAD_PARAMETER if clients is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t reset_shutdown_ack(client_list_t *clients)
{
    return reset_ack(clients, E_CNX_MODEM_SHUTDOWN);
}
