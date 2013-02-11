/* Modem Manager - client list header file
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

#ifndef __MMGR_CLIENT_HEADER__
#define __MMGR_CLIENT_HEADER__

#include "data_to_msg.h"
#include "errors.h"
#include "mmgr.h"
#include <stdbool.h>
#include <time.h>

typedef e_mmgr_errors_t (*set_msg) (msg_t *, void *);

typedef enum e_cnx_requests {
    E_CNX_NONE = 0,
    E_CNX_NAME = 0x01 << 0,
    E_CNX_FILTER = 0x01 << 1,
    E_CNX_COLD_RESET = 0x01 << 2,
    E_CNX_MODEM_SHUTDOWN = 0x01 << 3,
    E_CNX_RESOURCE_RELEASED = 0x01 << 4
} e_cnx_requests_t;

typedef struct client {
    char name[CLIENT_NAME_LEN + 1];
    int fd;
    struct timespec time;
    e_mmgr_requests_t request;
    uint32_t subscription;
    /* These flags are used to store client ACKs */
    e_cnx_requests_t cnx;
    /* @TODO: remove this once MMGR will use getter/setter */
    set_msg *set_data;
} client_t;

typedef struct client_list {
    int list_size;
    int connected;
    client_t *list;
    set_msg set_data[E_MMGR_NUM_EVENTS];
} client_list_t;

e_mmgr_errors_t initialize_list(client_list_t *clients, int list_size);
e_mmgr_errors_t add_client(client_list_t *clients, int fd, client_t **client);
e_mmgr_errors_t remove_client(client_list_t *clients, client_t *client);
e_mmgr_errors_t set_client_name(client_t *client, char *name, size_t len);
e_mmgr_errors_t set_client_filter(client_t *client, uint32_t subscription);
e_mmgr_errors_t find_client(client_list_t *clients, int fd, client_t **client);

e_mmgr_errors_t inform_all_clients(client_list_t *clients,
                                   e_mmgr_events_t state);
e_mmgr_errors_t inform_client(client_t *client, e_mmgr_events_t state,
                              bool force);
e_mmgr_errors_t inform_flash_client(client_t *client, e_mmgr_events_t state, void
                                    *data, bool force);
e_mmgr_errors_t close_all_clients(client_list_t *clients);

e_mmgr_errors_t check_cold_ack(client_list_t *clients, bool listing);
e_mmgr_errors_t check_shutdown_ack(client_list_t *clients, bool listing);
e_mmgr_errors_t check_resource_released(client_list_t *clients, bool listing);

e_mmgr_errors_t reset_cold_ack(client_list_t *clients);
e_mmgr_errors_t reset_shutdown_ack(client_list_t *clients);

#endif                          /* __MMGR_CLIENT_HEADER__ */
