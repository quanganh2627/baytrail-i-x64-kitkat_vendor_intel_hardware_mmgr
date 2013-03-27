/* Modem Manager - events manager header file
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

#ifndef __MMGR_EVENTS_MANAGER_HEADER__
#define __MMGR_EVENTS_MANAGER_HEADER__

#include "bus_events.h"
#include "config.h"
#include "client.h"
#include "client_cnx.h"
#include "mmgr.h"
#include "modem_info.h"
#include "bus_events.h"
#include "reset_escalation.h"
#include "security.h"

#define EVENTS \
    X(MODEM), \
    X(NEW_CLIENT), \
    X(CLIENT), \
    X(TIMEOUT), \
    X(MCD), \
    X(BUS), \
    X(SECUR), \
    X(NUM)

#define TIMER \
    X(COLD_RESET_ACK), \
    X(MODEM_SHUTDOWN_ACK), \
    X(WAIT_FOR_IPC_READY), \
    X(WAIT_FOR_BUS_READY), \
    X(ACCEPT_CLIENT_RQUEST), \
    X(NUM)

typedef enum e_timer_type {
#undef X
#define X(a) E_TIMER_##a
    TIMER
} e_timer_type_t;

typedef enum e_events_type {
#undef X
#define X(a) E_EVENT_##a
    EVENTS
} e_events_type_t;

typedef enum e_modem_state {
    E_MDM_STATE_NONE = 0x00,
    E_MDM_STATE_BB_READY = 0x1,
    E_MDM_STATE_FLASH_READY = 0x1 << 1,
    E_MDM_STATE_IPC_READY = 0x1 << 2,
    E_MDM_STATE_FW_DL_READY = 0x1 << 3,
    E_MDM_STATE_CORE_DUMP_READY = 0x1 << 4,
    E_MDM_STATE_CORE_DUMP_READ_READY = 0x1 << 5,
} e_modem_state_t;

typedef struct mmgr_timer {
    uint8_t type;
    int cur_timeout;
    int timeout[E_TIMER_NUM];
    struct timespec start[E_TIMER_NUM];
} mmgr_timer_t;

typedef struct mmgr_events {
    int nfds;
    struct epoll_event *ev;
    int cur_ev;
    e_events_type_t state;
    bus_ev_t bus_events;
    e_modem_state_t modem_state;
} mmgr_events_t;

typedef struct current_request {
    msg_t msg;
    client_t *client;
    e_mmgr_events_t answer;
    e_mmgr_events_t additional_info;
    bool accept_request;
} current_request_t;

struct mmgr_data;
typedef e_mmgr_errors_t (*event_hdler_t) (struct mmgr_data * mmgr);

typedef struct mmgr_data {
    int epollfd;
    int fd_tty;
    int fd_cnx;
    e_mmgr_events_t client_notification;
    mmgr_configuration_t config;
    reset_management_t reset;
    client_list_t clients;
    mmgr_timer_t timer;
    modem_info_t info;
    mmgr_events_t events;
    current_request_t request;
    secur_t secur;
    /* functions handlers: */
    event_hdler_t hdler_events[E_EVENT_NUM];
    event_hdler_t hdler_client[E_MMGR_NUM_REQUESTS];
    event_hdler_t hdler_modem[E_EL_NUMBER_OF];
} mmgr_data_t;

e_mmgr_errors_t events_manager(mmgr_data_t *mmgr);
e_mmgr_errors_t events_cleanup(mmgr_data_t *mmgr);
e_mmgr_errors_t events_init(mmgr_data_t *mmgr);

#endif                          /* __MMGR_EVENTS_MANAGER_HEADER__ */
