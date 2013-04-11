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
    X(NUM)

#define MMGR_STATE\
    X(MDM_OFF),\
    X(MDM_RESET),\
    X(WAIT_CLI_ACK),\
    X(MDM_CONF_ONGOING),\
    X(MDM_CORE_DUMP),\
    X(MDM_UP),\
    X(MDM_OOS),\
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

typedef enum e_client_req {
    E_CLI_REQ_NONE = 0x0,
    E_CLI_REQ_RESET = 0x1 << 1,
    E_CLI_REQ_OFF = 0x1 << 2,
} e_client_req_t;

typedef enum e_mmgr_state {
#undef X
#define X(a) E_MMGR_##a
    MMGR_STATE
} e_mmgr_state_t;

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
    e_client_req_t cli_req;
    e_mdm_link_state_t link_state;
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
typedef e_mmgr_errors_t (*reset_mdm_op_t) (modem_info_t *modem_info);

typedef struct mmgr_data {
    int epollfd;
    int fd_tty;
    int fd_cnx;
    e_mmgr_state_t state;
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
    event_hdler_t hdler_client[E_MMGR_NUM][E_MMGR_NUM_REQUESTS];
    event_hdler_t hdler_pre_mdm[E_EL_NUMBER_OF];
    reset_mdm_op_t hdler_mdm[E_EL_NUMBER_OF];
} mmgr_data_t;

e_mmgr_errors_t events_manager(mmgr_data_t *mmgr);
e_mmgr_errors_t events_cleanup(mmgr_data_t *mmgr);
e_mmgr_errors_t events_init(mmgr_data_t *mmgr);
inline void set_mmgr_state(mmgr_data_t *mmgr, e_timer_type_t state);

#endif                          /* __MMGR_EVENTS_MANAGER_HEADER__ */
