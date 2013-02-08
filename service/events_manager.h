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

#include "config.h"
#include "client.h"
#include "mmgr.h"
#include "modem_info.h"
#include "reset_escalation.h"

#define TIMEOUT_ACK 1           /* in second */
#define TIMEOUT_EPOLL_ACK 200   /* in milliseconds */
#define TIMEOUT_EPOLL_INFINITE -1       /* wait indefinitely */
#define STEPS 10

#define FORCE_MODEM_SHUTDOWN(mmgr) do { \
    mmgr->info.ev |= E_EV_AP_RESET; \
    mmgr->events.restore_modem = true; \
    mmgr->reset.modem_shutdown = true; \
} while (0)

#define START_TIMER(timer, timeout) do { \
    timer.timeout = timeout; \
    clock_gettime(CLOCK_MONOTONIC, &timer.start); \
} while (0)

#define STOP_TIMER(timer) do { \
    LOG_DEBUG("timer stopped"); \
    timer.timeout = TIMEOUT_EPOLL_INFINITE; \
} while (0)

#define EVENTS \
    X(MODEM), \
    X(NEW_CLIENT), \
    X(CLIENT), \
    X(TIMEOUT), \
    X(NUM)

typedef enum e_events_type {
#undef X
#define X(a) E_EVENT_##a
    EVENTS
} e_events_type_t;

typedef struct mmgr_events {
    int nfds;
    struct epoll_event *ev;
    int cur_ev;
    e_events_type_t state;
    bool restore_modem;
    bool modem_shutdown;
    bool inform_down;
} mmgr_events_t;

typedef struct mmgr_timer {
    int timeout;
    struct timespec start;
} mmgr_timer_t;

typedef struct client_request {
    e_mmgr_requests_t id;
    uint32_t ts;
} client_request_t;

typedef struct current_request {
    client_request_t received;
    client_t *client;
    e_mmgr_events_t answer;
    e_mmgr_events_t additional_info;
} current_request_t;

struct mmgr_data;
typedef int (*event_hdler_t) (struct mmgr_data * mmgr);

typedef struct mmgr_data {
    int epollfd;
    int fd_tty;
    int fd_socket;
    e_mmgr_events_t modem_state;
    mmgr_configuration_t config;
    reset_management_t reset;
    client_list_t clients;
    mmgr_timer_t timer;
    modem_info_t info;
    mmgr_events_t events;
    current_request_t request;
    /* functions handlers: */
    event_hdler_t hdler_events[E_EVENT_NUM];
    event_hdler_t hdler_client[E_MMGR_NUM_REQUESTS];
    event_hdler_t hdler_modem[E_EL_NUMBER_OF];
} mmgr_data_t;

int events_manager(mmgr_data_t *mmgr);
int events_cleanup(mmgr_data_t *mmgr);
int events_init(mmgr_data_t *mmgr);

#endif                          /* __MMGR_EVENTS_MANAGER_HEADER__ */
