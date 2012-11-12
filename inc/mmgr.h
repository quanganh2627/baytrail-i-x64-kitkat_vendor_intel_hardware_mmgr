/* Modem Manager (MMGR) - external include file
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

#ifndef __MMGR_EXTERNAL_HEADER_FILE__
#define __MMGR_EXTERNAL_HEADER_FILE__

#define MMGR_SOCKET_NAME "mmgr"
#define CLIENT_NAME_LEN 64

/* Please read README file to have useful information about
   MMGR requests */

#define MMGR_REQUESTS \
    /* Resource allocation: Clients -> MMGR */ \
    X(RESOURCE_ACQUIRE), \
    X(RESOURCE_RELEASE), \
    /* Requests: Clients -> MMGR */ \
    X(REQUEST_MODEM_RECOVERY), \
    X(REQUEST_MODEM_RESTART), \
    X(REQUEST_FORCE_MODEM_SHUTDOWN), \
    /* ACK: Clients -> MMGR */ \
    X(ACK_MODEM_COLD_RESET), \
    X(ACK_MODEM_SHUTDOWN), \
    X(NUM_REQUESTS)

#define MMGR_EVENTS \
    /* Events notification: MMGR -> Clients */ \
    X(EVENT_MODEM_DOWN), \
    X(EVENT_MODEM_UP), \
    X(EVENT_MODEM_OUT_OF_SERVICE), \
    /* Notifications: MMGR -> Clients */ \
    X(NOTIFY_MODEM_WARM_RESET), \
    X(NOTIFY_MODEM_COLD_RESET), \
    X(NOTIFY_MODEM_SHUTDOWN), \
    X(NOTIFY_PLATFORM_REBOOT), \
    X(NOTIFY_CORE_DUMP), \
    /* ACK: MMGR -> Clients */ \
    X(ACK), \
    X(NACK), \
    X(NUM_EVENTS)

typedef enum e_mmgr_requests {
#undef X
#define X(a) E_MMGR_##a
    MMGR_REQUESTS
} e_mmgr_requests_t;

typedef enum e_mmgr_events {
#undef X
#define X(a) E_MMGR_##a
    MMGR_EVENTS
} e_mmgr_events_t;

extern const char *g_mmgr_requests[];
extern const char *g_mmgr_events[];

#define REQUEST_SIZE (sizeof(uint32_t) + sizeof(uint32_t))

#endif                          /* __MMGR_EXTERNAL_HEADER_FILE__ */
