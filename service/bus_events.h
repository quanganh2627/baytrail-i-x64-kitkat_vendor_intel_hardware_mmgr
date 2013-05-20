/* Modem Manager - bus events header file
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

#ifndef __MMGR_BUS_EV_MANAGER_HEADER__
#define __MMGR_BUS_EV_MANAGER_HEADER__

#include <inttypes.h>
#include <linux/limits.h>
#include "events_manager.h"
#include "errors.h"

#define BUS_EV_CAPACITY 32
#define MDM_FLASH_READY 1
#define MDM_BB_READY 2
#define MDM_CD_READY 4

typedef enum {
    EV_NONE,
    EV_ADDED,
    EV_DELETED
} e_bus_ev_t;

typedef struct {
    char path[PATH_MAX];
    e_bus_ev_t event;
} bus_event_t;

typedef struct {
    int i;
    bus_event_t evs[BUS_EV_CAPACITY];
} bus_ev_cli_ctx_t;

typedef struct {
    struct usb_host_context *ctx;
    bus_ev_cli_ctx_t cli_ctx;
    int mdm_state;
    int wd_fd;
    char modem_flash_path[PATH_MAX];
    char modem_bb_path[PATH_MAX];
    char modem_cd_path[PATH_MAX];
    uint16_t modem_flash_pid;
    uint16_t modem_flash_vid;
    uint16_t modem_bb_pid;
    uint16_t modem_bb_vid;
    uint16_t mcdr_bb_pid;
    uint16_t mcdr_bb_vid;
} bus_ev_t;

e_mmgr_errors_t bus_events_init(bus_ev_t *bus_events, char *bb_pid,
                                char *bb_vid, char *flash_pid, char *flash_vid,
                                char *mcdr_pid, char *mcdr_vid);
int get_bus_state(bus_ev_t *bus_event);
int bus_ev_get_fd(bus_ev_t *bus_events);
int bus_read_events(bus_ev_t *bus_events);
e_mmgr_errors_t bus_handle_events(bus_ev_t *bus_events);

#endif                          /* __MMGR_BUS_EV_MANAGER_HEADER__ */
