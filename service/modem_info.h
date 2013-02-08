/* Modem Manager - modem info header file
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
#ifndef _MMGR_MODEM_INFO_HEADER__
#define _MMGR_MODEM_INFO_HEADER__

#include <stdbool.h>
#include <limits.h>             /* @TODO: remove me when Modem Boot Driver will be used */
#include <time.h>
#include "config.h"
#include "core_dump.h"

#define UNKNOWN_PANIC_ID -1
#define TIMEOUT_HANDSHAKE_AFTER_CD 30   /* in seconds */

/* @TODO: remove me when Modem Boot Driver will be used */
typedef enum hsi_type {
    E_HSI_DLP,
    E_HSI_FFL
} e_hsi_type_t;

/* @TODO: remove me when Modem Boot Driver will be used */
typedef enum e_hsi_path {
    E_HSI_PATH_WARM,
    E_HSI_PATH_COLD,
    E_HSI_PATH_HANGUP,
    E_HSI_PATH_POWER_OFF,
    E_HSI_PATH_NUM
} e_hsi_path_t;

typedef enum e_modem_events_type {
    E_EV_NONE = 0x00,
    E_EV_MODEM_HANDSHAKE_FAILED = 0x01,
    E_EV_LINE_DISCIPLINE_FAILED = 0x01 << 1,
    E_EV_MODEM_MUX_INIT_FAILED = 0x01 << 2,
    E_EV_MODEM_SELF_RESET = 0x01 << 3,
    E_EV_AP_RESET = 0x01 << 4,
    E_EV_CORE_DUMP = 0x01 << 5,
    E_EV_CORE_DUMP_SUCCEED = 0x01 << 6,
    E_EV_CORE_DUMP_FAILED = 0x01 << 7,
    E_EV_FORCE_RESET = 0x01 << 8,
    E_EV_OPEN_FAILED = 0x01 << 9,
} e_modem_events_type_t;

typedef struct modem_info {
    int panic_id;
    e_modem_events_type_t ev;
    mcdr_lib_t mcdr;
    /* @TODO: remove me when Modem Boot Driver will be used */
    e_hsi_type_t hsi_type;
    char hsi_path[E_HSI_PATH_NUM][PATH_MAX];
} modem_info_t;

int modem_info_init(const mmgr_configuration_t *config, modem_info_t *info);
int check_modem_state(mmgr_configuration_t *config, modem_info_t *info);
int switch_to_mux(int *fd_tty, mmgr_configuration_t *config,
                  modem_info_t *info, int timeout);
int manage_core_dump(mmgr_configuration_t *config, modem_info_t *info);
int get_sysfs_path(modem_info_t *info, e_hsi_path_t hsi_path, char **path);

#endif                          /* _MMGR_MODEM_INFO_HEADER__ */
