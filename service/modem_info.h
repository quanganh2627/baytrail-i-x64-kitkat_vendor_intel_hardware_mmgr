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
#include <time.h>
#include "config.h"
#include "core_dump.h"

#define UNKNOWN_PANIC_ID -1
#define TIMEOUT_HANDSHAKE_AFTER_CD 30   /* in seconds */
#define MBD_DEV "/dev/mdm_ctrl"
#define FLASHLESS_CFG "/etc/telephony/flashless.conf"

typedef enum e_modem_events_type {
    E_EV_NONE = 0x00,
    E_EV_CONF_FAILED = 0x01 << 1,
    E_EV_MODEM_SELF_RESET = 0x01 << 2,
    E_EV_AP_RESET = 0x01 << 3,
    E_EV_CORE_DUMP = 0x01 << 4,
    E_EV_CORE_DUMP_SUCCEED = 0x01 << 5,
    E_EV_CORE_DUMP_FAILED = 0x01 << 6,
    E_EV_FORCE_RESET = 0x01 << 7,
    E_EV_MODEM_OFF = 0x01 << 8,
    E_EV_WAIT_FOR_IPC_READY = 0x01 << 9,
    E_EV_IPC_READY = 0x01 << 10,
    E_EV_FW_DOWNLOAD_READY = 0x01 << 11,
} e_modem_events_type_t;

typedef struct modem_info {
    int panic_id;
    e_modem_events_type_t ev;
    mcdr_lib_t mcdr;
    int fd_mcd;
    int polled_states;
    int restore_timeout;
    char fls_in[MAX_SIZE_CONF_VAL];
    char fls_out[MAX_SIZE_CONF_VAL];
    char nvm_files_path[MAX_SIZE_CONF_VAL];
    char cal_path[MAX_SIZE_CONF_VAL];
} modem_info_t;

e_mmgr_errors_t modem_info_init(const mmgr_configuration_t *config,
                                modem_info_t *info);
e_mmgr_errors_t switch_to_mux(int *fd_tty, mmgr_configuration_t *config,
                              modem_info_t *info, int timeout);
e_mmgr_errors_t manage_core_dump(mmgr_configuration_t *config,
                                 modem_info_t *info);

#endif                          /* _MMGR_MODEM_INFO_HEADER__ */
