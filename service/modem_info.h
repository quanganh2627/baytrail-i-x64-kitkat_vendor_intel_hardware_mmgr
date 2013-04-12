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
#include "modem_update.h"

#define TIMEOUT_HANDSHAKE_AFTER_CD 30   /* in seconds */
#define MBD_DEV "/dev/mdm_ctrl"
#define FLASHLESS_CFG "/etc/telephony/flashless.conf"

typedef enum e_modem_events_type {
    E_EV_NONE = 0x00,
    E_EV_CONF_FAILED = 0x01 << 1,
    E_EV_MODEM_SELF_RESET = 0x01 << 2,
    E_EV_AP_RESET = 0x01 << 3,
    E_EV_CORE_DUMP = 0x01 << 4,
    E_EV_FORCE_RESET = 0x01 << 5,
    E_EV_MODEM_OFF = 0x01 << 6,
    E_EV_WAIT_FOR_IPC_READY = 0x01 << 7,
    E_EV_IPC_READY = 0x01 << 8,
    E_EV_FW_DOWNLOAD_READY = 0x01 << 9,
    E_EV_FORCE_MODEM_OFF = 0x01 << 10,
} e_modem_events_type_t;

typedef struct mup_op {
    void *hdle;
    e_mup_err_t (*initialize) (mup_interface_t **handle,
                               mup_ap_log_callback_t ap_log_callback);
    e_mup_err_t (*open_device) (mup_fw_update_params_t *params);
    e_mup_err_t (*toggle_hsi_flashing_mode) (bool flashing_mode);
    e_mup_err_t (*update_fw) (mup_fw_update_params_t *params);
    e_mup_err_t (*dispose) (mup_interface_t *handle);
    e_mup_err_t (*check_fw_version) (char *fw_path, char *version);
    e_mup_err_t (*config_secur_channel) (mup_interface_t *handle, void *func,
                                         char *rnd_path, size_t l);
} mup_op_t;

typedef struct modem_info {
    mup_op_t mup;
    e_modem_events_type_t ev;
    mcdr_lib_t mcdr;
    int fd_mcd;
    int polled_states;
    int restore_timeout;
    flashless_config_t fl_conf;
} modem_info_t;

e_mmgr_errors_t modem_info_init(const mmgr_configuration_t *config,
                                modem_info_t *info);
e_mmgr_errors_t switch_to_mux(int *fd_tty, mmgr_configuration_t *config,
                              modem_info_t *info, int timeout);

#endif                          /* _MMGR_MODEM_INFO_HEADER__ */
