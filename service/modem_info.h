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

#define HANDSHAKE_AFTER_CD_RETRIES_COUNT 12
#define CORE_DUMP_READY_TIMEOUT 10      /* 10 seconds for modem to re-enumerate
                                         * in flashing mode */
#define MBD_DEV "/dev/mdm_ctrl"
#define FLASHLESS_CFG "/etc/telephony/flashless.conf"

typedef enum e_modem_events_type {
    E_EV_NONE = 0x0,
    E_EV_MODEM_SELF_RESET = 0x1,
    E_EV_CORE_DUMP = 0x1 << 1,
    E_EV_IPC_READY = 0x1 << 2,
    E_EV_FW_DOWNLOAD_READY = 0x1 << 3,
    E_EV_MODEM_OFF = 0x1 << 4,
    E_EV_CONF_FAILED = 0x1 << 5,
} e_modem_events_type_t;

typedef enum e_mdm_link_state {
    E_MDM_LINK_NONE = 0x0,
    E_MDM_LINK_BB_READY = 0x1,  /* configure modem */
    E_MDM_LINK_FLASH_READY = 0x1 << 1,  /* flash modem */
    E_MDM_LINK_FW_DL_READY = 0x1 << 2,
    E_MDM_LINK_IPC_READY = 0x1 << 3,
    E_MDM_LINK_CORE_DUMP_READY = 0x1 << 4,
    E_MDM_LINK_CORE_DUMP_READ_READY = 0x1 << 5,
} e_mdm_link_state_t;

typedef struct mup_op {
    void *hdle;
    e_mup_err_t (*initialize) (mup_interface_t **handle,
                               mup_ap_log_callback_t ap_log_callback);
    e_mup_err_t (*open_device) (mup_fw_update_params_t *params);
    e_mup_err_t (*toggle_hsi_flashing_mode) (bool flashing_mode);
    e_mup_err_t (*update_fw) (mup_fw_update_params_t *params);
    e_mup_err_t (*update_nvm) (mup_nvm_update_params_t *params);
    e_mup_err_t (*read_nvm_id) (mup_nvm_read_id_params_t *params);
    e_mup_err_t (*dispose) (mup_interface_t *handle);
    e_mup_err_t (*check_fw_version) (char *fw_path, char *version);
    e_mup_err_t (*config_secur_channel) (mup_interface_t *handle, void *func,
                                         char *rnd_path, size_t l);
    e_mup_err_t (*gen_fls) (const char *in, const char *out, const char *dir,
                            const char *certificate, const char *secur);
} mup_op_t;

typedef enum e_link_type {
    E_LINK_UART,
    E_LINK_HSI,
    E_LINK_HSIC,
} e_link_type_t;

typedef struct modem_info {
    mup_op_t mup;
    mcdr_lib_t mcdr;
    int fd_mcd;
    int polled_states;
    flashless_config_t fl_conf;
    bool is_flashless;
    e_link_type_t mdm_link;     /* modem link */
    e_link_type_t cd_link;      /* core dump link */
    char *hsic_pm_path;
    char *hsic_enable_path;
} modem_info_t;

e_mmgr_errors_t modem_info_init(const mmgr_configuration_t *config,
                                modem_info_t *info);
e_mmgr_errors_t switch_to_mux(int *fd_tty, mmgr_configuration_t *config,
                              modem_info_t *info, int timeout);

#endif                          /* _MMGR_MODEM_INFO_HEADER__ */
