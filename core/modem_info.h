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
#include "modem_update.h"
#include "tcs_config.h"
#include "tcs_mmgr.h"
#include "pm.h"
#include "ctrl.h"
#include "file.h"

#define HANDSHAKE_AFTER_CD_RETRIES_COUNT 12

typedef enum e_mdm_link_state {
    E_MDM_LINK_NONE = 0x0,
    E_MDM_LINK_BB_READY = 0x1,         /* configure modem */
    E_MDM_LINK_FLASH_READY = 0x1 << 1, /* flash modem */
        E_MDM_LINK_FW_DL_READY = 0x1 << 2,
        E_MDM_LINK_IPC_READY = 0x1 << 3,
        E_MDM_LINK_CORE_DUMP_READY = 0x1 << 4,
        E_MDM_LINK_CORE_DUMP_READ_READY = 0x1 << 5,
} e_mdm_link_state_t;

typedef enum e_mdm_wakeup_cfg {
    E_MDM_WAKEUP_UNKNOWN,
    E_MDM_WAKEUP_INBAND,
    E_MDM_WAKEUP_OUTBAND,
} e_mdm_wakeup_cfg_t;


typedef enum e_cd_status {
    /* General */
    E_STATUS_COMPLETE = 0,  /** CD was generated successfully */
    E_STATUS_UNCOMPLETED,   /** Time-out occured during CD generation or more
                             * data must be read */
    E_STATUS_FAILED,        /** Failure while generating core dump */
    E_STATUS_NONE           /** No core dump was generated */
} e_cd_status_t;

typedef struct modem_info {
    bool ipc_ready_present;
    e_link_t mdm_link;          /* modem link */
    e_link_t cd_link;           /* core dump link */
    e_cd_status_t cd_generated; /* Indicates the core dump status before the
                                 * last mdm_reset */
    char mdm_ipc_path[PATH_MAX];
    char sanity_check_dlc[PATH_MAX];
    char shtdwn_dlc[PATH_MAX];
    mux_t mux;
    pm_handle_t *pm;
    ctrl_handle_t *ctrl;
    e_mdm_wakeup_cfg_t wakeup_cfg;
    /* @TODO: remove ME. W/A for DSDA */
    bool delay_open;
    bool ssic_hack;
} modem_info_t;

e_mmgr_errors_t modem_info_init(mdm_info_t *mdm_info, mmgr_com_t *com,
                                tlvs_info_t *tlvs, mmgr_mdm_link_t *mdm_link,
                                channels_mmgr_t *ch, mmgr_mcd_t *mcd,
                                modem_info_t *info, bool ssic_hack);

/* Callback used to parse an AT response string */
typedef int (*PFN_PARSE_RESP) (void *ctx, const char *pszResp, size_t *len);

e_cd_status_t get_core_dump_status(e_core_dump_state_t state);
const char *get_core_dump_status_string(e_cd_status_t status);
bool generate_timestamp(char *timestamp, int size);
e_cd_status_t read_cd_logs(int fd_tty, int fd_fs, PFN_PARSE_RESP parseFct);

void modem_info_dispose(modem_info_t *info);
e_mmgr_errors_t switch_to_mux(int *fd_tty, modem_info_t *info);

#endif                          /* _MMGR_MODEM_INFO_HEADER__ */
