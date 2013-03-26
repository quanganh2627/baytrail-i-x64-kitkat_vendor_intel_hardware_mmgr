/* Modem Manager - modem specific header file
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

#ifndef __MMGR_MODEM_SPECIFIC_HEADER__
#define __MMGR_MODEM_SPECIFIC_HEADER__

#define MMGR_FW_OPERATIONS
#include "mmgr.h"
#include "errors.h"
#include "modem_info.h"
#include "security.h"
#include <linux/mdm_ctrl.h>

#define HSIC_PATH "/sys/devices/pci0000:00/0000:00:10.0/hsic_enable"

/* @TODO: remove is_flashless param */
e_mmgr_errors_t modem_specific_init(modem_info_t *info, bool is_flashless);
e_mmgr_errors_t modem_warm_reset(modem_info_t *info);
e_mmgr_errors_t modem_cold_reset(modem_info_t *info);
e_mmgr_errors_t modem_down(modem_info_t *info);
e_mmgr_errors_t modem_up(modem_info_t *info, bool is_flashless, bool is_hsic);
e_mmgr_errors_t get_modem_state(int fd_mcd, e_modem_events_type_t *state);
e_mmgr_errors_t start_hsic(modem_info_t *info);
e_mmgr_errors_t stop_hsic(modem_info_t *info);
e_mmgr_errors_t regen_fls(modem_info_t *info);
e_mmgr_errors_t flash_modem(modem_info_t *info, char *comport, bool ch_sw,
                            secur_t *secur, e_modem_fw_error_t *verdict);
e_mmgr_errors_t set_mcd_poll_states(modem_info_t *info);
e_mmgr_errors_t toggle_flashing_mode(modem_info_t *info, char *link_layer,
                                     bool flashing_mode);

void mup_log(const char *msg, size_t msg_len);

#endif                          /* __MMGR_MODEM_SPECIFIC_HEADER__ */
