/* Modem Manager - modem upgrade header file
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

#ifndef __MODEM_UPGRADE_HEADER__
#define __MODEM_UPGRADE_HEADER__

#include "errors.h"
#include "tcs_config.h"

#define MDM_UPGRADE_FLS_ERROR 0x1
#define MDM_UPGRADE_TLV_ERROR 0x2

typedef void *mdm_upgrade_hdle_t;

mdm_upgrade_hdle_t *mdm_upgrade_init(tlvs_info_t *tlvs, int inst_id, bool dsda,
                                     mdm_info_t *mdm_info, const char *fls_file,
                                     const char *run_folder);

void mdm_upgrade_dispose(mdm_upgrade_hdle_t *hdle);

e_mmgr_errors_t mdm_upgrade(mdm_upgrade_hdle_t *hdle);

char *mdm_upgrade_get_tlv_path(mdm_upgrade_hdle_t *hdle);

int mdm_upgrade_get_error(mdm_upgrade_hdle_t *hdle);

#endif /* __MODEM_UPGRADE_HEADER__ */
