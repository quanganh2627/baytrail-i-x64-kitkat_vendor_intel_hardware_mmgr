/* Modem Manager - link power management source file
 **
 ** Copyright (C) Intel 2013
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

#ifndef __MMGR_IPC_PM_HEADER__
#define __MMGR_IPC_PM_HEADER__

#include "errors.h"
#include "modem_info.h"

e_mmgr_errors_t pm_on_mdm_flash(modem_info_t *info);
e_mmgr_errors_t pm_on_mdm_up(modem_info_t *info);

e_mmgr_errors_t pm_on_mdm_oos(modem_info_t *info);

e_mmgr_errors_t pm_on_mdm_cd(modem_info_t *info);
e_mmgr_errors_t pm_on_mdm_cd_complete(modem_info_t *info);

#endif                          /* __MMGR_IPC_PM_HEADER__ */
