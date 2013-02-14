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

#include "errors.h"
#include "modem_info.h"

e_mmgr_errors_t modem_warm_reset(modem_info_t *info);
e_mmgr_errors_t modem_cold_reset(modem_info_t *info);
e_mmgr_errors_t modem_down(modem_info_t *info);
e_mmgr_errors_t modem_up(modem_info_t *info);
e_mmgr_errors_t get_modem_state(int fd_mcd, e_modem_events_type_t *state);

#endif                          /* __MMGR_MODEM_SPECIFIC_HEADER__ */
