/* Modem Manager - timer manager header file
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

#ifndef __MMGR_TIMER_HEADER__
#define __MMGR_TIMER_HEADER__

#include "events_manager.h"

e_mmgr_errors_t timer_init(mmgr_timer_t *timer, mmgr_configuration_t *config);
e_mmgr_errors_t start_timer(mmgr_timer_t *timer, e_timer_type_t type);
e_mmgr_errors_t stop_timer(mmgr_timer_t *timer, e_timer_type_t type);
e_mmgr_errors_t timer_event(mmgr_data_t *mmgr);

#endif                          /* __MMGR_TIMER_HEADER__ */
