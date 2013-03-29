/* Modem Manager - client events header file
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

#ifndef __MMGR_CLIENT_EVENTS_HEADER__
#define __MMGR_CLIENT_EVENTS_HEADER__

#include "events_manager.h"

#define FAKE_ERROR_REASON "fake reason. Only for test purpose"
#define FAKE_ERROR_ID 598

#define FAKE_CD_FILENAME "cd_fake_coredump.tgz"
#define FAKE_CD_ID 159374682

e_mmgr_errors_t client_events_init(mmgr_data_t *mmgr);
e_mmgr_errors_t new_client(mmgr_data_t *mmgr);
e_mmgr_errors_t known_client(mmgr_data_t *mmgr);

#endif                          /* __MMGR_CLIENT_EVENTS_HEADER__ */
