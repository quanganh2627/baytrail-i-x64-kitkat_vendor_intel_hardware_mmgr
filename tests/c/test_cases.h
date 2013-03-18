/* Modem Manager (MMGR) test application - tests definition header file
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

#ifndef __MMGR_TEST_CASES_FILE__
#define __MMGR_TEST_CASES_FILE__

#include "test_utils.h"

int modem_self_reset(test_data_t *events_data);
int reset_with_cd(test_data_t *events_data);
int modem_restart(test_data_t *events_data);
int modem_recovery(test_data_t *events_data);
int turn_off_modem(test_data_t *events_data);
int turn_on_modem(test_data_t *events_data);
int full_recovery(test_data_t *events_data);
int reset_counter(test_data_t *events_data);
int resource_check(test_data_t *events_data);
int test_libmmgrcli_api(test_data_t *events_data);
int resource_acquire(test_data_t *test);
int resource_release(test_data_t *test);

#endif                          /* __MMGR_TEST_CASES_FILE__ */
