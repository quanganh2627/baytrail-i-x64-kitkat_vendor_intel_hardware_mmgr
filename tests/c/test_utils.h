/* Modem Manager (MMGR) test application - utils header file
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

#ifndef __MMGR_TEST_UTILS_FILE__
#define __MMGR_TEST_UTILS_FILE__

#include <pthread.h>
#include <stdbool.h>
#include "config.h"
#include "logs.h"
#include "mmgr.h"
#include "mmgr_cli.h"

#define EXE_NAME MODULE_NAME"-test"
#define FILENAME_SIZE 256
#define TIMEOUT_MODEM_DOWN_AFTER_CMD 20
#define TIMEOUT_MODEM_UP_AFTER_RESET 600

typedef struct test_data {
    pthread_mutex_t new_state_read;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    pthread_mutex_t cond_mutex;
    int waited_state;
    int modem_state;
    mmgr_configuration_t config;
    mmgr_cli_handle_t *lib;
    bool test_succeed;
} test_data_t;

e_mmgr_errors_t modem_state_set(test_data_t *test_data, int state);
e_mmgr_errors_t compare_file_content(const char *path, const char *data,
                                     int len);
e_mmgr_errors_t wait_for_state(test_data_t *thread_data, int state,
                               bool wakelock, int timeout);
e_mmgr_errors_t is_core_dump_found(char *filename, const char *core_dump_dir);
e_mmgr_errors_t cleanup_modemcrash_dir(const char *path);
e_mmgr_errors_t configure_client_library(test_data_t *data);
e_mmgr_errors_t cleanup_client_library(test_data_t *data);
int event_without_ack(mmgr_cli_event_t *ev);

e_mmgr_errors_t reset_by_client_request(test_data_t *events_data,
                                        e_mmgr_requests_t request,
                                        e_mmgr_events_t notification,
                                        e_mmgr_events_t final_state);

e_mmgr_errors_t at_self_reset(test_data_t *events_data);
e_mmgr_errors_t at_core_dump(test_data_t *events_data);
e_mmgr_errors_t request_fake_ev(test_data_t *test, e_mmgr_requests_t id,
                                e_mmgr_events_t answer, bool check_result);

#endif                          /* __MMGR_TEST_UTILS_FILE__ */
