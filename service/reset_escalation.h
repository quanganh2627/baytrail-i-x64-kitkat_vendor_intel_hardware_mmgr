/* Modem Manager - modem reset escalation header file
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

#ifndef __MMGR_RESET_ESCALATION_HEADER__
#define __MMGR_RESET_ESCALATION_HEADER__

#include <time.h>
#include "config.h"
#include "errors.h"
#include "modem_info.h"

#define RECOV_LEVEL \
    X(UNKNOWN), \
    X(MODEM_COLD_RESET), \
    X(PLATFORM_REBOOT), \
    X(MODEM_OUT_OF_SERVICE), \
    X(NUMBER_OF)

/* escalation process states */
typedef enum e_escalation_level {
#undef X
#define X(a) E_EL_ ## a
    RECOV_LEVEL
} e_escalation_level_t;

typedef void *reset_handle_t;

/* enum used by pre_operation escalation function */
typedef enum e_reset_operation_state {
    E_OPERATION_UNKNOWN,
    E_OPERATION_CONTINUE,
    E_OPERATION_WAIT,
    E_OPERATION_SKIP,
} e_reset_operation_state_t;

typedef enum e_force_operation {
    E_FORCE_NONE,
    /* Do not count this operation in the escalation recovery */
    E_FORCE_NO_COUNT,
    /* force modem out of service state */
    E_FORCE_OOS,
} e_force_operation_t;

reset_handle_t *recov_init(const mmgr_configuration_t *p);
e_mmgr_errors_t recov_dispose(reset_handle_t *h);

e_mmgr_errors_t recov_do_reset(reset_handle_t *h);
e_mmgr_errors_t recov_reinit(reset_handle_t *h);
e_mmgr_errors_t recov_start(reset_handle_t *h);
e_mmgr_errors_t recov_next(reset_handle_t *h);
e_mmgr_errors_t recov_done(reset_handle_t *h);

e_mmgr_errors_t recov_force(reset_handle_t *h, e_force_operation_t op);
e_mmgr_errors_t recov_set_state(reset_handle_t *h,
                                e_reset_operation_state_t st);

int recov_get_retry_allowed(reset_handle_t *h);
int recov_get_reboot(void);
void recov_set_reboot(int reboot);
e_escalation_level_t recov_get_level(reset_handle_t *h);
e_reset_operation_state_t recov_get_state(reset_handle_t *h);
struct timeval recov_get_last_reset(reset_handle_t *h);

e_mmgr_errors_t platform_reboot(modem_info_t *unused);
e_mmgr_errors_t out_of_service(modem_info_t *info);

#endif                          /* __MMGR_RESET_ESCALATION_HEADER__ */
