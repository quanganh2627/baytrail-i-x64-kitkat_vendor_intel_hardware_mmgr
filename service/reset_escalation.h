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
#include "modem_specific.h"

#define RECOV_LEVEL \
    X(MODEM_WARM_RESET),\
    X(MODEM_COLD_RESET),\
    X(PLATFORM_REBOOT),\
    X(MODEM_OUT_OF_SERVICE),\
    X(NUMBER_OF)

/* escalation process states */
typedef enum e_escalation_level {
#undef X
#define X(a) E_EL_##a
    RECOV_LEVEL
} e_escalation_level_t;

/* enum used by pre_operation escalation function */
typedef enum e_reset_operation_state {
    E_OPERATION_CONTINUE,
    E_OPERATION_WAIT,
    E_OPERATION_SKIP,
} e_reset_operation_state_t;

typedef enum e_force_reset_operation {
    E_FORCE_RESET_ENABLED,
    E_FORCE_RESET_ON_GOING,
    E_FORCE_RESET_DISABLED
} e_force_reset_operation_t;

struct reset_management;
typedef struct reset_operation {
    int retry_allowed;
    e_escalation_level_t next_level;
} reset_operation_t;

typedef struct reset_operation_level {
    e_escalation_level_t id;
    int counter;
} reset_operation_level_t;

typedef struct reset_management {
    reset_operation_level_t level;
    reset_operation_level_t level_bckup;
    e_reset_operation_state_t state;
    reset_operation_t process[E_EL_NUMBER_OF];
    struct timeval last_reset_time;
    const mmgr_configuration_t *config;
    bool wait_operation;        /* used by pre_cold_reset */
    e_force_reset_operation_t modem_restart;
} reset_management_t;

e_mmgr_errors_t recov_init(const mmgr_configuration_t *params,
                           reset_management_t *p_reset);
e_mmgr_errors_t recov_do_reset(reset_management_t *p_reset);
e_mmgr_errors_t recov_reinit(reset_management_t *p_reset);
e_mmgr_errors_t recov_start(reset_management_t *reset);
e_mmgr_errors_t recov_get_level(reset_management_t *reset,
                                e_escalation_level_t *level);
e_mmgr_errors_t recov_next(reset_management_t *reset);
e_mmgr_errors_t recov_done(reset_management_t *reset);
int recov_get_reboot(void);
void recov_set_reboot(int reboot);

e_mmgr_errors_t platform_reboot(modem_info_t *unused);
e_mmgr_errors_t out_of_service(modem_info_t *info);

#endif                          /* __MMGR_RESET_ESCALATION_HEADER__ */
