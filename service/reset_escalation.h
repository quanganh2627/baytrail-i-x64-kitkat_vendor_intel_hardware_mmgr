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
#include "modem_specific.h"

/* persistent android property to count the platform reboot.
   NB: The key length can't exceed PROPERTY_KEY_MAX */
#define PLATFORM_REBOOT_KEY "persist.service.mmgr.reboot"

/* escalation process states */
typedef enum e_escalation_level {
    E_EL_MODEM_WARM_RESET = 0,
    E_EL_MODEM_COLD_RESET,
    E_EL_PLATFORM_REBOOT,
    E_EL_MODEM_OUT_OF_SERVICE,
    E_EL_MODEM_SHUTDOWN,
    E_EL_NUMBER_OF
} e_escalation_level_t;

/* enum used by pre_operation escalation function */
typedef enum e_reset_operation_state {
    E_OPERATION_CONTINUE,
    E_OPERATION_WAIT,
    E_OPERATION_SKIP,
    E_OPERATION_NEXT,
    E_OPERATION_BAD_PARAMETER = E_ERR_BAD_PARAMETER
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
    e_mmgr_errors_t (*operation) (modem_info_t *modem_info);
    e_reset_operation_state_t (*pre_operation) (struct reset_management *);
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
    modem_info_t *modem_info;
    bool wait_operation;        /* used by pre_cold_reset */
    e_force_reset_operation_t modem_restart;
    bool modem_shutdown;
} reset_management_t;

e_mmgr_errors_t escalation_recovery_init(const mmgr_configuration_t *params,
                                         reset_management_t *p_reset,
                                         modem_info_t *info);
e_mmgr_errors_t pre_modem_escalation_recovery(reset_management_t *p_reset);
e_mmgr_errors_t modem_escalation_recovery(reset_management_t *p_reset);
e_mmgr_errors_t reset_escalation_counter(reset_management_t *p_reset);

#endif                          /* __MMGR_RESET_ESCALATION_HEADER__ */
