/* Modem Manager - modem reset escalation source file
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

#define MMGR_FW_OPERATIONS
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/mdm_ctrl.h>
#include "at.h"
#include "errors.h"
#include "file.h"
#include "java_intent.h"
#include "logs.h"
#include "property.h"
#include "reset_escalation.h"
#include "modem_specific.h"
#include "tty.h"

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
    e_reset_operation_state_t state;
    reset_operation_t process[E_EL_NUMBER_OF];
    struct timeval last_reset_time;
    const mmgr_configuration_t *config;
    e_force_operation_t op;
} reset_management_t;

/**
 * Perform a platform reboot
 *
 * @param [in] unused
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t platform_reboot(modem_info_t *unused)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    (void)unused;
    LOG_INFO("PLATFORM REBOOT. [SHTDWN] Reboot requested by %s", MODULE_NAME);

    /* force commit buffer cache to disk to prevent data lost */
    sync();
    broadcast_action(E_ACTION_INTENT_REBOOT);
    return ret;
}

/**
 * Perform a out of service operation
 *
 * @param [in] info modem info
 *
 * @return E_ERR_SUCCESS ALWAYS
 */
e_mmgr_errors_t out_of_service(modem_info_t *info)
{
    mdm_down(info);
    return E_ERR_SUCCESS;
}

/**
 * This function launches the escalation recovery procedure
 *
 * @param [in] h reset module handler
 *
 * @ return E_ERR_BAD_PARAMETER if h is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t recov_start(reset_handle_t * h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    struct timeval current_time;
    int reboot_counter = 0;
    reset_management_t *reset = (reset_management_t *)h;

    CHECK_PARAM(reset, ret, out);

    if (reset->op == E_FORCE_OOS) {
        reset->level.id = E_EL_MODEM_OUT_OF_SERVICE;
        reset->op = E_FORCE_NONE;
    } else {
        gettimeofday(&current_time, NULL);

        /* If there is more than xx seconds since the last reset, consider that
         * we were in a stable state before the issue. So, reset the escalation
         * recovery variable to default. */
        if (reset->level.id != E_EL_MODEM_OUT_OF_SERVICE) {

            if (current_time.tv_sec - reset->last_reset_time.tv_sec
                > reset->config->min_time_issue) {
                /* The modem behavior was correct during at least
                 * min_time_issue, so we can reset the reboot counter */
                LOG_DEBUG("Last reset occurred at least %ds ago",
                          reset->config->min_time_issue);
                recov_reinit(h);
                property_set_int(PLATFORM_REBOOT_KEY, reboot_counter);
            }
        }
    }

out:
    reset->last_reset_time = current_time;
    return ret;
}

/**
 * This function returns the current level
 *
 * @param [in] h reset module handler
 *
 * @return E_EL_UNKNOWN if h is NULL
 * @return a valid e_escalation_level_t state otherwise
 */
e_escalation_level_t recov_get_level(reset_handle_t * h)
{
    e_escalation_level_t level = E_EL_UNKNOWN;
    reset_management_t *reset = (reset_management_t *)h;

    if (reset)
        level = reset->level.id;

    return level;
}

/**
 * This function returns the current platform reboot performed
 *
 * @return current platform reboot performed
 */
int recov_get_reboot(void)
{
    int reboot_counter;
    property_get_int(PLATFORM_REBOOT_KEY, &reboot_counter);
    return reboot_counter;
}

/**
 * This function sets the current platform reboot performed
 *
 * @param [in] reboot current performed reboot
 */
void recov_set_reboot(int reboot)
{
    property_set_int(PLATFORM_REBOOT_KEY, reboot);
}

/**
 * Reset escalation counter: set to initial reset level
 *
 * @param [in] h reset module handler
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if bad parameter
 */
e_mmgr_errors_t recov_reinit(reset_handle_t * h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    reset_management_t *reset = (reset_management_t *)h;

    CHECK_PARAM(reset, ret, out);

    reset->level.counter = 0;
    reset->level.id = E_EL_MODEM_COLD_RESET;
    if (reset->process[reset->level.id].retry_allowed <= 0)
        recov_next(h);

out:
    return ret;
}

/**
 * Set to next reset level
 *
 * @param [in] h reset module handler
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if bad parameter
 **/
e_mmgr_errors_t recov_next(reset_handle_t * h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    reset_management_t *reset = (reset_management_t *)h;

    CHECK_PARAM(reset, ret, out);

    do {
        reset->level.id = reset->process[reset->level.id].next_level;
    } while ((reset->process[reset->level.id].retry_allowed <= 0) &&
             (reset->level.id != E_EL_MODEM_OUT_OF_SERVICE));
    reset->level.counter = 0;
    LOG_DEBUG("new level: %d", reset->level.id);
out:
    return ret;
}

/**
 * Finalize the recovery procedure
 *
 * @param [in] h reset module handler
 *
 * @return E_ERR_BAD_PARAMETER if bad parameter
 * @return E_ERR_FAILED operation has failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t recov_done(reset_handle_t * h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    reset_operation_t *process = NULL;
    reset_management_t *reset = (reset_management_t *)h;
    static const char const *level_str[] = {
#undef X
#define X(a) #a
        RECOV_LEVEL
    };

    CHECK_PARAM(reset, ret, out);

    if (reset->level.id >= E_EL_NUMBER_OF)
        goto out;

    if (reset->op != E_FORCE_NO_COUNT) {
        reset->level.counter++;
        reset->op = E_FORCE_NONE;
    }

    process = &reset->process[reset->level.id];

    /* go to next level if we reached the maximum attempt */
    if ((process->retry_allowed >= 0) &&
        (reset->level.counter >= process->retry_allowed))
        recov_next(h);

    LOG_DEBUG("level: %s, counter: %d", level_str[reset->level.id],
              reset->level.counter);
out:
    return ret;
}

/**
 * initialize the escalation recovery
 *
 * @param [in] config mmgr configuration
 *
 * @return a valid pointer to reset module
 * @return NULL otherwise
 */
reset_handle_t *recov_init(const mmgr_configuration_t *config)
{
    int i = 0;
    reset_operation_t *p_process = NULL;
    reset_management_t *reset = calloc(1, sizeof(reset_management_t));
    if (!reset) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }

    if (!config) {
        LOG_ERROR("config is NULL");
        recov_dispose((reset_handle_t *) reset);
        reset = NULL;
        goto out;
    }

    reset->config = config;

    /* initialize structure */
    for (i = 0; i < E_EL_NUMBER_OF; i++) {
        reset->process[i].retry_allowed = 0;
        reset->process[i].next_level = E_EL_MODEM_OUT_OF_SERVICE;
    }

    /* always configure routines to handle FORCE user requests */
    reset->op = E_FORCE_NONE;
    if (config->modem_reset_enable) {
        /* initialize some data */
        reset->level.id = E_EL_MODEM_COLD_RESET;
        reset->level.counter = 0;
        reset->state = E_OPERATION_CONTINUE;
        gettimeofday(&reset->last_reset_time, NULL);

        /* structure initialization: */
        p_process = &reset->process[E_EL_MODEM_COLD_RESET];
        if (config->nb_cold_reset > 0)
            p_process->retry_allowed = config->nb_cold_reset;

        if (config->nb_platform_reboot > 0) {
            p_process->next_level = E_EL_PLATFORM_REBOOT;
            p_process = &reset->process[E_EL_PLATFORM_REBOOT];
            p_process->retry_allowed = config->nb_platform_reboot;
        }
    }

    p_process = &reset->process[E_EL_MODEM_OUT_OF_SERVICE];
    p_process->retry_allowed = -1;

out:
    return (reset_handle_t *) reset;
}

/**
 * Free the modem recovery module
 *
 * @param [in] h reset module handler
 *
 * @return E_ERR_BAD_PARAMETER if h is NULL
 * @return E_ERR_SUCCESS otherwise
 */
e_mmgr_errors_t recov_dispose(reset_handle_t * h)
{
    reset_management_t *reset = (reset_management_t *)h;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(reset, ret, out);

    free(reset);

out:
    return ret;
}

/**
 * Returns the last time a reset operation happened
 *
 * @param [in] h reset module handler
 *
 * @return a 0 timeval if h is NULL
 * @return a correct timeval otherwise
 */
struct timeval recov_get_last_reset(reset_handle_t * h)
{
    reset_management_t *reset = (reset_management_t *)h;
    struct timeval ts;

    memset(&ts, 0, sizeof(ts));
    if (reset)
        ts = reset->last_reset_time;

    return ts;
}

/**
 * Set current escalation recovery state
 *
 * @param [in] h reset module handler
 *
 * @return E_ERR_BAD_PARAMETER if h is NULL
 * @return E_ERR_SUCCESS otherwise
 */
e_mmgr_errors_t recov_set_state(reset_handle_t * h,
                                e_reset_operation_state_t state)
{
    reset_management_t *reset = (reset_management_t *)h;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(reset, ret, out);

    reset->state = state;

out:
    return ret;
}

/**
 * Get current escalation recovery state
 *
 * @param [in] h reset module handler
 *
 * @return E_OPERATION_UNKNOWN if h is NULL
 * @return a valid e_reset_operation_state_t otherwise
 */
e_reset_operation_state_t recov_get_state(reset_handle_t * h)
{
    reset_management_t *reset = (reset_management_t *)h;
    e_reset_operation_state_t state = E_OPERATION_UNKNOWN;

    if (reset)
        state = reset->state;

    return state;
}

/**
 * Returns the maximum operation allowed for current state
 *
 * @param [in] h reset module handler
 *
 * @return -1 if h is NULL
 * @return the maximum operation allowed otherwise
 */
int recov_get_retry_allowed(reset_handle_t * h)
{
    reset_management_t *reset = (reset_management_t *)h;
    int retry = -1;

    if (reset)
        retry = reset->process[reset->level.id].retry_allowed;

    return retry;
}

/**
 * This function allows user to force the next reset operation
 *
 * @param [in] h reset module handler
 * @param [in] op forced operation type
 *
 * @return E_ERR_BAD_PARAMETER if h is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t recov_force(reset_handle_t * h, e_force_operation_t op)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    reset_management_t *reset = (reset_management_t *)h;

    CHECK_PARAM(reset, ret, out);
    reset->op = op;

out:
    return ret;
}
