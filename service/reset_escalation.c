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
#include "tty.h"

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

e_mmgr_errors_t recov_start(reset_management_t *reset)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    struct timeval current_time;
    int reboot_counter = 0;

    CHECK_PARAM(reset, ret, out);

    gettimeofday(&current_time, NULL);

    /* special cases */
    if (reset->modem_restart == E_FORCE_RESET_ENABLED) {
        LOG_DEBUG("force COLD RESET");
        reset->level_bckup = reset->level;
        reset->modem_restart = E_FORCE_RESET_ON_GOING;
        reset->level.id = E_EL_MODEM_COLD_RESET;
        reset->level.counter = 0;
        goto out;
    }

    /* If there is more than xx seconds since the last reset, consider that we
     * were in a stable state before the issue. So, reset the escalation
     * recovery variable to default. */
    if ((reset->level.id != E_EL_MODEM_OUT_OF_SERVICE) &&
        (reset->modem_restart != E_FORCE_RESET_ON_GOING)) {

        if (current_time.tv_sec - reset->last_reset_time.tv_sec
            > reset->config->min_time_issue) {
            /* The modem behavior was correct during at least min_time_issue,
             * so we can reset the reboot counter */
            LOG_DEBUG("Last reset occurred at least %ds ago",
                      reset->config->min_time_issue);
            recov_reinit(reset);
            property_set_int(PLATFORM_REBOOT_KEY, reboot_counter);
        }
    }

out:
    reset->last_reset_time = current_time;
    return ret;
}

e_mmgr_errors_t recov_get_level(reset_management_t *reset,
                                e_escalation_level_t *level)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(reset, ret, out);
    CHECK_PARAM(level, ret, out);

    *level = reset->level.id;
out:
    return ret;
}

e_mmgr_errors_t recov_get_max_op(reset_management_t *reset, int *max)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(reset, ret, out);
    CHECK_PARAM(max, ret, out);

    *max = reset->process[reset->level.id].retry_allowed;
out:
    return ret;
}

int recov_get_reboot(void)
{
    int reboot_counter;
    property_get_int(PLATFORM_REBOOT_KEY, &reboot_counter);
    return reboot_counter;
}

void recov_set_reboot(int reboot)
{
    property_set_int(PLATFORM_REBOOT_KEY, reboot);
}

/**
 * Reset escalation counter: set to initial reset level
 *
 * @param [in,out] reset reset_management_t pointer
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if bad parameter
 */
e_mmgr_errors_t recov_reinit(reset_management_t *reset)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(reset, ret, out);

    reset->level.counter = 0;
    reset->level.id = E_EL_MODEM_WARM_RESET;
    if (reset->process[reset->level.id].retry_allowed <= 0)
        recov_next(reset);

out:
    return ret;
}

/**
 * Set to next reset level
 *
 * @param [in] reset reset_management_t pointer
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if bad parameter
 **/
e_mmgr_errors_t recov_next(reset_management_t *reset)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

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
 * Compute and process the modem escalation pre recovery
 *
 * @param [in,out] reset reset_management_t pointer
 *
 * @return E_ERR_BAD_PARAMETER if bad parameter
 * @return E_ERR_FAILED operation has failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t recov_done(reset_management_t *reset)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    reset_operation_t *process = NULL;
    const char *level_str[] = {
#undef X
#define X(a) #a
        RECOV_LEVEL
    };

    CHECK_PARAM(reset, ret, out);

    if (reset->level.id >= E_EL_NUMBER_OF)
        goto out;

    if (reset->modem_restart == E_FORCE_RESET_ON_GOING) {
        reset->modem_restart = E_FORCE_RESET_DISABLED;
        reset->level = reset->level_bckup;
        goto done;
    }

    process = &reset->process[reset->level.id];
    reset->level.counter++;

    /* go to next level if performed process is upper than allowed */
    if (((process->retry_allowed >= 0) &&
         (reset->level.counter >= process->retry_allowed)) &&
        (reset->modem_restart != E_FORCE_RESET_ON_GOING)) {
        recov_next(reset);
    }

done:
    LOG_DEBUG("level: %s, counter: %d", level_str[reset->level.id],
              reset->level.counter);
out:
    return ret;
}

/**
 * initialize the escalation recovery
 *
 * @param [in] config mmgr configuration
 * @param [out] reset reset management
 *
 * @return E_ERR_BAD_PARAMETER if one parameter is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t recov_init(const mmgr_configuration_t *config,
                           reset_management_t *reset)
{
    int i = 0;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    reset_operation_t *p_process = NULL;

    CHECK_PARAM(config, ret, out);
    CHECK_PARAM(reset, ret, out);

    reset->config = config;

    /* initialize structure */
    for (i = 0; i < E_EL_NUMBER_OF; i++) {
        reset->process[i].retry_allowed = 0;
        reset->process[i].next_level = E_EL_MODEM_OUT_OF_SERVICE;
    }

    /* always configure routines to handle FORCE user requests */
    reset->modem_restart = E_FORCE_RESET_DISABLED;
    if (config->modem_reset_enable) {
        /* initialize some data */
        reset->level.id = E_EL_MODEM_WARM_RESET;
        reset->level.counter = 0;
        reset->wait_operation = true;
        reset->state = E_OPERATION_CONTINUE;
        gettimeofday(&reset->last_reset_time, NULL);

        /* structure initialization: */
        p_process = &reset->process[E_EL_MODEM_WARM_RESET];
        if (!config->is_flashless)
            p_process->retry_allowed = config->nb_warm_reset;

        if (config->nb_cold_reset > 0) {
            p_process->next_level = E_EL_MODEM_COLD_RESET;
            p_process = &reset->process[E_EL_MODEM_COLD_RESET];
            p_process->retry_allowed = config->nb_cold_reset;
        }

        if (config->nb_platform_reboot > 0) {
            p_process->next_level = E_EL_PLATFORM_REBOOT;
            p_process = &reset->process[E_EL_PLATFORM_REBOOT];
            p_process->retry_allowed = config->nb_platform_reboot;
        }
        p_process->next_level = E_EL_MODEM_OUT_OF_SERVICE;
    }

    p_process = &reset->process[E_EL_MODEM_OUT_OF_SERVICE];
    p_process->retry_allowed = -1;
    p_process->next_level = E_EL_MODEM_OUT_OF_SERVICE;

out:
    return ret;
}
