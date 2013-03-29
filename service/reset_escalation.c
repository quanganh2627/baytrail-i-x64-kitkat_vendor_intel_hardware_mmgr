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
 * Perform a pre modem warm reset
 *
 * @param [in,out] p_reset reset management structure
 *
 * @return E_OPERATION_BAD_PARAMETER if p_reset is NULL
 * @return E_OPERATION_CONTINUE if sucessful
 * @return E_OPERATION_SKIP otherwise
 */
static e_reset_operation_state_t pre_modem_warm_reset(reset_management_t
                                                      *p_reset)
{
    e_reset_operation_state_t ret = E_OPERATION_CONTINUE;

    CHECK_PARAM(p_reset, ret, out);

    LOG_DEBUG("events 0x%.2X", p_reset->modem_info->ev);
    if (!(p_reset->modem_info->ev & E_EV_CONF_FAILED) &&
        ((p_reset->modem_info->ev & E_EV_MODEM_SELF_RESET) ||
         (p_reset->modem_info->mcdr.state == E_CD_SUCCEED_WITHOUT_PANIC_ID))) {
        LOG_DEBUG("WARM RESET: skipped");
        ret = E_OPERATION_SKIP;
    }
out:
    return ret;
}

/**
 * Perform a pre modem cold reset
 *
 * @param [in,out] p_reset reset management structure
 *
 * @return E_OPERATION_CONTINUE;
 * @return E_OPERATION_WAIT
 */
static e_reset_operation_state_t pre_modem_cold_reset(reset_management_t
                                                      *p_reset)
{
    int ret;

    if (p_reset->wait_operation) {
        LOG_DEBUG("waiting for client acknowledge");
        p_reset->wait_operation = false;
        ret = E_OPERATION_WAIT;
    } else {
        p_reset->wait_operation = true;
        ret = E_OPERATION_CONTINUE;
    }
    return ret;
}

/**
 * Perform a pre platform reboot
 *
 * @param [in,out] p_reset reset management structure
 *
 * @return E_OPERATION_BAD_PARAMETER if p_reset is NULL
 * @return E_OPERATION_CONTINUE if sucessful
 * @return E_OPERATION_NEXT if reboot is not allowed
 */
static e_reset_operation_state_t pre_platform_reboot(reset_management_t
                                                     *p_reset)
{
    int reboot_counter;
    int err;
    e_reset_operation_state_t ret = E_OPERATION_CONTINUE;

    CHECK_PARAM(p_reset, ret, out);

    err = get_property(PLATFORM_REBOOT_KEY, &reboot_counter);
    if (err == E_OPERATION_BAD_PARAMETER) {
        ret = E_OPERATION_BAD_PARAMETER;
        goto out;
    }
    if (reboot_counter >= p_reset->process[E_EL_PLATFORM_REBOOT].retry_allowed) {
        /* go to next level */
        LOG_INFO("%s STATE: Reboot cancelled. Max value reached", MODULE_NAME);
        ret = E_OPERATION_NEXT;
    } else {
        reboot_counter++;
        LOG_DEBUG("set platform_reboot_counter = %d", reboot_counter);
        err = set_property(PLATFORM_REBOOT_KEY, reboot_counter);
        if (err == E_OPERATION_BAD_PARAMETER) {
            ret = E_OPERATION_BAD_PARAMETER;
            goto out;
        }
    }
out:
    return ret;
}

/**
 * Perform a pre out of service operation
 *
 * @param [in] none NULL
 *
 * @return E_OPERATION_CONTINUE
 */
static e_reset_operation_state_t pre_out_of_service(reset_management_t *none)
{
    (void)none;
    LOG_INFO("%s STATE: MODEM OUT OF SERVICE", MODULE_NAME);
    return E_OPERATION_CONTINUE;
}

/**
 * Perform a platform reboot
 *
 * @param [in] unused
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
static e_mmgr_errors_t platform_reboot(modem_info_t *unused)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    (void)unused;
    LOG_INFO("%s STATE: PLATFORM REBOOT\n"
             "[SHTDWN] Reboot requested by %s", MODULE_NAME, MODULE_NAME);

    /* force commit buffer cache to disk to prevent data lost
       Specially the COLD_RESET file */
    sync();
    broadcast_action(E_ACTION_INTENT_REBOOT);
    return ret;
}

/**
 * Perform a out of service operation
 *
 * @param [in] unused set NULL
 *
 * @return E_ERR_SUCCESS ALWAYS
 */
static e_mmgr_errors_t out_of_service(modem_info_t *unused)
{
    (void)unused;
    /* Nothing to do */
    return E_ERR_SUCCESS;
}

/**
 * Set to next reset level
 *
 * @param [in,out] p_reset reset_management_t pointer
 * @param [in,out] p_process current process
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if bad parameter
 */
static e_mmgr_errors_t set_next_level(reset_management_t *p_reset,
                                      reset_operation_t **p_process)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(p_reset, ret, out);
    CHECK_PARAM(p_process, ret, out);
    CHECK_PARAM(*p_process, ret, out);

    do {
        LOG_DEBUG("id=%d next=%d", p_reset->level.id, (*p_process)->next_level);
        p_reset->level.id = (*p_process)->next_level;
        *p_process = &p_reset->process[p_reset->level.id];
    } while (((*p_process)->retry_allowed <= 0) &&
             (p_reset->level.id != E_EL_MODEM_OUT_OF_SERVICE));
    p_reset->level.counter = 1;
    LOG_DEBUG("new level: %d", p_reset->level.id);
out:
    return ret;
}

/**
 * Reset escalation counter: set to initial reset level
 *
 * @param [in,out] p_reset reset_management_t pointer
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if bad parameter
 */
e_mmgr_errors_t reset_escalation_counter(reset_management_t *p_reset)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(p_reset, ret, out);

    p_reset->level.counter = 0;
    p_reset->level.id = E_EL_MODEM_WARM_RESET;
    LOG_DEBUG("done");

out:
    return ret;
}

/**
 * Compute and process the modem escalation pre recovery
 *
 * @param [in,out] p_reset reset_management_t pointer
 *
 * @return E_ERR_BAD_PARAMETER if bad parameter
 * @return E_ERR_FAILED operation has failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t pre_modem_escalation_recovery(reset_management_t *p_reset)
{
    int reboot_counter;
    e_mmgr_errors_t ret = E_ERR_FAILED;
    reset_operation_t *p_process = NULL;
    struct timeval current_time;

    CHECK_PARAM(p_reset, ret, out);

    if (p_reset->level.id >= E_EL_NUMBER_OF)
        goto out;

    /* special cases */
    if (p_reset->modem_restart == E_FORCE_RESET_ENABLED) {
        LOG_DEBUG("force COLD RESET");
        p_reset->level_bckup = p_reset->level;
        p_reset->modem_restart = E_FORCE_RESET_ON_GOING;
        p_reset->level.id = E_EL_MODEM_COLD_RESET;
        p_reset->level.counter = 0;
    }

    p_process = &p_reset->process[p_reset->level.id];

    gettimeofday(&current_time, NULL);

    /* If there is more than xx seconds since the last reset, consider that
       we were in a stable state before the issue. So, reset the escalation
       recovery variable to default. */
    if ((p_reset->level.id != E_EL_MODEM_OUT_OF_SERVICE) &&
        (p_reset->modem_restart != E_FORCE_RESET_ON_GOING)) {

        if (current_time.tv_sec - p_reset->last_reset_time.tv_sec
            > p_reset->config->min_time_issue) {
            /* The modem behavior was correct during at least min_time_issue,
               so we can reset the reboot counter */
            LOG_DEBUG("Last reset occurred at least %ds ago",
                      p_reset->config->min_time_issue);
            reset_escalation_counter(p_reset);
            p_process = &p_reset->process[p_reset->level.id];
            reboot_counter = 0;
            ret = set_property(PLATFORM_REBOOT_KEY, reboot_counter);
            if (ret == E_ERR_BAD_PARAMETER)
                goto out;
        }
    }

    p_reset->last_reset_time = current_time;
    p_reset->level.counter++;

    /* go to next level if performed process is upper than allowed */
    if (((p_process->retry_allowed >= 0) &&
         (p_reset->level.counter > p_process->retry_allowed)) &&
        (p_reset->modem_restart != E_FORCE_RESET_ON_GOING)) {
        LOG_DEBUG("level: %d, counter: %d. max reached", p_reset->level.id,
                  p_reset->level.counter);
        set_next_level(p_reset, &p_process);
    }

    LOG_DEBUG("level: %d, counter: %d", p_reset->level.id,
              p_reset->level.counter);

    do {
        /* perform reset pre-operation */
        if (p_process->pre_operation != NULL) {
            p_reset->state = p_process->pre_operation(p_reset);
            ret = E_ERR_SUCCESS;
        } else {
            LOG_ERROR("pre_operation is NULL");
            p_reset->state = E_OPERATION_BAD_PARAMETER;
        }

        switch (p_reset->state) {
        case E_OPERATION_CONTINUE:
            /* perform reset operation */
            break;
        case E_OPERATION_WAIT:
            p_reset->level.counter--;
            break;
        case E_OPERATION_SKIP:
            break;
        case E_OPERATION_NEXT:
            LOG_DEBUG("next operation");
            set_next_level(p_reset, &p_process);
            break;
        case E_OPERATION_BAD_PARAMETER:
            LOG_ERROR("*** NON RECOVERABLE ERROR ***");
            ret = E_ERR_BAD_PARAMETER;
            goto out;
        }
    } while (p_reset->state == E_OPERATION_NEXT);

out:
    return ret;
}

/**
 * Compute and process the modem escalation recovery
 *
 * @param [in,out] p_reset reset_management_t pointer
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED if failed
 * @return E_ERR_BAD_PARAMETER if bad parameter
 */
e_mmgr_errors_t modem_escalation_recovery(reset_management_t *p_reset)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    reset_operation_t *p_process = NULL;

    CHECK_PARAM(p_reset, ret, out);
    if (p_reset->level.id >= E_EL_NUMBER_OF)
        goto out;

    p_process = &p_reset->process[p_reset->level.id];

    if (p_process->operation != NULL) {
        ret = p_process->operation(p_reset->modem_info);
    } else {
        LOG_ERROR("operation is NULL");
        ret = E_ERR_BAD_PARAMETER;
    }

    if (p_reset->modem_restart == E_FORCE_RESET_ON_GOING) {
        p_reset->modem_restart = E_FORCE_RESET_DISABLED;
        p_reset->level = p_reset->level_bckup;
    }
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * initialize the escalation recovery
 *
 * @param [in] config mmgr configuration
 * @param [out] p_reset reset management
 * @param [in] info modem info
 *
 * @return E_ERR_BAD_PARAMETER if one parameter is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t escalation_recovery_init(const mmgr_configuration_t *config,
                                         reset_management_t *p_reset,
                                         modem_info_t *info)
{
    int i = 0;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    reset_operation_t *p_process = NULL;

    CHECK_PARAM(config, ret, out);
    CHECK_PARAM(p_reset, ret, out);
    CHECK_PARAM(info, ret, out);

    p_reset->modem_info = info;
    p_reset->config = config;

    /* initialize structure */
    for (i = 0; i < E_EL_NUMBER_OF; i++) {
        p_reset->process[i].retry_allowed = 0;
        p_reset->process[i].operation = NULL;
        p_reset->process[i].pre_operation = NULL;
        p_reset->process[i].next_level = E_EL_MODEM_OUT_OF_SERVICE;
    }

    /* always configure routines to handle FORCE user requests */
    p_reset->process[E_EL_MODEM_WARM_RESET].pre_operation =
        pre_modem_warm_reset;
    p_reset->process[E_EL_MODEM_WARM_RESET].operation = modem_warm_reset;
    p_reset->process[E_EL_MODEM_COLD_RESET].pre_operation =
        pre_modem_cold_reset;
    p_reset->process[E_EL_MODEM_COLD_RESET].operation = modem_cold_reset;
    p_reset->process[E_EL_PLATFORM_REBOOT].pre_operation = pre_platform_reboot;
    p_reset->process[E_EL_PLATFORM_REBOOT].operation = platform_reboot;
    p_reset->process[E_EL_MODEM_OUT_OF_SERVICE].pre_operation =
        pre_out_of_service;
    p_reset->process[E_EL_MODEM_OUT_OF_SERVICE].operation = out_of_service;

    if (config->modem_reset_enable) {
        /* initialize some data */
        p_reset->level.id = E_EL_MODEM_WARM_RESET;
        p_reset->level.counter = 0;
        p_reset->wait_operation = true;
        p_reset->modem_restart = E_FORCE_RESET_DISABLED;
        p_reset->state = E_OPERATION_CONTINUE;
        gettimeofday(&p_reset->last_reset_time, NULL);

        /* structure initialization: */
        p_process = &p_reset->process[E_EL_MODEM_WARM_RESET];
        if (!config->is_flashless)
            p_process->retry_allowed = config->nb_warm_reset;

        if (config->nb_cold_reset > 0) {
            p_process->next_level = E_EL_MODEM_COLD_RESET;
            p_process = &p_reset->process[E_EL_MODEM_COLD_RESET];
            p_process->retry_allowed = config->nb_cold_reset;
        }

        if (config->nb_platform_reboot > 0) {
            p_process->next_level = E_EL_PLATFORM_REBOOT;
            p_process = &p_reset->process[E_EL_PLATFORM_REBOOT];
            p_process->retry_allowed = config->nb_platform_reboot;
        }
        p_process->next_level = E_EL_MODEM_OUT_OF_SERVICE;
    }

    p_process = &p_reset->process[E_EL_MODEM_OUT_OF_SERVICE];
    p_process->retry_allowed = -1;
    p_process->next_level = E_EL_MODEM_OUT_OF_SERVICE;

out:
    return ret;
}
