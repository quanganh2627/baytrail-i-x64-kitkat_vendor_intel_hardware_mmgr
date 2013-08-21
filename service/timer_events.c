/* Modem Manager - timer manager source file
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

#include "events_manager.h"
#include "modem_specific.h"
#include "file.h"
#include "logs.h"
#include "timer_events.h"
#include "modem_info.h"

static const char *g_type_str[] = {
#undef X
#define X(a) #a
    TIMER
};

#define STEPS 10
#define TIMEOUT_EPOLL_INFINITE -1       /* wait indefinitely */

/**
 * start a timer for a specific event
 *
 * @param [in] timer
 * @param [in] type type of event
 *
 * @return E_ERR_BAD_PARAMETER if timer is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t start_timer(mmgr_timer_t *timer, e_timer_type_t type)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    struct timespec current;

    CHECK_PARAM(timer, ret, out);

    clock_gettime(CLOCK_MONOTONIC, &current);

    timer->type |= 0x01 << type;
    timer->start[type] = current;
    LOG_DEBUG("start timer for event: %s", g_type_str[type]);

    if ((timer->cur_timeout == TIMEOUT_EPOLL_INFINITE) ||
        (timer->cur_timeout > timer->timeout[type])) {
        timer->cur_timeout = timer->timeout[type];
        LOG_DEBUG("update timeout: %dms", timer->cur_timeout);
    }

out:
    return ret;
}

e_mmgr_errors_t stop_all_timers(mmgr_timer_t *timer)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(timer, ret, out);

    timer->type = 0x0;
    LOG_DEBUG("timer stopped");
    timer->cur_timeout = TIMEOUT_EPOLL_INFINITE;

out:
    return ret;
}

/**
 * stop a timer for a specific event
 *
 * @param [in] timer
 * @param [in] type type of event
 *
 * @return E_ERR_BAD_PARAMETER if timer is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t stop_timer(mmgr_timer_t *timer, e_timer_type_t type)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int min;

    CHECK_PARAM(timer, ret, out);

    LOG_DEBUG("stop timer for event: %s", g_type_str[type]);
    timer->type &= ~(0x01 << type);

    if (timer->type == 0x0) {
        LOG_DEBUG("timer stopped");
        timer->cur_timeout = TIMEOUT_EPOLL_INFINITE;
    } else {
        min = timer->cur_timeout;
        if ((timer->type & (0x01 << E_TIMER_COLD_RESET_ACK)) &&
            (min > timer->timeout[E_TIMER_COLD_RESET_ACK]))
            min = timer->timeout[E_TIMER_COLD_RESET_ACK];

        if ((timer->type & (0x01 << E_TIMER_MODEM_SHUTDOWN_ACK)) &&
            (min > timer->timeout[E_TIMER_MODEM_SHUTDOWN_ACK]))
            min = timer->timeout[E_TIMER_MODEM_SHUTDOWN_ACK];

        if ((timer->type & (0x01 << E_TIMER_WAIT_FOR_IPC_READY)) &&
            (min > timer->timeout[E_TIMER_WAIT_FOR_IPC_READY]))
            min = timer->timeout[E_TIMER_WAIT_FOR_IPC_READY];

        if ((timer->type & (0x01 << E_TIMER_WAIT_FOR_BUS_READY)) &&
            (min > timer->timeout[E_TIMER_WAIT_FOR_BUS_READY]))
            min = timer->timeout[E_TIMER_WAIT_FOR_BUS_READY];

        if ((timer->type & (0x01 << E_TIMER_WAIT_CORE_DUMP_READY)) &&
            (min > timer->timeout[E_TIMER_WAIT_CORE_DUMP_READY]))
            min = timer->timeout[E_TIMER_WAIT_CORE_DUMP_READY];

        timer->cur_timeout = min;
        LOG_DEBUG("update timeout: %dms", timer->cur_timeout);
    }

out:
    return ret;
}

/**
 * handle timeout cases
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t timer_event(mmgr_data_t *mmgr)
{
    struct timespec current;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mmgr_cli_core_dump_t cd = {.state = E_CD_SUCCEED};

    CHECK_PARAM(mmgr, ret, out);

    clock_gettime(CLOCK_MONOTONIC, &current);

    if ((mmgr->timer.type & (0x01 << E_TIMER_COLD_RESET_ACK)) &&
        ((current.tv_sec - mmgr->timer.start[E_TIMER_COLD_RESET_ACK].tv_sec)
         > mmgr->config.timeout_ack_cold)) {
        check_cold_ack(&mmgr->clients, true);
        stop_timer(&mmgr->timer, E_TIMER_COLD_RESET_ACK);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
    }

    if ((mmgr->timer.type & (0x01 << E_TIMER_MODEM_SHUTDOWN_ACK)) &&
        ((current.tv_sec - mmgr->timer.start[E_TIMER_MODEM_SHUTDOWN_ACK].tv_sec)
         > mmgr->config.timeout_ack_shtdwn)) {
        check_shutdown_ack(&mmgr->clients, true);
        mmgr->events.cli_req = E_CLI_REQ_OFF;
        stop_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
    }

    if ((mmgr->timer.type & (0x01 << E_TIMER_WAIT_FOR_IPC_READY)) &&
        ((current.tv_sec - mmgr->timer.start[E_TIMER_WAIT_FOR_IPC_READY].tv_sec)
         > mmgr->config.modem_reset_delay)) {
        LOG_DEBUG("IPC READY not received. force modem reset");
        restore_nvm(&mmgr->info);
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
        mmgr_cli_fw_update_result_t result = {.id = E_MODEM_FW_READY_TIMEOUT };
        inform_all_clients(&mmgr->clients, E_MMGR_RESPONSE_MODEM_FW_RESULT,
                           &result);
    }

    if ((mmgr->timer.type & (0x01 << E_TIMER_WAIT_FOR_BUS_READY)) &&
        ((current.tv_sec - mmgr->timer.start[E_TIMER_WAIT_FOR_BUS_READY].tv_sec)
         > mmgr->config.modem_reset_delay)) {
        LOG_DEBUG("BUS READY not received. force modem reset");
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
    }

    if ((mmgr->timer.type & (0x01 << E_TIMER_REBOOT_MODEM_DELAY)) &&
        ((current.tv_sec - mmgr->timer.start[E_TIMER_REBOOT_MODEM_DELAY].tv_sec)
         > 2)) {
        stop_timer(&mmgr->timer, E_TIMER_REBOOT_MODEM_DELAY);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
    }

    if ((mmgr->timer.type & (0x01 << E_TIMER_WAIT_CORE_DUMP_READY)) &&
        ((current.tv_sec -
          mmgr->timer.start[E_TIMER_WAIT_CORE_DUMP_READY].tv_sec)
         > CORE_DUMP_READY_TIMEOUT)) {
        LOG_DEBUG("Timeout while waiting for core dump IPC. Force modem reset");
        stop_timer(&mmgr->timer, E_TIMER_WAIT_CORE_DUMP_READY);
        set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
        cd.state = E_CD_LINK_ERROR;
        cd.reason = "Modem re-enumeration fail.";
        cd.reason_len = strlen(cd.reason);
        inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_CORE_DUMP_COMPLETE,
                                   &cd);
    }

out:
    return ret;
}

/**
 * initialize timer
 *
 * @param [in,out] timer timer
 * @param [in,out] config mmgr config
 *
 * @return E_ERR_BAD_PARAMETER timer or/and config is/are NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t timer_init(mmgr_timer_t *timer, mmgr_configuration_t *config)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(timer, ret, out);
    CHECK_PARAM(config, ret, out);

    timer->type = 0;
    timer->cur_timeout = TIMEOUT_EPOLL_INFINITE;
    timer->timeout[E_TIMER_COLD_RESET_ACK] =
        (config->timeout_ack_cold * 1000) / STEPS;
    timer->timeout[E_TIMER_MODEM_SHUTDOWN_ACK] =
        (config->timeout_ack_shtdwn * 1000) / STEPS;
    timer->timeout[E_TIMER_WAIT_FOR_IPC_READY] =
        (config->modem_reset_delay * 1000) / STEPS;
    timer->timeout[E_TIMER_WAIT_FOR_BUS_READY] =
        (config->modem_reset_delay * 1000) / STEPS;
    timer->timeout[E_TIMER_REBOOT_MODEM_DELAY] =
        (((int)(config->modem_reset_delay / 2)) * 1000) / STEPS;
    timer->timeout[E_TIMER_WAIT_CORE_DUMP_READY] =
        (CORE_DUMP_READY_TIMEOUT * 1000) / STEPS;
out:
    return ret;
}
