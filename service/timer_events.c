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
#include "logs.h"
#include "timer_events.h"

static const char *g_type_str[] = {
#undef X
#define X(a) #a
    TIMER
};

#define TIMEOUT_ACK 1           /* in second */
#define TIMEOUT_EPOLL_ACK 200   /* in millisecond */
#define TIMEOUT_EPOLL_INFINITE -1       /* wait indefinitely */
#define STEPS 10

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

        if ((timer->type & (0x01 << E_TIMER_NO_RESOURCE_RELEASE_ACK)) &&
            (min > timer->timeout[E_TIMER_NO_RESOURCE_RELEASE_ACK]))
            min = timer->timeout[E_TIMER_NO_RESOURCE_RELEASE_ACK];

        if ((timer->type & (0x01 << E_TIMER_WAIT_FOR_IPC_READY)) &&
            (min > timer->timeout[E_TIMER_NO_RESOURCE_RELEASE_ACK]))
            min = timer->timeout[E_TIMER_NO_RESOURCE_RELEASE_ACK];

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

    CHECK_PARAM(mmgr, ret, out);

    clock_gettime(CLOCK_MONOTONIC, &current);

    if ((mmgr->timer.type & (0x01 << E_TIMER_COLD_RESET_ACK)) &&
        ((current.tv_sec - mmgr->timer.start[E_TIMER_COLD_RESET_ACK].tv_sec)
         > TIMEOUT_ACK)) {
        check_cold_ack(&mmgr->clients, true);
        mmgr->info.ev |= E_EV_FORCE_RESET;
        mmgr->events.do_restore_modem = true;
        stop_timer(&mmgr->timer, E_TIMER_COLD_RESET_ACK);
    }

    if ((mmgr->timer.type & (0x01 << E_TIMER_MODEM_SHUTDOWN_ACK)) &&
        ((current.tv_sec - mmgr->timer.start[E_TIMER_MODEM_SHUTDOWN_ACK].tv_sec)
         > TIMEOUT_ACK)) {
        check_shutdown_ack(&mmgr->clients, true);
        FORCE_MODEM_SHUTDOWN(mmgr);
        stop_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
    }

    if ((mmgr->timer.type & (0x01 << E_TIMER_NO_RESOURCE_RELEASE_ACK)) &&
        ((current.tv_sec -
          mmgr->timer.start[E_TIMER_NO_RESOURCE_RELEASE_ACK].tv_sec) >
         mmgr->config.delay_before_modem_shtdwn)) {
        mmgr->client_notification = E_MMGR_NOTIFY_MODEM_SHUTDOWN;
        inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_SHUTDOWN);
        stop_timer(&mmgr->timer, E_TIMER_NO_RESOURCE_RELEASE_ACK);
        start_timer(&mmgr->timer, E_TIMER_MODEM_SHUTDOWN_ACK);
    }

    if ((mmgr->timer.type & (0x01 << E_TIMER_WAIT_FOR_IPC_READY)) &&
        ((current.tv_sec - mmgr->timer.start[E_TIMER_WAIT_FOR_IPC_READY].tv_sec)
         > mmgr->config.modem_reset_delay)) {
        LOG_DEBUG("IPC READY not received. force modem reset");
        mmgr->info.ev |= E_EV_FORCE_RESET;
        mmgr->events.do_restore_modem = true;
        stop_timer(&mmgr->timer, E_TIMER_WAIT_FOR_IPC_READY);
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
    timer->timeout[E_TIMER_COLD_RESET_ACK] = TIMEOUT_EPOLL_ACK;
    timer->timeout[E_TIMER_MODEM_SHUTDOWN_ACK] = TIMEOUT_EPOLL_ACK;
    timer->timeout[E_TIMER_NO_RESOURCE_RELEASE_ACK] =
        (config->delay_before_modem_shtdwn * 1000) / STEPS;
    timer->timeout[E_TIMER_WAIT_FOR_IPC_READY] =
        (config->modem_reset_delay * 1000) / STEPS;
out:
    return ret;
}
