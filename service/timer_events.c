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

#define MMGR_FW_OPERATIONS
#include "events_manager.h"
#include "modem_specific.h"
#include "file.h"
#include "logs.h"
#include "timer_events.h"
#include "modem_info.h"

static const char const *g_type_str[] = {
#undef X
#define X(a) #a
    TIMER
};

#define STEPS 10
#define TIMER_INFINITE -1       /* wait indefinitely */
#define TIMER_ERROR -2

typedef struct mmgr_timer {
    uint8_t type;
    int cur_timeout;
    int timeout[E_TIMER_NUM];
    struct timespec start[E_TIMER_NUM];
    int ack_cold_reset;
    int ack_shtdwn_timeout;
    int ipc_ready;
    int cd_ipc_reset;
    int cd_ipc_ready;
    const clients_hdle_t *clients;
} mmgr_timer_t;


/**
 * @brief timer_get_timeout Return current timeout value
 *
 * @param h timer module handle
 *
 * @return TIMER_ERROR if h is NULL
 * @return current timeout value otherwise
 */
int timer_get_timeout(timer_handle_t *h)
{
    int timeout = TIMER_ERROR;
    mmgr_timer_t *timer = (mmgr_timer_t *)h;

    if (timer)
        timeout = timer->cur_timeout;

    return timeout;
}

/**
 * start a timer for a specific event
 *
 * @param [in] h timer module handle
 * @param [in] type type of event
 *
 * @return E_ERR_BAD_PARAMETER if h is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t timer_start(timer_handle_t *h, e_timer_type_t type)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    struct timespec current;
    mmgr_timer_t *timer = (mmgr_timer_t *)h;

    CHECK_PARAM(timer, ret, out);

    clock_gettime(CLOCK_MONOTONIC, &current);

    timer->type |= 0x01 << type;
    timer->start[type] = current;
    LOG_DEBUG("start timer for event: %s", g_type_str[type]);

    if ((timer->cur_timeout == TIMER_INFINITE) ||
        (timer->cur_timeout > timer->timeout[type])) {
        timer->cur_timeout = timer->timeout[type];
        LOG_DEBUG("update timeout: %dms", timer->cur_timeout);
    }

out:
    return ret;
}

/**
 * @brief stop_all_timers stop all running timers
 *
 * @param [in] h timer module handle
 *
 * @return E_ERR_BAD_PARAMETER if timer is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t timer_stop_all(timer_handle_t *h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mmgr_timer_t *timer = (mmgr_timer_t *)h;

    CHECK_PARAM(timer, ret, out);

    timer->type = 0x0;
    LOG_DEBUG("timer stopped");
    timer->cur_timeout = TIMER_INFINITE;

out:
    return ret;
}

/**
 * stop a timer for a specific event
 *
 * @param [in] h timer module handle
 * @param [in] type type of event
 *
 * @return E_ERR_BAD_PARAMETER if h is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t timer_stop(timer_handle_t *h, e_timer_type_t type)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int min = 0;
    mmgr_timer_t *timer = (mmgr_timer_t *)h;

    CHECK_PARAM(timer, ret, out);

    LOG_DEBUG("stop timer for event: %s", g_type_str[type]);
    timer->type &= ~(0x01 << type);

    if (timer->type == 0x0) {
        LOG_DEBUG("timer stopped");
        timer->cur_timeout = TIMER_INFINITE;
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
 * @param [in] h timer module handle
 * @param [out] reset true if MMGR should reset the modem
 * @param [out] mdm_off true if MMGR should shutdown the modem
 * @param [out] cd_err true if MMGR should restart cd IPC
 *
 * @return E_ERR_BAD_PARAMETER h is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t timer_event(timer_handle_t *h, bool *reset, bool *mdm_off,
                            bool *cd_err)
{
    struct timespec cur;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mmgr_timer_t *t = (mmgr_timer_t *)h;

    CHECK_PARAM(t, ret, out);
    CHECK_PARAM(reset, ret, out);
    CHECK_PARAM(mdm_off, ret, out);
    CHECK_PARAM(cd_err, ret, out);

    *reset = false;
    *mdm_off = false;
    *cd_err = false;

    clock_gettime(CLOCK_MONOTONIC, &cur);

    if ((t->type & (0x01 << E_TIMER_COLD_RESET_ACK)) &&
        ((cur.tv_sec - t->start[E_TIMER_COLD_RESET_ACK].tv_sec)
         > t->ack_cold_reset)) {
        clients_has_ack_cold(t->clients, true);
        timer_stop(h, E_TIMER_COLD_RESET_ACK);
        *reset = true;
    }

    if ((t->type & (0x01 << E_TIMER_MODEM_SHUTDOWN_ACK)) &&
        ((cur.tv_sec - t->start[E_TIMER_MODEM_SHUTDOWN_ACK].tv_sec)
         > t->ack_shtdwn_timeout)) {
        clients_has_ack_shtdwn(t->clients, true);
        timer_stop(h, E_TIMER_MODEM_SHUTDOWN_ACK);
        *reset = true;
        *mdm_off = true;
    }

    if ((t->type & (0x01 << E_TIMER_WAIT_FOR_IPC_READY)) &&
        ((cur.tv_sec - t->start[E_TIMER_WAIT_FOR_IPC_READY].tv_sec)
         > t->ipc_ready)) {
        LOG_DEBUG("IPC READY not received. force modem reset");
        timer_stop(h, E_TIMER_WAIT_FOR_IPC_READY);
        *reset = true;

        mmgr_cli_fw_update_result_t result = { .id = E_MODEM_FW_READY_TIMEOUT };
        clients_inform_all(t->clients, E_MMGR_RESPONSE_MODEM_FW_RESULT,
                           &result);
    }

    if ((t->type & (0x01 << E_TIMER_WAIT_FOR_BUS_READY)) &&
        ((cur.tv_sec - t->start[E_TIMER_WAIT_FOR_BUS_READY].tv_sec)
         > t->ipc_ready)) {
        LOG_DEBUG("BUS READY not received. force modem reset");
        timer_stop(h, E_TIMER_WAIT_FOR_BUS_READY);
        *reset = true;
    }

    if ((t->type & (0x01 << E_TIMER_REBOOT_MODEM_DELAY)) &&
        ((cur.tv_sec - t->start[E_TIMER_REBOOT_MODEM_DELAY].tv_sec) > 2)) {
        timer_stop(h, E_TIMER_REBOOT_MODEM_DELAY);
        *reset = true;
    }

    if (t->type & (0x01 << E_TIMER_WAIT_CORE_DUMP_READY)) {
        if (t->cd_ipc_reset) {
            if (((cur.tv_sec - t->start[E_TIMER_WAIT_CORE_DUMP_READY].tv_sec)
                 == t->cd_ipc_reset)) {
                LOG_DEBUG("Timeout while waiting for core dump IPC. Reset IPC");
                *cd_err = true;
            }
        }

        if ((cur.tv_sec - t->start[E_TIMER_WAIT_CORE_DUMP_READY].tv_sec)
            > t->cd_ipc_ready) {
            LOG_DEBUG("Timeout while waiting for core dump IPC. Reset modem");
            timer_stop(h, E_TIMER_WAIT_CORE_DUMP_READY);
            *reset = true;

            mmgr_cli_core_dump_t cd = { .state = E_CD_LINK_ERROR };
            cd.reason = "Modem enumeration failure";
            cd.reason_len = strlen(cd.reason);
            clients_inform_all(t->clients, E_MMGR_NOTIFY_CORE_DUMP_COMPLETE,
                               &cd);
        }
    }

out:
    return ret;
}

/**
 * initialize timer module
 *
 * @param [in] recov recovery configuration
 * @param [in] timings mmgr timings
 * @param [in] clients list
 *
 * @return a valid timer_handle_t pointer
 * @return NULL otherwise
 */
timer_handle_t *timer_init(const mmgr_recovery_t *recov,
                           const mmgr_timings_t *timings,
                           const clients_hdle_t *clients)
{
    mmgr_timer_t *timer = NULL;

    if (!recov && !timings && !clients)
        goto out;

    timer = calloc(1, sizeof(mmgr_timer_t));
    if (timer) {
        timer->ack_cold_reset = recov->cold_timeout;
        timer->ack_shtdwn_timeout = recov->shtdwn_timeout;
        timer->ipc_ready = timings->ipc_ready;
        timer->cd_ipc_reset = timings->cd_ipc_reset;
        timer->cd_ipc_ready = timings->cd_ipc_ready;
        timer->clients = clients;

        timer->type = 0;
        timer->cur_timeout = TIMER_INFINITE;
        timer->timeout[E_TIMER_COLD_RESET_ACK] =
            (recov->cold_timeout * 1000) / STEPS;
        timer->timeout[E_TIMER_MODEM_SHUTDOWN_ACK] =
            (recov->shtdwn_timeout * 1000) / STEPS;
        timer->timeout[E_TIMER_WAIT_FOR_IPC_READY] =
            (timings->ipc_ready * 1000) / STEPS;
        timer->timeout[E_TIMER_WAIT_FOR_BUS_READY] =
            (timings->ipc_ready * 1000) / STEPS;
        timer->timeout[E_TIMER_REBOOT_MODEM_DELAY] =
            (((int)(timings->ipc_ready / 2)) * 1000) / STEPS;
        timer->timeout[E_TIMER_WAIT_CORE_DUMP_READY] =
            (timings->cd_ipc_ready * 1000) / STEPS;
    }

out:
    return (timer_handle_t *)timer;
}

/**
 * dispose timer module
 *
 * @param [in] h timer module handle
 *
 * @return E_ERR_BAD_PARAMETER h is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t timer_dispose(timer_handle_t *h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mmgr_timer_t *timer = (mmgr_timer_t *)h;

    CHECK_PARAM(timer, ret, out);

    free(timer);

out:
    return ret;
}
