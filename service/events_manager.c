/* Modem Manager - events manager source file
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
#include <fcntl.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include "at.h"
#include "client_events.h"
#include "errors.h"
#include "events_manager.h"
#include "logs.h"
#include "modem_events.h"
#include "mmgr.h"
#include "socket.h"
#include "tty.h"

#define FIRST_EVENT -1

/**
 * close modem tty and sockets
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_SUCCESS
 */
int events_cleanup(mmgr_data_t *mmgr)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    free(mmgr->events.ev);
    close_all_clients(&mmgr->clients);
    if (mmgr->fd_tty != CLOSED_FD)
        close_tty(&mmgr->fd_tty);
    if (mmgr->fd_socket != CLOSED_FD)
        close_socket(&mmgr->fd_socket);
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
static int timeout_event(mmgr_data_t *mmgr)
{
    struct timespec current;
    int ret = E_ERR_SUCCESS;
    int timeout = TIMEOUT_EPOLL_ACK;

    CHECK_PARAM(mmgr, ret, out);

    clock_gettime(CLOCK_MONOTONIC, &current);
    if (mmgr->modem_state == E_MMGR_NOTIFY_MODEM_COLD_RESET) {
        if ((current.tv_sec - mmgr->timer.start.tv_sec) > TIMEOUT_ACK) {
            check_cold_ack(&mmgr->clients, true);
            mmgr->info.ev |= E_EV_AP_RESET;
            mmgr->events.restore_modem = true;
        }
    } else if (mmgr->modem_state == E_MMGR_NOTIFY_MODEM_SHUTDOWN) {
        if ((current.tv_sec - mmgr->timer.start.tv_sec) > TIMEOUT_ACK) {
            check_shutdown_ack(&mmgr->clients, true);
            FORCE_MODEM_SHUTDOWN(mmgr);
        }
    } else if (mmgr->events.modem_shutdown) {
        if ((current.tv_sec - mmgr->timer.start.tv_sec) >
            mmgr->config.delay_before_modem_shtdwn) {
            mmgr->modem_state = E_MMGR_NOTIFY_MODEM_SHUTDOWN;
            START_TIMER(mmgr->timer, timeout);
            inform_all_clients(&mmgr->clients, E_MMGR_NOTIFY_MODEM_SHUTDOWN);
        }
    } else {
        LOG_ERROR("timeout during state: %d", mmgr->modem_state);
        STOP_TIMER(mmgr->timer);
    }
out:
    return ret;
}

/**
 * initialize mmgr structure
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
int events_init(mmgr_data_t *mmgr)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->fd_tty = CLOSED_FD;
    mmgr->fd_socket = CLOSED_FD;
    mmgr->modem_state = E_MMGR_EVENT_MODEM_DOWN;

    mmgr->events.nfds = 0;
    mmgr->events.ev = malloc(sizeof(struct epoll_event) *
                             (mmgr->config.max_clients + 1));
    mmgr->events.cur_ev = FIRST_EVENT;
    mmgr->events.restore_modem = true;  /* force reset modem at start-up */
    mmgr->events.modem_shutdown = false;

    mmgr->timer.timeout = TIMEOUT_EPOLL_INFINITE;

    if (mmgr->events.ev == NULL) {
        LOG_ERROR("Unable to initialize event structure");
        ret = E_ERR_BAD_PARAMETER;
        goto out;
    }

    if ((ret = modem_info_init(&mmgr->config, &mmgr->info))
        != E_ERR_SUCCESS) {
        LOG_ERROR("Modem info initialization failed");
        goto out;
    }

    if ((ret = initialize_list(&mmgr->clients,
                               mmgr->config.max_clients)) != E_ERR_SUCCESS) {
        LOG_ERROR("Client list initialisation failed");
        goto out;
    }

    ret = open_socket(&mmgr->fd_socket);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = initialize_epoll(&mmgr->epollfd, mmgr->fd_socket, EPOLLIN);
    if (ret != E_ERR_SUCCESS) {
        LOG_ERROR("epoll configuration failed");
        goto out;
    }

    /* configure events handlers */
    mmgr->hdler_events[E_EVENT_MODEM] = modem_event;
    mmgr->hdler_events[E_EVENT_NEW_CLIENT] = new_client;
    mmgr->hdler_events[E_EVENT_CLIENT] = known_client;
    mmgr->hdler_events[E_EVENT_TIMEOUT] = timeout_event;

    if ((ret = client_events_init(mmgr)) != E_ERR_SUCCESS) {
        LOG_ERROR("unable to configure client events handlers");
        goto out;
    }

    if ((ret = modem_events_init(mmgr)) != E_ERR_SUCCESS)
        LOG_ERROR("unable to configure modem events handler");

out:
    return ret;
}

/**
 * this function is an event dispatcher. it waits for a new event if event list
 * is empty. otherwise, it sets the current event type
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if epoll_wait fails
 * E_ERR_SUCCESS: if successful
 */
static int wait_for_event(mmgr_data_t *mmgr)
{
    int ret = E_ERR_SUCCESS;
    int fd;
    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->events.cur_ev + 1 >= mmgr->events.nfds) {
        do {
            mmgr->events.cur_ev = FIRST_EVENT;
            LOG_INFO("%s STATE: waiting for a new event", MODULE_NAME);
            mmgr->events.nfds = epoll_wait(mmgr->epollfd, mmgr->events.ev,
                                           mmgr->config.max_clients + 1,
                                           mmgr->timer.timeout);
            if (mmgr->events.nfds == -1) {
                LOG_ERROR("epoll_wait failed (%s)", strerror(errno));
                if ((errno == EBADF) || (errno == EINVAL)) {
                    LOG_ERROR("Bad configuration");
                    ret = E_ERR_FAILED;
                    goto out;
                }
            }
        } while (mmgr->events.nfds == -1);
    }

    mmgr->events.cur_ev++;
    if (mmgr->events.nfds == 0) {
        mmgr->events.state = E_EVENT_TIMEOUT;
    } else {
        fd = mmgr->events.ev[mmgr->events.cur_ev].data.fd;
        if (fd == mmgr->fd_socket) {
            mmgr->events.state = E_EVENT_NEW_CLIENT;
        } else if (fd == mmgr->fd_tty) {
            mmgr->events.state = E_EVENT_MODEM;
        } else {
            mmgr->events.state = E_EVENT_CLIENT;
        }
    }
out:
    return ret;
}

/**
 * events manager: manage modem and socket events
 * Instead of a state machine, an event dispatcher is used here.
 * A state machine is not usefull here as the protocol
 * is stateless.
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_SUCCESS
 */
int events_manager(mmgr_data_t *mmgr)
{
    int ret = E_ERR_FAILED;
    char *events_str[] = {
#undef X
#define X(a) #a
        EVENTS
    };

    CHECK_PARAM(mmgr, ret, out);

    for (;;) {
        if (mmgr->events.restore_modem) {
            mmgr->events.restore_modem = false;
            restore_modem(mmgr);
        }
        if ((ret = wait_for_event(mmgr)) != E_ERR_SUCCESS)
            goto out;
        LOG_DEBUG("event type: %s", events_str[mmgr->events.state]);
        if (mmgr->hdler_events[mmgr->events.state] != NULL) {
            if ((ret = mmgr->hdler_events[mmgr->events.state] (mmgr))
                == E_ERR_BAD_PARAMETER)
                goto out;
        }
    }
out:
    return ret;
}
