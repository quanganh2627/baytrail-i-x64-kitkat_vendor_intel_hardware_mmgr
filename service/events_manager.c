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
#include "client_cnx.h"
#include "errors.h"
#include "events_manager.h"
#include "logs.h"
#include "modem_events.h"
#include "mmgr.h"
#include "timer_events.h"
#include "tty.h"

#define FIRST_EVENT -1

/**
 * close modem tty and cnxs
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_SUCCESS
 */
e_mmgr_errors_t events_cleanup(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    free(mmgr->events.ev);
    close_all_clients(&mmgr->clients);
    if (mmgr->fd_tty != CLOSED_FD)
        close_tty(&mmgr->fd_tty);
    if (mmgr->fd_cnx != CLOSED_FD)
        close_cnx(&mmgr->fd_cnx);
    if (mmgr->info.fd_mcd != CLOSED_FD)
        close_tty(&mmgr->info.fd_mcd);
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
e_mmgr_errors_t events_init(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    struct epoll_event ev;
    struct epoll_event ev_mcd;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->fd_tty = CLOSED_FD;
    mmgr->fd_cnx = CLOSED_FD;
    mmgr->client_notification = E_MMGR_EVENT_MODEM_DOWN;

    mmgr->events.nfds = 0;
    mmgr->events.ev = malloc(sizeof(struct epoll_event) *
                             (mmgr->config.max_clients + 1));
    mmgr->events.cur_ev = FIRST_EVENT;
    mmgr->events.modem_shutdown = false;
    mmgr->events.modem_state = E_MDM_STATE_NONE;

    if (mmgr->events.ev == NULL) {
        LOG_ERROR("Unable to initialize event structure");
        ret = E_ERR_BAD_PARAMETER;
        goto out;
    }

    if (timer_init(&mmgr->timer, &mmgr->config) != E_ERR_SUCCESS) {
        LOG_ERROR("Failed to configure timer");
        goto out;
    }

    if ((ret = initialize_list(&mmgr->clients,
                               mmgr->config.max_clients)) != E_ERR_SUCCESS) {
        LOG_ERROR("Client list initialisation failed");
        goto out;
    }

    if ((ret = modem_info_init(&mmgr->config, &mmgr->info))
        != E_ERR_SUCCESS) {
        LOG_ERROR("Modem info initialization failed");
        goto out;
    }

    if (mmgr->config.is_flashless) {
        if ((ret = modem_specific_init() != E_ERR_SUCCESS))
            goto out;
        if ((ret = regen_fls(&mmgr->info) != E_ERR_SUCCESS))
            goto out;
    }

    ret = open_cnx(&mmgr->fd_cnx);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = initialize_epoll(&mmgr->epollfd, mmgr->fd_cnx, EPOLLIN);
    if (ret != E_ERR_SUCCESS) {
        LOG_ERROR("epoll configuration failed");
        goto out;
    }

    ev_mcd.events = EPOLLIN;
    ev_mcd.data.fd = mmgr->info.fd_mcd;
    if (epoll_ctl(mmgr->epollfd, EPOLL_CTL_ADD, mmgr->info.fd_mcd, &ev_mcd) ==
        -1) {
        LOG_ERROR("failed to add modem control driver interface to epoll");
        goto out;
    }
    ret = set_mcd_poll_states(&mmgr->info);
    LOG_DEBUG("MCD driver added to poll list");

    /* configure events handlers */
    mmgr->hdler_events[E_EVENT_MODEM] = modem_event;
    mmgr->hdler_events[E_EVENT_MCD] = modem_control_event;
    mmgr->hdler_events[E_EVENT_BUS] = bus_events;
    mmgr->hdler_events[E_EVENT_NEW_CLIENT] = new_client;
    mmgr->hdler_events[E_EVENT_CLIENT] = known_client;
    mmgr->hdler_events[E_EVENT_TIMEOUT] = timer_event;

    if ((ret = client_events_init(mmgr)) != E_ERR_SUCCESS) {
        LOG_ERROR("unable to configure client events handlers");
        goto out;
    }

    if ((ret = modem_events_init(mmgr)) != E_ERR_SUCCESS) {
        LOG_ERROR("unable to configure modem events handler");
        goto out;
    }

    if (strcmp(mmgr->config.link_layer, "hsic") == 0) {
        if ((ret =
             bus_events_init(&mmgr->events.bus_events, mmgr->config.bb_pid,
                             mmgr->config.bb_vid, mmgr->config.flash_pid,
                             mmgr->config.flash_vid, mmgr->config.mcdr_pid,
                             mmgr->config.mcdr_vid)) != E_ERR_SUCCESS) {
            LOG_ERROR("unable to configure bus events handler");
            goto out;
        }

        int wd_fd = bus_ev_get_fd(&mmgr->events.bus_events);
        ev.events = EPOLLIN;
        ev.data.fd = wd_fd;
        if (epoll_ctl(mmgr->epollfd, EPOLL_CTL_ADD, wd_fd, &ev) == -1) {
            LOG_ERROR("Error during epoll_ctl. fd=%d (%s)",
                      wd_fd, strerror(errno));
            ret = E_ERR_FAILED;
            goto out;
        }
        LOG_DEBUG("bus event fd added to poll list");

        // handle the first events after discovery
        if (get_bus_state(&mmgr->events.bus_events) & MDM_BB_READY) {
            // ready to configure modem
            mmgr->events.modem_state &= ~E_MDM_STATE_FLASH_READY;
            mmgr->events.modem_state |= E_MDM_STATE_BB_READY;
        } else if (get_bus_state(&mmgr->events.bus_events) & MDM_FLASH_READY) {
            // ready to flash modem
            mmgr->events.modem_state |= E_MDM_STATE_FLASH_READY;
            mmgr->events.modem_state &= ~E_MDM_STATE_BB_READY;
        } else if (!mmgr->config.is_flashless)
            start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
    } else {
        mmgr->events.modem_state |= E_MDM_STATE_BB_READY;
    }

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
static e_mmgr_errors_t wait_for_event(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int fd;
    CHECK_PARAM(mmgr, ret, out);

    if (mmgr->events.cur_ev + 1 >= mmgr->events.nfds) {
        do {
            mmgr->events.cur_ev = FIRST_EVENT;
            LOG_INFO("%s STATE: waiting for a new event", MODULE_NAME);
            mmgr->events.nfds = epoll_wait(mmgr->epollfd, mmgr->events.ev,
                                           mmgr->config.max_clients + 1,
                                           mmgr->timer.cur_timeout);
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
        if (fd == mmgr->fd_cnx) {
            mmgr->events.state = E_EVENT_NEW_CLIENT;
        } else if (fd == mmgr->fd_tty) {
            mmgr->events.state = E_EVENT_MODEM;
        } else if (fd == mmgr->info.fd_mcd) {
            mmgr->events.state = E_EVENT_MCD;
        } else if (fd == mmgr->events.bus_events.wd_fd) {
            mmgr->events.state = E_EVENT_BUS;
        } else {
            mmgr->events.state = E_EVENT_CLIENT;
        }
    }
out:
    return ret;
}

/**
 * events manager: manage modem and cnx events
 * Instead of a state machine, an event dispatcher is used here.
 * A state machine is not usefull here as the protocol
 * is stateless.
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_SUCCESS
 */
e_mmgr_errors_t events_manager(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    char *events_str[] = {
#undef X
#define X(a) #a
        EVENTS
    };

    CHECK_PARAM(mmgr, ret, out);

    for (;;) {
        if (mmgr->info.ev & E_EV_FORCE_RESET) {
            LOG_DEBUG("restoring modem");
            restore_modem(mmgr);
            mmgr->info.ev &= ~E_EV_FORCE_RESET;
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
