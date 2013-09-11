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
#include <dlfcn.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include "at.h"
#include "client_events.h"
#include "client_cnx.h"
#include "errors.h"
#include "events_manager.h"
#include "file.h"
#include "logs.h"
#include "modem_events.h"
#include "mmgr.h"
#include "property.h"
#include "security.h"
#include "timer_events.h"
#include "tty.h"
#include "modem_specific.h"

#define FIRST_EVENT -1
#define TEL_STACK_PROPERTY "persist.service.telephony.off"

const char *g_mmgr_st[] = {
#undef X
#define X(a) #a
    MMGR_STATE
};

inline void set_mmgr_state(mmgr_data_t *mmgr, e_timer_type_t state)
{
    mmgr->state = state;
    LOG_VERBOSE("new STATE: %s", g_mmgr_st[mmgr->state]);
}

static e_mmgr_errors_t security_event(mmgr_data_t *mmgr)
{
    return secur_event(&mmgr->secur);
}

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
    secur_dispose(&mmgr->secur);
    write_to_file(WAKE_UNLOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));
    if (mmgr->info.mcdr.lib != NULL)
        dlclose(mmgr->info.mcdr.lib);
    if (mmgr->info.mup.hdle != NULL)
        dlclose(mmgr->info.mup.hdle);
    if (mmgr->fd_tty != CLOSED_FD)
        close_tty(&mmgr->fd_tty);
    if (mmgr->fd_cnx != CLOSED_FD)
        close_cnx(&mmgr->fd_cnx);
    if (mmgr->info.fd_mcd != CLOSED_FD)
        close_tty(&mmgr->info.fd_mcd);
    if (mmgr->epollfd != CLOSED_FD)
        close(mmgr->epollfd);
    secur_stop(&mmgr->secur);
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
    int disable_telephony = 1;

    CHECK_PARAM(mmgr, ret, out);

    mmgr->fd_tty = CLOSED_FD;
    mmgr->fd_cnx = CLOSED_FD;

    property_get_int(TEL_STACK_PROPERTY, &disable_telephony);
    if (disable_telephony == 1) {
        LOG_DEBUG("telephony stack is disabled");
        mdm_down(&mmgr->info);
        set_mmgr_state(mmgr, E_MMGR_MDM_OOS);
    } else
        set_mmgr_state(mmgr, E_MMGR_MDM_OFF);

    mmgr->events.nfds = 0;
    mmgr->events.ev = malloc(sizeof(struct epoll_event) *
                             (mmgr->config.max_clients + 1));
    mmgr->events.cur_ev = FIRST_EVENT;
    mmgr->events.link_state = E_MDM_LINK_NONE;
    mmgr->request.accept_request = true;

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

    if ((ret = mdm_specific_init(&mmgr->info)) != E_ERR_SUCCESS)
        goto out;

    if ((ret = mdm_prepare(&mmgr->info)) != E_ERR_SUCCESS)
        goto out;

    ret = open_cnx(&mmgr->fd_cnx);
    if (ret != E_ERR_SUCCESS)
        goto out;

    mmgr->epollfd = CLOSED_FD;
    if ((ret = init_ev_hdler(&mmgr->epollfd)) != E_ERR_SUCCESS)
        goto out;

    ret = add_fd_ev(mmgr->epollfd, mmgr->fd_cnx, EPOLLIN);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = add_fd_ev(mmgr->epollfd, mmgr->info.fd_mcd, EPOLLIN);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = set_mcd_poll_states(&mmgr->info);
    LOG_DEBUG("MCD driver added to poll list");

    ret = secur_init(&mmgr->secur, &mmgr->config);
    if (ret != E_ERR_SUCCESS)
        goto out;

    /* configure events handlers */
    mmgr->hdler_events[E_EVENT_IPC] = ipc_event;
    mmgr->hdler_events[E_EVENT_MCD] = modem_control_event;
    mmgr->hdler_events[E_EVENT_BUS] = bus_events;
    mmgr->hdler_events[E_EVENT_NEW_CLIENT] = new_client;
    mmgr->hdler_events[E_EVENT_CLIENT] = known_client;
    mmgr->hdler_events[E_EVENT_SECUR] = security_event;
    mmgr->hdler_events[E_EVENT_TIMEOUT] = timer_event;

    if ((ret = client_events_init(mmgr)) != E_ERR_SUCCESS) {
        LOG_ERROR("unable to configure client events handlers");
        goto out;
    }

    if ((ret = modem_events_init(mmgr)) != E_ERR_SUCCESS) {
        LOG_ERROR("unable to configure modem events handler");
        goto out;
    }

    if (mmgr->info.mdm_link == E_LINK_HSIC) {
        if ((ret =
             bus_events_init(&mmgr->events.bus_events, mmgr->config.bb_pid,
                             mmgr->config.bb_vid, mmgr->config.flash_pid,
                             mmgr->config.flash_vid, mmgr->config.mcdr_pid,
                             mmgr->config.mcdr_vid)) != E_ERR_SUCCESS) {
            LOG_ERROR("unable to configure bus events handler");
            goto out;
        }

        int wd_fd = bus_ev_get_fd(&mmgr->events.bus_events);
        ret = add_fd_ev(mmgr->epollfd, wd_fd, EPOLLIN);
        if (ret != E_ERR_SUCCESS)
            goto out;
        LOG_DEBUG("bus event fd added to poll list");

        /* handle the first events after discovery */
        if (get_bus_state(&mmgr->events.bus_events) & MDM_BB_READY) {
            /* ready to configure modem */
            mmgr->events.link_state &= ~E_MDM_LINK_FLASH_READY;
            mmgr->events.link_state |= E_MDM_LINK_BB_READY;
        } else if (get_bus_state(&mmgr->events.bus_events) & MDM_FLASH_READY) {
            /* ready to flash modem */
            mmgr->events.link_state |= E_MDM_LINK_FLASH_READY;
            mmgr->events.link_state &= ~E_MDM_LINK_BB_READY;
        } else if (!mmgr->config.is_flashless)
            start_timer(&mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
    } else {
        mmgr->events.link_state |= E_MDM_LINK_BB_READY;
        mmgr->events.bus_events.wd_fd = CLOSED_FD;
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
            mmgr->events.state = E_EVENT_IPC;
        } else if (fd == mmgr->info.fd_mcd) {
            mmgr->events.state = E_EVENT_MCD;
        } else if (fd == mmgr->events.bus_events.wd_fd) {
            mmgr->events.state = E_EVENT_BUS;
        } else if (fd == mmgr->secur.fd) {
            mmgr->events.state = E_EVENT_SECUR;
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
    bool wakelock = false;
    char *events_str[] = {
#undef X
#define X(a) #a
        EVENTS
    };

    CHECK_PARAM(mmgr, ret, out);

    for (;;) {
        if (mmgr->events.cli_req & E_CLI_REQ_OFF) {
            reset_shutdown_ack(&mmgr->clients);
            modem_shutdown(mmgr);
            set_mmgr_state(mmgr, E_MMGR_MDM_OFF);
            mmgr->events.cli_req &= ~E_CLI_REQ_OFF;
        } else if (mmgr->state == E_MMGR_MDM_RESET) {
            LOG_DEBUG("restoring modem");
            reset_modem(mmgr);
            mmgr->events.cli_req &= ~E_CLI_REQ_RESET;
        }

        if ((mmgr->state == E_MMGR_MDM_OFF) || (mmgr->state == E_MMGR_MDM_UP) ||
            (mmgr->state == E_MMGR_MDM_OOS)) {
            wakelock = false;
            write_to_file(WAKE_UNLOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                          strlen(MODULE_NAME));
        }
        if ((ret = wait_for_event(mmgr)) != E_ERR_SUCCESS)
            goto out;
        if (wakelock == false) {
            wakelock = true;
            write_to_file(WAKE_LOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                          strlen(MODULE_NAME));
        }

        LOG_DEBUG("event type: %s", events_str[mmgr->events.state]);
        if (mmgr->hdler_events[mmgr->events.state] != NULL) {
            if ((ret = mmgr->hdler_events[mmgr->events.state] (mmgr))
                == E_ERR_BAD_PARAMETER)
                goto out;
        }
    }
out:
    /* if the wakelock is set here, it will be removed by events_cleanup
     * function */
    return ret;
}
