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

#define MMGR_FW_OPERATIONS
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

static const char const *g_mmgr_st[] = {
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
    return secure_event(mmgr->secure);
}

/**
 * close modem tty and cnxs
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_SUCCESS
 */
e_mmgr_errors_t events_dispose(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    free(mmgr->events.ev);
    write_to_file(WAKE_UNLOCK_SYSFS, SYSFS_OPEN_MODE, MODULE_NAME,
                  strlen(MODULE_NAME));
    if (mmgr->fd_tty != CLOSED_FD)
        close_tty(&mmgr->fd_tty);
    if (mmgr->fd_cnx != CLOSED_FD)
        close_cnx(&mmgr->fd_cnx);
    if (mmgr->epollfd != CLOSED_FD)
        close(mmgr->epollfd);
out:
    return ret;
}

/**
 * initialize events module
 *
 * @param [in] nb_client
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t events_init(int nb_client, mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    /* initialize all fds */
    mmgr->fd_tty = CLOSED_FD;
    mmgr->fd_cnx = CLOSED_FD;
    mmgr->epollfd = CLOSED_FD;

    mmgr->events.nfds = 0;
    mmgr->events.ev = malloc(sizeof(struct epoll_event) * (nb_client + 1));
    if (mmgr->events.ev == NULL) {
        LOG_ERROR("memory allocation failed");
        ret = E_ERR_FAILED;
        goto out;
    }

    mmgr->events.cur_ev = FIRST_EVENT;
    mmgr->events.link_state = E_MDM_LINK_NONE;
    mmgr->request.accept_request = true;

out:
    return ret;
}

/**
 * start events handler
 *
 * @param [in,out] mmgr mmgr context
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t events_start(mmgr_data_t *mmgr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(mmgr, ret, out);

    if ((ret = mdm_prepare(&mmgr->info)) != E_ERR_SUCCESS)
        goto out;

    ret = open_cnx(&mmgr->fd_cnx);
    if (ret != E_ERR_SUCCESS)
        goto out;

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

    if (mmgr->info.mdm_link == E_LINK_HSIC) {
        if (E_ERR_SUCCESS != (ret = bus_ev_start(mmgr->events.bus_events)))
            goto out;

        int wd_fd = bus_ev_get_fd(mmgr->events.bus_events);
        ret = add_fd_ev(mmgr->epollfd, wd_fd, EPOLLIN);
        if (ret != E_ERR_SUCCESS)
            goto out;
        LOG_DEBUG("bus event fd added to poll list");

        /* handle the first events after discovery */
        if (bus_ev_get_state(mmgr->events.bus_events) & MDM_BB_READY) {
            /* ready to configure modem */
            mmgr->events.link_state &= ~E_MDM_LINK_FLASH_READY;
            mmgr->events.link_state |= E_MDM_LINK_BB_READY;
        } else if (bus_ev_get_state(mmgr->events.bus_events) &
                   MDM_FLASH_READY) {
            /* ready to flash modem */
            mmgr->events.link_state |= E_MDM_LINK_FLASH_READY;
            mmgr->events.link_state &= ~E_MDM_LINK_BB_READY;
        } else if (!mmgr->info.is_flashless) {
            timer_start(mmgr->timer, E_TIMER_WAIT_FOR_BUS_READY);
        }
    } else {
        mmgr->events.link_state |= E_MDM_LINK_BB_READY;
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
            LOG_INFO("Waiting for a new event");
            mmgr->events.nfds = epoll_wait(mmgr->epollfd, mmgr->events.ev,
                                           clients_get_allowed(mmgr->clients)
                                           + 1,
                                           timer_get_timeout(mmgr->timer));
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
        if (fd == mmgr->fd_cnx)
            mmgr->events.state = E_EVENT_NEW_CLIENT;
        else if (fd == mmgr->fd_tty)
            mmgr->events.state = E_EVENT_IPC;
        else if (fd == mmgr->info.fd_mcd)
            mmgr->events.state = E_EVENT_MCD;
        else if (fd == bus_ev_get_fd(mmgr->events.bus_events))
            mmgr->events.state = E_EVENT_BUS;
        else if (fd == secure_get_fd(mmgr->secure))
            mmgr->events.state = E_EVENT_SECUR;
        else
            mmgr->events.state = E_EVENT_CLIENT;
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

    for (;; ) {
        if (mmgr->events.cli_req & E_CLI_REQ_OFF) {
            clients_reset_ack_shtdwn(mmgr->clients);
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
        switch (mmgr->events.state) {
        case E_EVENT_IPC:
            ret = ipc_event(mmgr);
            break;
        case E_EVENT_MCD:
            ret = modem_control_event(mmgr);
            break;
        case E_EVENT_BUS:
            ret = bus_events(mmgr);
            break;
        case E_EVENT_NEW_CLIENT:
            ret = new_client(mmgr);
            break;
        case E_EVENT_CLIENT:
            ret = known_client(mmgr);
            break;
        case E_EVENT_SECUR:
            ret = security_event(mmgr);
            break;
        case E_EVENT_TIMEOUT: {
            bool reset = false;
            bool mdm_off = false;
            bool cd_ipc = false;
            ret = timer_event(mmgr->timer, &reset, &mdm_off, &cd_ipc);
            if (reset)
                set_mmgr_state(mmgr, E_MMGR_MDM_RESET);
            if (mdm_off)
                mmgr->events.cli_req = E_CLI_REQ_OFF;
            if (cd_ipc)
                ctrl_on_cd_ipc_failure(mmgr->info.ctrl);

            break;
        }
        }

        if (ret == E_ERR_BAD_PARAMETER)
            goto out;
    }
out:
    /* if the wakelock is set here, it will be removed by events_cleanup
     * function */
    return ret;
}
