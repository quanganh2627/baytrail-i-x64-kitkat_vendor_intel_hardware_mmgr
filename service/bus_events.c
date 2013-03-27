/* Modem Manager - bus events source file
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
#include <string.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <usbhost/usbhost.h>
#include "errors.h"
#include "logs.h"
#include "tty.h"
#include "events_manager.h"
#include "bus_events.h"

/**
 * add bus event
 *
 * @private
 *
 * @param [in] path device path
 * @param [in] event event type (remove or add)
 * @param [out] ctx context
 *
 * @return E_ERR_FAILED if bus events capacity has been reached
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t add_ev(const char *path, uint8_t event, void *ctx)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    bus_ev_cli_ctx_t *ev_ctx = (bus_ev_cli_ctx_t *)ctx;
    int i = ev_ctx->i;

    if (i >= BUS_EV_CAPACITY) {
        LOG_ERROR("too much events at once, reached %d CAPACITY -> lost event",
                  BUS_EV_CAPACITY);
        ret = E_ERR_FAILED;
        goto out;
    }

    bus_event_t *evs = ev_ctx->evs;
    evs[i].event = event;
    strncpy(evs[i].path, path, sizeof(evs[i].path));
    ev_ctx->i++;

out:
    return ret;
}

/**
 * add device
 *
 * @private
 *
 * @param [in] path device path
 * @param [out] ctx context
 *
 * @return E_ERR_FAILED if bus events capacity has been reached
 * @return E_ERR_SUCCESS if successful
 */
static int device_added_cb(const char *path, void *ctx)
{
    return add_ev(path, EV_ADDED, ctx);
}

/**
 * remove device
 *
 * @private
 *
 * @param [in] path device path
 * @param [out] ctx context
 *
 * @return E_ERR_FAILED if bus events capacity has been reached
 * @return E_ERR_SUCCESS if successful
 */
static int device_rmed_cb(const char *path, void *ctx)
{
    return add_ev(path, EV_DELETED, ctx);
}

/**
 * check PID and VID
 *
 * @private
 *
 * @param [in] path device path
 * @param [in] pid
 * @param [out] vid
 *
 * @return 1 if PID and VID are correct
 * @return 0 if PID and VID are not correct
 */
int is_pid_and_vid(const char *path, uint16_t pid, uint16_t vid)
{
    struct usb_device *dev = usb_device_open(path);
    if (dev == NULL) {
        LOG_ERROR("Failed to open path: %s", path);
        return 0;
    }

    uint16_t ppid = usb_device_get_product_id(dev);
    uint16_t pvid = usb_device_get_vendor_id(dev);
    LOG_DEBUG("Event bus pid 0x%.4x vid 0x%.4x", ppid, pvid);

    return (ppid == pid && pvid == vid);
}

int bus_read_events(bus_ev_t *bus_events)
{
    return usb_host_read_event(bus_events->ctx);
}

/**
 * handle bus event
 *
 * @param [in, out] bus_events
 *
 * @return E_ERR_SUCCESS
 */
e_mmgr_errors_t bus_handle_events(bus_ev_t *bus_events)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int i;

    for (i = 0; i < bus_events->cli_ctx.i; i++) {
        LOG_DEBUG("Event: %s %d", bus_events->cli_ctx.evs[i].path,
                  bus_events->cli_ctx.evs[i].event);
        if (bus_events->cli_ctx.evs[i].event == EV_ADDED) {
            LOG_DEBUG("EVENT ADDED");
            if (is_pid_and_vid(bus_events->cli_ctx.evs[i].path,
                               bus_events->modem_flash_pid,
                               bus_events->modem_flash_vid)) {
                bus_events->mdm_state |= MDM_FLASH_READY;
                strncpy(bus_events->modem_flash_path,
                        bus_events->cli_ctx.evs[i].path, PATH_MAX);
                LOG_DEBUG("+Modem flash is READY");
            } else if (is_pid_and_vid(bus_events->cli_ctx.evs[i].path,
                                      bus_events->modem_bb_pid,
                                      bus_events->modem_bb_vid)) {
                bus_events->mdm_state |= MDM_BB_READY;
                strncpy(bus_events->modem_bb_path,
                        bus_events->cli_ctx.evs[i].path, PATH_MAX);
                LOG_DEBUG("+Modem base band READY");
            } else if (is_pid_and_vid(bus_events->cli_ctx.evs[i].path,
                                      bus_events->mcdr_bb_pid,
                                      bus_events->mcdr_bb_vid)) {
                bus_events->mdm_state |= MDM_CD_READY;
                strncpy(bus_events->modem_cd_path,
                        bus_events->cli_ctx.evs[i].path, PATH_MAX);
                LOG_DEBUG("+Modem core dump READY");
            }
        } else if (bus_events->cli_ctx.evs[i].event == EV_DELETED) {
            LOG_DEBUG("EVENT DELETED");
            if (strncmp(bus_events->modem_flash_path,
                        bus_events->cli_ctx.evs[i].path, PATH_MAX) == 0) {
                bus_events->mdm_state &= ~MDM_FLASH_READY;
                bus_events->modem_flash_path[0] = '\0';
                LOG_DEBUG("-Modem flash not READY");
            } else if (strncmp(bus_events->modem_bb_path,
                               bus_events->cli_ctx.evs[i].path,
                               PATH_MAX) == 0) {
                bus_events->mdm_state &= ~MDM_BB_READY;
                bus_events->modem_bb_path[0] = '\0';
                LOG_DEBUG("-Modem base band not READY");
            } else if (strncmp(bus_events->modem_cd_path,
                               bus_events->cli_ctx.evs[i].path,
                               PATH_MAX) == 0) {
                bus_events->mdm_state &= ~MDM_CD_READY;
                bus_events->modem_cd_path[0] = '\0';
                LOG_DEBUG("-Modem core dump not READY");
            }
        }
    }

    bus_events->cli_ctx.i = 0;
    return ret;
}

int get_bus_state(bus_ev_t *bus_events)
{
    return bus_events->mdm_state;
}

int bus_ev_get_fd(bus_ev_t *bus_events)
{
    bus_events->wd_fd = usb_host_get_fd(bus_events->ctx);
    return bus_events->wd_fd;
}

/**
 * bus event initialization
 *
 * @private
 *
 * @param [in,out] bus_events
 * @param [in] bb_pid base band PID
 * @param [in] bb_vid base band VID
 * @param [in] flash_pid flahless PID
 * @param [in] flash_vid flashless VID
 * @param [in] mcdr_pid mcdr PID
 * @param [in] mcdr_vid mcdr VID
 *
 * @return E_ERR_FAILED
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t bus_events_init(bus_ev_t *bus_events, char *bb_pid,
                                char *bb_vid, char *flash_pid, char *flash_vid,
                                char *mcdr_pid, char *mcdr_vid)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(bus_events, ret, out);
    CHECK_PARAM(bb_pid, ret, out);
    CHECK_PARAM(bb_vid, ret, out);
    CHECK_PARAM(flash_pid, ret, out);
    CHECK_PARAM(flash_vid, ret, out);

    memset(bus_events, 0, sizeof(bus_ev_t));
    if ((bus_events->ctx = usb_host_init()) == NULL) {
        ret = E_ERR_FAILED;
        goto out;
    }

    errno = 0;
    bus_events->modem_flash_pid = strtoul(flash_pid, NULL, 0);
    bus_events->modem_flash_vid = strtoul(flash_vid, NULL, 0);
    bus_events->modem_bb_pid = strtoul(bb_pid, NULL, 0);
    bus_events->modem_bb_vid = strtoul(bb_vid, NULL, 0);
    bus_events->mcdr_bb_pid = strtoul(mcdr_pid, NULL, 0);
    bus_events->mcdr_bb_vid = strtoul(mcdr_vid, NULL, 0);
    if (errno != 0) {
        LOG_DEBUG("Couldn't convert PID/VIDs from config: %s %s %s %s %s %s",
                  bb_pid, bb_vid, flash_pid, flash_vid, mcdr_pid, mcdr_vid);
        goto out;
    }
    /* @TODO: handle errors */
    usb_host_load(bus_events->ctx, device_added_cb, device_rmed_cb, NULL,
                  &bus_events->cli_ctx);
    /* when calling usb_host_load, there's a call to find_existing_devices
       which triggers added_cb events so, there's been events ... maybe. */
    bus_handle_events(bus_events);

out:
    return ret;
}
