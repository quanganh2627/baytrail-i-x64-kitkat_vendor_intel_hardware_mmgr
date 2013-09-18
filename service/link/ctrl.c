/* Modem Manager - link control management source file
**
** Copyright (C) Intel 2013
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

#include "ctrl.h"
#include "logs.h"
#include "file.h"

#include <string.h>

typedef struct ctrl_link {
    link_ctrl_t ctrl;
    e_link_t type;
} ctrl_link_t;

typedef struct ctrl_ctx {
    ctrl_link_t mdm;
    ctrl_link_t cd;
} ctrl_ctx_t;

typedef enum e_ctrl_action {
    E_ACTION_ON,
    E_ACTION_OFF,
    E_ACTION_RESET,
} e_ctrl_action_t;

static inline void fill_ctrl_link(ctrl_link_t *link, e_link_t type,
                                  link_ctrl_t *ctrl)
{
    link->type = type;
    link->ctrl = *ctrl;
}

/**
 * Initializes the link control module
 *
 * @param [in] mdm_type modem link type
 * @param [in] mdm_ctrl modem control link data
 * @param [in] cd_type core dump link type
 * @param [in] cd_ctrl core dump control link data
 *
 * @return NULL if module initialization has failed
 * @return valid ctrl_handle_t pointer otherwise
 */
ctrl_handle_t ctrl_init(e_link_t mdm_type, link_ctrl_t *mdm_ctrl,
                        e_link_t cd_type, link_ctrl_t *cd_ctrl)
{
    ctrl_ctx_t *ctx = NULL;

    if (mdm_ctrl && cd_ctrl) {
        ctx = calloc(1, sizeof(ctrl_ctx_t));
        if (ctx) {
            fill_ctrl_link(&ctx->mdm, mdm_type, mdm_ctrl);
            fill_ctrl_link(&ctx->cd, cd_type, cd_ctrl);
        } else {
            LOG_ERROR("memory allocation failed");
        }
    }

    if ((mdm_type == E_LINK_HSIC) &&
        !strncmp(mdm_ctrl->device, "", sizeof(mdm_ctrl->device))) {
        LOG_ERROR("wrong device for modem link control handling");
        goto err;
    }

    if ((cd_type == E_LINK_HSIC) &&
        !strncmp(cd_ctrl->device, "", sizeof(cd_ctrl->device))) {
        LOG_ERROR("wrong device for core dump link control handling");
        goto err;
    }

    return (ctrl_handle_t *)ctx;

err:
    ctrl_dispose((ctrl_handle_t *)ctx);
    return NULL;
}

/**
 * Disposes the link control module
 *
 * @param [in] h control link handle
 *
 * @param E_ERR_BAD_PARAMETER if h is NULL
 * @param E_ERR_SUCCESS otherwise
 */
e_mmgr_errors_t ctrl_dispose(ctrl_handle_t *h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    ctrl_ctx_t *ctx = (ctrl_ctx_t *)h;

    CHECK_PARAM(ctx, ret, out);

    free(ctx);

out:
    return ret;
}

/**
 * This function sets the IPC control state
 *
 * @param [in] p link power
 * @param [in] action
 *
 * @return E_ERR_FAILED if it fails
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info or/and path or/and value is/are NULL
 */
static e_mmgr_errors_t ctrl_set_state(link_ctrl_t *ctrl, e_ctrl_action_t action)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    char *cmd = NULL;

    CHECK_PARAM(ctrl, ret, out);

    switch (action) {
    case E_ACTION_OFF:
        cmd = ctrl->off;
        break;
    case E_ACTION_ON:
        cmd = ctrl->on;
        break;
    case E_ACTION_RESET:
        cmd = ctrl->reset;
        break;
    }

    ret = write_to_file(ctrl->device, SYSFS_OPEN_MODE, cmd, strlen(cmd));
out:
    return ret;
}

/**
 * Performs the right link control operation when modem is down
 *
 * @param [in] h power management handle
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t ctrl_on_mdm_down(ctrl_handle_t *h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    ctrl_ctx_t *ctx = (ctrl_ctx_t *)h;

    CHECK_PARAM(ctx, ret, out);

    switch (ctx->mdm.type) {
    case E_LINK_HSI:
        /* Nothing to do */
        break;
    case E_LINK_HSIC:
        ret = ctrl_set_state(&ctx->mdm.ctrl, E_ACTION_OFF);
        break;
    case E_LINK_UART:
        /* Nothing to do */
        break;
    default:
        LOG_ERROR("type %d not handled", ctx->mdm.type);
        ret = E_ERR_FAILED;
        break;
    }

out:
    return ret;
}

/**
 * Performs the right link control operation when modem is up
 *
 * @param [in] h power management handle
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t ctrl_on_mdm_up(ctrl_handle_t *h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    ctrl_ctx_t *ctx = (ctrl_ctx_t *)h;

    CHECK_PARAM(ctx, ret, out);

    switch (ctx->mdm.type) {
    case E_LINK_HSI:
        /* Nothing to do */
        break;
    case E_LINK_HSIC:
        ret = ctrl_set_state(&ctx->mdm.ctrl, E_ACTION_ON);
        break;
    case E_LINK_UART:
        /* Nothing to do */
        break;
    default:
        LOG_ERROR("type %d not handled", ctx->mdm.type);
        ret = E_ERR_FAILED;
        break;
    }

out:
    return ret;
}

/**
 * Performs the right link control operation when modem is flashed
 *
 * @param [in] h power management handle
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t ctrl_on_mdm_flash(ctrl_handle_t *h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    ctrl_ctx_t *ctx = (ctrl_ctx_t *)h;

    CHECK_PARAM(ctx, ret, out);

    switch (ctx->mdm.type) {
    case E_LINK_HSI:
        /* Nothing to do */
        break;
    case E_LINK_HSIC:
        ret = ctrl_set_state(&ctx->mdm.ctrl, E_ACTION_RESET);
        break;
    case E_LINK_UART:
        /* Nothing to do */
        break;
    default:
        LOG_ERROR("type %d not handled", ctx->mdm.type);
        ret = E_ERR_FAILED;
        break;
    }

out:
    return ret;
}

/**
 * Performs the right link control operation when core dump enumeration has
 * failed
 *
 * @param [in] h power management handle
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t ctrl_on_cd_ipc_failure(ctrl_handle_t *h)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    ctrl_ctx_t *ctx = (ctrl_ctx_t *)h;

    CHECK_PARAM(ctx, ret, out);

    switch (ctx->mdm.type) {
    case E_LINK_HSI:
        /* Nothing to do */
        break;
    case E_LINK_HSIC:
        ret = ctrl_set_state(&ctx->cd.ctrl, E_ACTION_RESET);
        break;
    case E_LINK_UART:
        /* Nothing to do */
        break;
    default:
        LOG_ERROR("type %d not handled", ctx->cd.type);
        ret = E_ERR_FAILED;
        break;
    }

out:
    return ret;
}
