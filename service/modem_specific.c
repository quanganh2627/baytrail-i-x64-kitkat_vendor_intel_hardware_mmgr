/* Modem Manager - modem specific source file
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

#include "logs.h"
#include "modem_specific.h"
#include <linux/mdm_ctrl.h>

/**
 * Perform a modem warm reset
 *
 * @param [in] info modem info structure
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t modem_warm_reset(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    LOG_INFO("MODEM WARM RESET");
    if (ioctl(info->fd_mcd, MDM_CTRL_WARM_RESET) == -1) {
        ret = E_ERR_FAILED;
        LOG_DEBUG("couldn't reset modem: %s", strerror(errno));
    }
out:
    return ret;
}

/**
 * Perform a modem cold reset (modem cold boot)
 *
 * @param [in] info modem info structure
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t modem_cold_reset(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    LOG_INFO("MODEM COLD RESET");
    if (ioctl(info->fd_mcd, MDM_CTRL_COLD_RESET) == -1) {
        ret = E_ERR_FAILED;
        LOG_DEBUG("couldn't reset modem: %s", strerror(errno));
    }
out:
    return ret;
}

/**
 * Shutting down modem
 *
 * @param [in,out] info reset management structure
 *
 * @return E_OPERATION_BAD_PARAMETER if info is NULL
 * @return E_OPERATION_CONTINUE
 */
e_mmgr_errors_t modem_down(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(info, ret, out);

    if (ioctl(info->fd_mcd, MDM_CTRL_POWER_OFF) == -1) {
        ret = E_ERR_FAILED;
        LOG_DEBUG("couldn't shutdown modem: %s", strerror(errno));
    } else {
        LOG_INFO("MODEM ELECTRICALLY SHUTDOWN");
        ret = E_ERR_SUCCESS;
    }
out:
    return ret;
}

/**
 * power on modem
 *
 * @param [in] info modem info structure
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t modem_up(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    if (ioctl(info->fd_mcd, MDM_CTRL_POWER_ON) == -1) {
        LOG_DEBUG("failed to power on the modem: %s", strerror(errno));
        ret = E_ERR_FAILED;
        goto out;
    } else
        LOG_DEBUG("Modem POWERED-UP");

out:
    return ret;
}

/**
 * this function retrieves the modem state
 *
 * @param [in] fd_mcd file descriptor of mcd
 * @param [out] state e_modem_events_type_t
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t get_modem_state(int fd_mcd, e_modem_events_type_t *state)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int read = 0;

    CHECK_PARAM(state, ret, out);

    *state = E_EV_NONE;

    if (ioctl(fd_mcd, MDM_CTRL_GET_STATE, &read) == -1) {
        ret = E_ERR_FAILED;
        LOG_DEBUG("couldn't get modem state %s", strerror(errno));
        goto out;
    }
    LOG_DEBUG("mcd state: 0x%.02X", read);

    if (read & MDM_CTRL_STATE_OFF) {
        LOG_INFO("modem state: OFF");
        *state |= E_EV_MODEM_OFF;
    }

    if (read & MDM_CTRL_STATE_IPC_READY) {
        LOG_INFO("modem state: IPC_READY");
        *state |= E_EV_IPC_READY;
    }

    if (read & MDM_CTRL_STATE_COREDUMP) {
        LOG_INFO("modem state: CORE DUMP");
        *state |= E_EV_CORE_DUMP;
    }

    read = 0;
    if ((ioctl(fd_mcd, MDM_CTRL_GET_HANGUP_REASONS, &read) < 0) ||
        (ioctl(fd_mcd, MDM_CTRL_CLEAR_HANGUP_REASONS) < 0)) {
        LOG_DEBUG("Failed to get hangup reason: %s", strerror(errno));
        goto out;
    }

    if (read & MDM_CTRL_HU_RESET) {
        LOG_INFO("modem state: SELF-RESET");
        *state |= E_EV_MODEM_SELF_RESET;
    }

out:
    return ret;
}
