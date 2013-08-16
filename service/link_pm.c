/* Modem Manager - link power management source file
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

#include "logs.h"
#include "link_pm.h"
#include "file.h"

#include <string.h>

#define UART_PM "/sys/devices/pci0000:00/0000:00:05.1/power/control"
#define HSIC_PM HSIC_PATH"/L2_autosuspend_enable"
#define PM_CMD_SIZE 6

#define HSIC_PM_ON "1"
#define HSIC_PM_OFF "0"
#define UART_PM_ON "auto"
#define UART_PM_OFF "on"

/**
 * This function sets the IPC power management
 *
 * @param [in] link type of link
 * @param [in] state (true: power management is enabled)
 *
 * @return E_ERR_FAILED if it fails
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info or/and path or/and value is/are NULL
 */
static e_mmgr_errors_t pm_set_state(e_link_type_t link, bool state)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    char *hsic_cmd[] = { HSIC_PM_OFF, HSIC_PM_ON };
    char *uart_cmd[] = { UART_PM_OFF, UART_PM_ON };
    char *path = NULL;
    char *cmd = NULL;

    switch (link) {
    case E_LINK_HSI:
        /* Nothing to do */
        ret = E_ERR_FAILED;
        break;
    case E_LINK_HSIC:
        path = HSIC_PM;
        cmd = hsic_cmd[state];
        break;
    case E_LINK_UART:
        path = UART_PM;
        cmd = uart_cmd[state];
        break;
    }
    if (path && cmd)
        ret = write_to_file(path, SYSFS_OPEN_MODE, cmd, strlen(cmd));
    return ret;
}

/**
 * Perform the right power management operation when the modem will be flashed
 *
 * @param [in] info modem info
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t pm_on_mdm_flash(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    switch (info->mdm_link) {
    case E_LINK_HSI:
        /* Nothing to do */
        break;
    case E_LINK_HSIC:
        /* Nothing to do */
        break;
    case E_LINK_UART:
        /* Nothing to do */
        break;
    }

out:
    return ret;
}

/**
 * Perform the right power management operation when the modem is up
 *
 * @param [in] info modem info
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t pm_on_mdm_up(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    switch (info->mdm_link) {
    case E_LINK_HSI:
        /* Nothing to do */
        break;
    case E_LINK_HSIC:
        pm_set_state(info->mdm_link, true);
        break;
    case E_LINK_UART:
        /* Nothing to do */
        break;
    }

out:
    return ret;
}

/**
 * Perform the right power management operation when the modem is OOS
 *
 * @param [in] info modem info
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t pm_on_mdm_oos(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    switch (info->mdm_link) {
    case E_LINK_HSI:
        /* Nothing to do */
        break;
    case E_LINK_HSIC:
        pm_set_state(info->mdm_link, true);
        break;
    case E_LINK_UART:
        /* Nothing to do */
        break;
    }

out:
    return ret;
}

/**
 * Perform the right power management operation when a core dump is available
 *
 * @param [in] info modem info
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t pm_on_mdm_cd(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    switch (info->cd_link) {
    case E_LINK_HSI:
        /* Nothing to do */
        break;
    case E_LINK_HSIC:
        /* Nothing to do */
        break;
    case E_LINK_UART:
        pm_set_state(info->cd_link, false);
        break;
    }

out:
    return ret;
}

/**
 * Perform the right power management operation when CD operation is completed
 *
 * @param [in] info modem info
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is NULL
 */
e_mmgr_errors_t pm_on_mdm_cd_complete(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    switch (info->cd_link) {
    case E_LINK_HSI:
        /* Nothing to do */
        break;
    case E_LINK_HSIC:
        pm_set_state(info->cd_link, true);
        break;
    case E_LINK_UART:
        pm_set_state(info->cd_link, true);
        break;
    }

out:
    return ret;
}
