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
#include "timer_events.h"
#include "file.h"
#include "modem_update.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define FLS_FILE_PERMISSION (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH)
#define INJECTION_TOOL "/system/bin/injection_tool"
/* @TODO: this should be configurable via mmgr.conf */
#define MUP_LIB "libmodemupdate.so"
#define MUP_FUNC_INIT "mup_initialize"
#define MUP_FUNC_OPEN "mup_open_device"
#define MUP_FUNC_TOGGLE_HSI_FLASHING_MODE "mup_toggle_hsi_flashing_mode"
#define MUP_FUNC_UP_FW "mup_update_fw"
#define MUP_FUNC_DISPOSE "mup_dispose"
#define MUP_FUNC_FW_VERSION "mup_check_fw_version"
#define MUP_FUNC_CONFIG_SECUR "mup_configure_secur_channel"

/**
 * callback to handle aplog messages
 *
 * @param [in] msg message to display
 * @param [in] msg_len unused
 *
 */
void mup_log(const char *msg, size_t msg_len)
{
    (void)msg_len;              //unused
    LOG_DEBUG("%s", msg);
}

/**
 * init module function
 *
 * @param[in] info modem data
 * @param[in] is_flashless
 *
 * @return E_ERR_FAILED if INJECTION_TOOL is missing
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t modem_specific_init(modem_info_t *info, bool is_flashless)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    char *p = NULL;

    CHECK_PARAM(info, ret, out);

    if (is_flashless) {
        info->mup.hdle = dlopen(MUP_LIB, RTLD_LAZY);
        if (info->mup.hdle == NULL) {
            LOG_ERROR("failed to open library");
            ret = E_ERR_FAILED;
            goto out;
        }

        /** see dlsym manpage to understand why this strange cast is used */
        *(void **)&info->mup.initialize = dlsym(info->mup.hdle, MUP_FUNC_INIT);
        *(void **)&info->mup.open_device = dlsym(info->mup.hdle, MUP_FUNC_OPEN);
        *(void **)&info->mup.toggle_hsi_flashing_mode =
            dlsym(info->mup.hdle, MUP_FUNC_TOGGLE_HSI_FLASHING_MODE);
        *(void **)&info->mup.update_fw = dlsym(info->mup.hdle, MUP_FUNC_UP_FW);
        *(void **)&info->mup.dispose = dlsym(info->mup.hdle, MUP_FUNC_DISPOSE);
        *(void **)&info->mup.config_secur_channel = dlsym(info->mup.hdle,
                                                          MUP_FUNC_CONFIG_SECUR);
        *(void **)&info->mup.check_fw_version =
            dlsym(info->mup.hdle, MUP_FUNC_FW_VERSION);

        p = (char *)dlerror();
        if (p != NULL) {
            LOG_ERROR("An error ocurred during symbol resolution");
            ret = E_ERR_FAILED;
            dlclose(info->mup.hdle);
            info->mup.hdle = NULL;
            goto out;
        }

        ret = is_file_exists(INJECTION_TOOL, 0);
    } else {
        info->mup.hdle = NULL;
    }
out:
    return ret;
}

e_mmgr_errors_t toggle_flashing_mode(modem_info_t *info, char *link_layer,
                                     bool flashing_mode)
{
    if (strcmp(link_layer, "hsi") == 0)
        return (info->mup.toggle_hsi_flashing_mode(flashing_mode) ==
                E_MUP_SUCCEED) ? E_ERR_SUCCESS : E_ERR_FAILED;
    return E_ERR_SUCCESS;
}

/**
 * flash modem data
 *
 * @param[in] info modem data
 * @param[in] comport modem communication port for flashing
 * @param[in] ch_sw channel hw sw
 * @param[in] secur secur library data
 * @param[out] verdict provides modem fw update status
 *
 * @return E_ERR_FAILED if operation fails
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info is empty
 */
e_mmgr_errors_t flash_modem(modem_info_t *info, char *comport, bool ch_sw,
                            secur_t *secur, e_modem_fw_error_t *verdict)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mup_interface_t *handle = NULL;
    void *secur_callback = NULL;

    CHECK_PARAM(info, ret, out);
    CHECK_PARAM(secur, ret, out);

    if (E_MUP_SUCCEED != info->mup.initialize(&handle, mup_log)) {
        ret = E_ERR_FAILED;
        LOG_ERROR("modem updater initialization failed");
        goto out;
    }

    /* @TODO retrieve modem version via SFI table and remove this static value */
    if (info->mup.check_fw_version(info->fl_conf.run_inj_fls, "XMM7160") !=
        E_MUP_SUCCEED) {
        LOG_ERROR("Bad modem family. Shutdown the modem");
        ret = E_ERR_FAILED;
        *verdict = E_MODEM_FW_BAD_FAMILY;
        goto out;
    }

    mup_fw_update_params_t params = {
        .handle = handle,
        .mdm_com_port = comport,
        .channel_hw_sw = ch_sw,
        .fw_file_path = info->fl_conf.run_inj_fls,
        .fw_file_path_len = strnlen(info->fl_conf.run_inj_fls,
                                    MAX_SIZE_CONF_VAL),
        .erase_all = false      /* for flashless modem, this should be false */
    };

    if (E_MUP_SUCCEED != info->mup.open_device(&params)) {
        ret = E_ERR_FAILED;
        LOG_ERROR("failed to open device");
        goto out;
    }

    secur_get_callback(secur, &secur_callback);
    if (secur_callback != NULL) {
        if (E_MUP_SUCCEED !=
            info->mup.config_secur_channel(handle, secur_callback,
                                           info->fl_conf.bkup_rnd_cert,
                                           strnlen(info->fl_conf.bkup_rnd_cert,
                                                   MAX_SIZE_CONF_VAL))) {
            LOG_ERROR("failed to configure secur channel");
            ret = E_ERR_FAILED;
            goto out;
        }
    }

    if (E_MUP_SUCCEED != info->mup.update_fw(&params)) {
        ret = E_ERR_FAILED;
        LOG_ERROR("modem firmware update failed");
    } else {
        *verdict = E_MODEM_FW_SUCCEED;
    }

    if (E_MUP_SUCCEED != info->mup.dispose(handle)) {
        ret = E_ERR_FAILED;
        LOG_ERROR("modem updater disposal fails");
    }

out:
    return ret;
}

/**
 * start hsic link
 *
 * @param [in] info modem info structure
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t start_hsic(modem_info_t *info)
{
    //FIXME: Writting 0 to stop the HSIC is useless and writting 1 stops and restarts the hsic
    //just write 1 in the HSIC_PATH when we want to stop/start
    //spec needs to be fixed with SE or need to be fixed by HSIC driver to conform to the spec
    return E_ERR_SUCCESS;
}

/**
 * stop hsic link
 *
 * @param [in] info modem info structure
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t stop_hsic(modem_info_t *info)
{
/*    return write_to_file(HSIC_PATH, SYSFS_OPEN_MODE, "0", 1);*/
    //FIXME: Writes 1 to HSIC_PATH to restart the HSIC before a cold boot
    //needs to be adressed
    (void)info;                 //unused
    e_mmgr_errors_t ret = write_to_file(HSIC_PATH, SYSFS_OPEN_MODE, "1", 1);
    usleep(500 * 1000);         /* TODO: remove me */
    return ret;
}

/**
 * package fls file with a fresh fls file and nvm files
 *
 * @param [in] info modem info structure
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t regen_fls(modem_info_t *info)
{

    e_mmgr_errors_t ret = E_ERR_FAILED;
    int status;

    CHECK_PARAM(info, ret, out);

    /* @TODO: replace InjectionTool by download lib */
    if ((ret = is_file_exists(info->fl_conf.run_boot_fls, 0)) != E_ERR_SUCCESS) {
        LOG_ERROR("fls file (%s) is missing", info->fl_conf.run_boot_fls);
        goto out;
    }

    ret = E_ERR_FAILED;
    remove(info->fl_conf.run_inj_fls);
    pid_t chld = fork();
    if (chld == 0) {
        LOG_DEBUG("trying to package fls file");
        execl(INJECTION_TOOL, "injection_tool", "-i",
              info->fl_conf.run_boot_fls, "-o", info->fl_conf.run_inj_fls, "-n",
              info->fl_conf.run_path, NULL);
        LOG_ERROR("execl has failed");
        exit(0);
    } else {
        waitpid(chld, &status, 0);
        if ((status == 0)
            && (is_file_exists(info->fl_conf.run_inj_fls, 0) == E_ERR_SUCCESS)) {
            ret = E_ERR_SUCCESS;
        }
    }
    if (ret == E_ERR_SUCCESS) {
        LOG_INFO("fls file created successfully (%s)",
                 info->fl_conf.run_inj_fls);
    } else {
        LOG_ERROR("failed to create fls file");
    }
out:
    return ret;
}

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
 * @param [in] is_flashless
 * @param [in] is_hsic
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t modem_up(modem_info_t *info, bool is_flashless, bool is_hsic)
{

    /* @TODO: rework this to remove the is_flashless and is_hsic
       boolean to hide modem_specific parameters from the calling module */
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int state;

    CHECK_PARAM(info, ret, out);

    ioctl(info->fd_mcd, MDM_CTRL_GET_STATE, &state);

    /*@TODO: broken start_hsic does nothing */
    if (is_hsic)
        start_hsic(info);

    if (is_flashless) {
        if (state & MDM_CTRL_STATE_OFF) {
            if (ioctl(info->fd_mcd, MDM_CTRL_POWER_ON) == -1) {
                LOG_DEBUG("failed to power on the modem: %s", strerror(errno));
                ret = E_ERR_FAILED;
            }
        } else {
            ret = modem_cold_reset(info);
        }
    } else if (ioctl(info->fd_mcd, MDM_CTRL_POWER_ON) == -1) {
        LOG_DEBUG("failed to power on the modem: %s", strerror(errno));
        ret = E_ERR_FAILED;
    }

    if (ret == E_ERR_SUCCESS)
        LOG_DEBUG("Modem successfully POWERED-UP");

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

    if (read & MDM_CTRL_STATE_FW_DOWNLOAD_READY) {
        LOG_INFO("ready to upload firmware");
        *state |= E_EV_FW_DOWNLOAD_READY;
    }

    read = 0;
    if (ioctl(fd_mcd, MDM_CTRL_GET_HANGUP_REASONS, &read) < 0) {
        LOG_DEBUG("Failed to get hangup reason: %s", strerror(errno));
        goto out;
    }

    if (read & MDM_CTRL_HU_RESET) {
        LOG_INFO("modem state: SELF-RESET");
        *state |= E_EV_MODEM_SELF_RESET;
    }

out:
    ioctl(fd_mcd, MDM_CTRL_CLEAR_HANGUP_REASONS);
    return ret;
}

/**
 * update mcd poll
 *
 * @param [in,out] info modem info context
 *
 * @return E_ERR_BAD_PARAMETER if mmgr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_mcd_poll_states(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    LOG_DEBUG("update mcd states filter: 0x%.2X", info->polled_states);
    if (ioctl(info->fd_mcd, MDM_CTRL_SET_POLLED_STATES,
              &info->polled_states) == -1) {
        LOG_DEBUG("failed to set Modem Control Driver polled states: %s",
                  strerror(errno));
        ret = E_ERR_FAILED;
    }

out:
    return ret;
}
