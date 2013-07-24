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
#include "link_pm.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#define FLS_FILE_PERMISSION (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH)
/* @TODO: this should be configurable via mmgr.conf */
#define MUP_LIB "libmodemupdate.so"
#define MUP_FUNC_INIT "mup_initialize"
#define MUP_FUNC_OPEN "mup_open_device"
#define MUP_FUNC_TOGGLE_HSI_FLASHING_MODE "mup_toggle_hsi_flashing_mode"
#define MUP_FUNC_UP_FW "mup_update_fw"
#define MUP_FUNC_UP_NVM "mup_update_nvm"
#define MUP_FUNC_READ_NVM_ID "mup_get_nvm_id"
#define MUP_FUNC_DISPOSE "mup_dispose"
#define MUP_FUNC_FW_VERSION "mup_check_fw_version"
#define MUP_FUNC_CONFIG_SECUR "mup_configure_secur_channel"
#define MUP_FUNC_GEN_FLS "mup_gen_fls"

#define BACKUP ".bkup"

/**
 * This function will backup the nvm files. Existing files will be overwrite.
 *
 * @param info
 *
 * @return E_ERR_BAD_PARAMETER
 * @return E_ERR_SUCCESS
 */
e_mmgr_errors_t backup_nvm(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    char dynamic[PATH_MAX] = { '\0' };
    char stat[PATH_MAX] = { '\0' };

    CHECK_PARAM(info, ret, out);

    snprintf(dynamic, PATH_MAX, "%s%s", info->fl_conf.run_dyn, BACKUP);
    snprintf(stat, PATH_MAX, "%s%s", info->fl_conf.run_stat, BACKUP);

    unlink(dynamic);
    unlink(stat);

    copy_file(info->fl_conf.run_dyn, dynamic, FLS_FILE_PERMISSION);
    copy_file(info->fl_conf.run_stat, stat, FLS_FILE_PERMISSION);

out:
    return ret;
}

/**
 * This function will restore the mode fw and all parameters (RnD, NVM)
 *
 * @param info
 *
 * @return E_ERR_BAD_PARAMETER
 * @return E_ERR_SUCCESS
 */
e_mmgr_errors_t restore_run(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    unlink(info->fl_conf.run_boot_fls);
    unlink(info->fl_conf.run_cal);
    unlink(info->fl_conf.run_dyn);
    unlink(info->fl_conf.run_stat);
    unlink(info->fl_conf.run_rnd_cert);

    copy_file(info->fl_conf.bkup_cal, info->fl_conf.run_cal,
              FLS_FILE_PERMISSION);
    copy_file(info->fl_conf.bkup_stat, info->fl_conf.run_stat,
              FLS_FILE_PERMISSION);
    copy_file(info->fl_conf.bkup_rnd_cert, info->fl_conf.run_rnd_cert,
              FLS_FILE_PERMISSION);
    copy_file(info->fl_conf.bkup_boot_fls, info->fl_conf.run_boot_fls,
              FLS_FILE_PERMISSION);

out:
    return ret;
}

/**
 * This function will restore the backup nvm files. If those files doesn't exist,
 * regen_fls will create blank ones
 *
 * @param info
 *
 * @return E_ERR_BAD_PARAMETER
 * @return E_ERR_SUCCESS
 */
e_mmgr_errors_t restore_nvm(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    char dynamic[PATH_MAX] = { '\0' };
    char stat[PATH_MAX] = { '\0' };

    CHECK_PARAM(info, ret, out);

    snprintf(dynamic, PATH_MAX, "%s%s", info->fl_conf.run_dyn, BACKUP);
    snprintf(stat, PATH_MAX, "%s%s", info->fl_conf.run_stat, BACKUP);

    unlink(info->fl_conf.run_dyn);
    unlink(info->fl_conf.run_stat);
    unlink(info->fl_conf.run_cal);

    if (is_file_exists(dynamic, 0) == E_ERR_SUCCESS) {
        ret = copy_file(dynamic, info->fl_conf.run_dyn, FLS_FILE_PERMISSION);
        unlink(dynamic);
    }

    if (is_file_exists(stat, 0) == E_ERR_SUCCESS) {
        ret = copy_file(stat, info->fl_conf.run_stat, FLS_FILE_PERMISSION);
        unlink(stat);
    }

    if (is_file_exists(info->fl_conf.bkup_cal, 0) == E_ERR_SUCCESS) {
        ret =
            copy_file(info->fl_conf.bkup_cal, info->fl_conf.run_cal,
                      FLS_FILE_PERMISSION);
    }

out:
    return ret;
}

/**
 * callback to handle aplog messages
 *
 * @param [in] msg message to display
 * @param [in] args variable arguments list
 *
 */
void mup_log(const char *msg, ...)
{
    char buff[256] = { '\0' };
    va_list ap;

    if (msg != NULL) {
        va_start(ap, msg);

        vsnprintf(buff, sizeof(buff), msg, ap);

        buff[sizeof(buff) - 1] = '\0';

        LOG_DEBUG("%s", buff);

        va_end(ap);
    }
}

/**
 * init module function
 *
 * @param[in] info modem data
 *
 * @return E_ERR_FAILED
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t mdm_specific_init(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    char *p = NULL;

    CHECK_PARAM(info, ret, out);

    if (info->is_flashless) {
        info->mup.hdle = dlopen(MUP_LIB, RTLD_LAZY);
        if (info->mup.hdle == NULL) {
            LOG_ERROR("failed to open library");
            ret = E_ERR_FAILED;
            dlerror();
            goto out;
        }

        info->mup.initialize = dlsym(info->mup.hdle, MUP_FUNC_INIT);
        info->mup.open_device = dlsym(info->mup.hdle, MUP_FUNC_OPEN);
        info->mup.toggle_hsi_flashing_mode = dlsym(info->mup.hdle,
                                                   MUP_FUNC_TOGGLE_HSI_FLASHING_MODE);
        info->mup.update_fw = dlsym(info->mup.hdle, MUP_FUNC_UP_FW);
        info->mup.update_nvm = dlsym(info->mup.hdle, MUP_FUNC_UP_NVM);
        info->mup.read_nvm_id = dlsym(info->mup.hdle, MUP_FUNC_READ_NVM_ID);
        info->mup.dispose = dlsym(info->mup.hdle, MUP_FUNC_DISPOSE);
        info->mup.config_secur_channel =
            dlsym(info->mup.hdle, MUP_FUNC_CONFIG_SECUR);
        info->mup.check_fw_version = dlsym(info->mup.hdle, MUP_FUNC_FW_VERSION);
        info->mup.gen_fls = dlsym(info->mup.hdle, MUP_FUNC_GEN_FLS);

        p = (char *)dlerror();
        if (p != NULL) {
            LOG_ERROR("An error ocurred during symbol resolution");
            ret = E_ERR_FAILED;
            dlclose(info->mup.hdle);
            info->mup.hdle = NULL;
            goto out;
        }
    } else {
        info->mup.hdle = NULL;
    }
out:
    return ret;
}

e_mmgr_errors_t toggle_flashing_mode(modem_info_t *info, bool flashing_mode)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    if (info->mdm_link == E_LINK_HSI)
        ret = (info->mup.toggle_hsi_flashing_mode(flashing_mode) ==
               E_MUP_SUCCEED) ? E_ERR_SUCCESS : E_ERR_FAILED;
    else
        ret = E_ERR_SUCCESS;

out:
    return ret;
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
e_mmgr_errors_t flash_modem_fw(modem_info_t *info, char *comport, bool ch_sw,
                               secur_t *secur, e_modem_fw_error_t *verdict)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mup_interface_t *handle = NULL;
    secur_callback_fptr_t secur_callback = NULL;

    CHECK_PARAM(info, ret, out);
    CHECK_PARAM(secur, ret, out);

    if (E_MUP_SUCCEED != info->mup.initialize(&handle, mup_log)) {
        LOG_ERROR("modem updater initialization failed");
        goto out;
    }

    /* @TODO retrieve modem version via SFI table and remove this static value */
    if (info->mup.check_fw_version(info->fl_conf.run_inj_fls, "XMM7160") !=
        E_MUP_SUCCEED) {
        LOG_ERROR("Bad modem family. Shutdown the modem");
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
        LOG_ERROR("failed to open device");
        goto out;
    }

    char *rnd = NULL;
    size_t len = 0;
    if (E_ERR_SUCCESS == is_file_exists(info->fl_conf.run_rnd_cert, 0)) {
        rnd = info->fl_conf.run_rnd_cert;
        len = strnlen(info->fl_conf.run_rnd_cert, MAX_SIZE_CONF_VAL);
    }

    secur_get_callback(secur, &secur_callback);
    if (E_MUP_SUCCEED !=
        info->mup.config_secur_channel(handle, secur_callback, rnd, len)) {
        LOG_ERROR("failed to configure the secured channel");
        goto out;
    }

    e_mup_err_t err = info->mup.update_fw(&params);
    const char *verdict_str[] = {
#undef X
#define X(a) #a
        MUP_STATE
    };
    LOG_DEBUG("verdict: %s", verdict_str[err]);

    switch (err) {
    case E_MUP_FW_RESTRICTED:
    case E_MUP_SUCCEED:
        *verdict = E_MODEM_FW_SUCCEED;
        ret = E_ERR_SUCCESS;
        break;
    case E_MUP_FAILED:
        restore_nvm(info);
        break;
    case E_MUP_FW_OUTDATED:
        *verdict = E_MODEM_FW_OUTDATED;
        break;
    case E_MUP_FW_CORRUPTED:
        *verdict = E_MODEM_FW_SECURITY_CORRUPTED;
        break;
    case E_MUP_BAD_PARAMETER:
        ret = E_ERR_BAD_PARAMETER;
    }

    if (E_MUP_SUCCEED != info->mup.dispose(handle)) {
        LOG_ERROR("modem updater disposal fails");
        ret = E_ERR_FAILED;
    }

out:
    return ret;
}

/**
 * flash modem nvm
 *
 * @param[in] info modem info
 * @param[in] comport modem communication port for flashing
 * @param[out] verdict provides modem nvm update status
 *
 * @return E_ERR_FAILED if operation fails
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if info, comport or verdict is null
 */
e_mmgr_errors_t flash_modem_nvm(modem_info_t *info, char *comport,
                                e_modem_nvm_error_t *verdict,
                                int *sub_error_code)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mup_interface_t *handle = NULL;
    e_mup_err_t mup_ret = E_MUP_SUCCEED;

    CHECK_PARAM(info, ret, out);
    CHECK_PARAM(comport, ret, out);
    CHECK_PARAM(verdict, ret, out);
    CHECK_PARAM(sub_error_code, ret, out);

    if (E_MUP_SUCCEED != info->mup.initialize(&handle, mup_log)) {
        ret = E_ERR_FAILED;
        LOG_ERROR("modem updater initialization failed");
        goto out;
    }

    mup_nvm_update_params_t params = {
        .handle = handle,
        .mdm_com_port = comport,
        .nvm_file_path = info->fl_conf.nvm_patch,
        .nvm_file_path_len = strnlen(info->fl_conf.nvm_patch,
                                     MAX_SIZE_CONF_VAL),
    };

    if ((mup_ret = info->mup.update_nvm(&params)) != E_MUP_SUCCEED) {
        ret = E_ERR_FAILED;
        *verdict = E_MODEM_NVM_FAIL;
        *sub_error_code = mup_ret;
        LOG_ERROR("modem nvm update failed with error %d", mup_ret);
    } else {
        if (unlink(info->fl_conf.nvm_patch) != 0) {
            LOG_ERROR("couldn't delete %s: %s", info->fl_conf.nvm_patch,
                      strerror(errno));
        }
        /* for now consider a success even if nvm patch not deleted */
        *verdict = E_MODEM_NVM_SUCCEED;
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
 * @param[in] info modem info
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
static e_mmgr_errors_t start_hsic(modem_info_t *info)
{
    return write_to_file(info->hsic_enable_path, SYSFS_OPEN_MODE, "1", 1);
}

/**
 * stop hsic link
 *
 * @param[in] info modem info
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
static e_mmgr_errors_t stop_hsic(modem_info_t *info)
{
    return write_to_file(info->hsic_enable_path, SYSFS_OPEN_MODE, "0", 1);
}

/**
 * restart hsic link
 *
 * @param[in] info modem info
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
static e_mmgr_errors_t restart_hsic(modem_info_t *info)
{
    /* When the HSIC is already UP, writing 1 resets the hsic, It's what we
     * want here. This function only exists for "readability" purpose. */
    return write_to_file(info->hsic_enable_path, SYSFS_OPEN_MODE, "1", 1);
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
static e_mmgr_errors_t regen_fls(modem_info_t *info)
{

    e_mmgr_errors_t ret = E_ERR_FAILED;
    e_mup_err_t mup_err;
    char no_file[2] = "";

    CHECK_PARAM(info, ret, out);

    if ((ret = is_file_exists(info->fl_conf.run_boot_fls, 0)) != E_ERR_SUCCESS) {
        LOG_ERROR("fls file (%s) is missing", info->fl_conf.run_boot_fls);
        goto out;
    }

    remove(info->fl_conf.run_inj_fls);
    LOG_DEBUG("trying to package fls file");

    /* @TODO: add certificate and secur files */
    mup_err = info->mup.gen_fls(info->fl_conf.run_boot_fls,
                                info->fl_conf.run_inj_fls,
                                info->fl_conf.run_path, no_file, no_file);

    if (mup_err == E_MUP_SUCCEED) {
        ret = is_file_exists(info->fl_conf.run_inj_fls, 0);
        if (ret == E_ERR_SUCCESS) {
            LOG_INFO("fls file created successfully (%s)",
                     info->fl_conf.run_inj_fls);
        } else {
            LOG_ERROR("failed to create fls file");
        }
    } else {
        ret = E_ERR_FAILED;
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
e_mmgr_errors_t mdm_warm_reset(modem_info_t *info)
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
e_mmgr_errors_t mdm_cold_reset(modem_info_t *info)
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
e_mmgr_errors_t mdm_down(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(info, ret, out);

    if (info->mdm_link == E_LINK_HSIC)
        stop_hsic(info);

    if (ioctl(info->fd_mcd, MDM_CTRL_POWER_OFF) == -1) {
        ret = E_ERR_FAILED;
        LOG_DEBUG("couldn't shutdown modem: %s", strerror(errno));
    } else {
        LOG_INFO("MODEM ELECTRICALLY SHUTDOWN");
        ret = E_ERR_SUCCESS;
    }

    pm_on_mdm_oos(info);

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
e_mmgr_errors_t mdm_up(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int state;

    CHECK_PARAM(info, ret, out);

    ioctl(info->fd_mcd, MDM_CTRL_GET_STATE, &state);

    if (info->mdm_link == E_LINK_HSIC)
        start_hsic(info);

    if (info->is_flashless) {
        if (state & MDM_CTRL_STATE_OFF) {
            if (ioctl(info->fd_mcd, MDM_CTRL_POWER_ON) == -1) {
                LOG_DEBUG("failed to power on the modem: %s", strerror(errno));
                ret = E_ERR_FAILED;
            }
        } else {
            ret = mdm_cold_reset(info);
        }
    } else if (ioctl(info->fd_mcd, MDM_CTRL_POWER_ON) == -1) {
        LOG_DEBUG("failed to power on the modem: %s", strerror(errno));
        ret = E_ERR_FAILED;
    }

    if (ret == E_ERR_SUCCESS)
        LOG_DEBUG("Modem successfully POWERED-UP");
    else if (info->mdm_link == E_LINK_HSIC)
        stop_hsic(info);

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
e_mmgr_errors_t mdm_get_state(int fd_mcd, e_modem_events_type_t *state)
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
 * @return E_ERR_BAD_PARAMETER if info is NULL
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

/**
 * This function is used to prepare the firmware modem
 *
 * @param [in,out] info modem info context
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 **/
e_mmgr_errors_t mdm_prepare(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    if (info->is_flashless) {
        /* Restore calibration file from backup if missing */
        if (is_file_exists(info->fl_conf.run_cal, 0) != E_ERR_SUCCESS) {
            if (copy_file
                (info->fl_conf.bkup_cal, info->fl_conf.run_cal,
                 FLS_FILE_PERMISSION) != E_ERR_SUCCESS) {
                /* This is not a blocking error case because this can happen in
                 * production when first calib is about to be done. Just raise a
                 * warning. */
                LOG_INFO("No calib could be restored from %s,"
                         " device must be re-calibrated",
                         info->fl_conf.bkup_cal);
            } else {
                LOG_INFO("Calibration file restored from %s",
                         info->fl_conf.bkup_cal);
            }
        }
        /* Restore R&D cert file from backup if missing */
        if (is_file_exists(info->fl_conf.run_rnd_cert, 0) != E_ERR_SUCCESS) {
            if (copy_file
                (info->fl_conf.bkup_rnd_cert, info->fl_conf.run_rnd_cert,
                 FLS_FILE_PERMISSION) != E_ERR_SUCCESS) {
                /* This is not a blocking error case because this can happen in
                 * production when no R&D exist yet. Just raise a warning. */
                LOG_INFO("No R&D cert could be restored from %s,"
                         " R&D cert must be provisioned",
                         info->fl_conf.bkup_rnd_cert);
            } else {
                LOG_INFO("R&D cert file restored from %s",
                         info->fl_conf.bkup_rnd_cert);
            }
        }
        /* re-generates the fls through nvm injection lib if the modem is
         * flashless */
        ret = regen_fls(info);
    }
out:
    return ret;
}

/**
 * This function is used to start the modem IPC link
 *
 * @param [in,out] info modem info context
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 **/
e_mmgr_errors_t mdm_prepare_link(modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    /* restart hsic if the modem is hsic */
    if (info->mdm_link == E_LINK_HSIC)
        restart_hsic(info);
out:
    return ret;
}

/**
 * This function is used to configure modem events after modem restart
 *
 * @param [in,out] info modem info context
 * @param [in] subscribe_cd_ev boolean to define if we should subscribe to
 * core dump event or not
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 **/
e_mmgr_errors_t mdm_subscribe_start_ev(modem_info_t *info, bool subscribe_cd_ev)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    if (info->is_flashless)
        info->polled_states = MDM_CTRL_STATE_FW_DOWNLOAD_READY;
    else
        info->polled_states = MDM_CTRL_STATE_IPC_READY;

    if (subscribe_cd_ev)
        info->polled_states |= MDM_CTRL_STATE_COREDUMP;
    ret = set_mcd_poll_states(info);
out:
    return ret;
}
