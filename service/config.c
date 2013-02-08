/* Modem Manager - configure source file
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

#include <glib.h>
#include <unistd.h>
#include "errors.h"
#include "logs.h"
#include "config.h"

/* MMGR default value for configuration */
#define DEF_MODEM_PORT               "/dev/ttyIFX0"
#define DEF_LATEST_TTY_NAME          "/dev/gsmtty63"
#define DEF_DELAY_BEFORE_AT          10
/* 27.010 5.7.2 max frame size */
#define GPP_MAX_FRAME_SIZE           32768
/* modem max frame size */
#define MODEM_MAX_FRAME_SIZE         1509
/* Modem recovery */
#define DEF_MODEM_RESET_ENABLE       true
#define DEF_MODEM_CORE_DUMP          true
#define DEF_NB_WARM_RESET            5
#define DEF_MODEM_COLD_RESET_ENABLE  true
#define DEF_NB_COLD_RESET            1
#define DEF_PLATFORM_REBOOT_ENABLE   true
#define DEF_NB_PLATFORM_REBOOT       1
#define DEF_MODEM_RESET_DELAY        5  /* in seconds */
#define DEF_MIN_TIME_ISSUE           600        /* in seconds */
#define DEF_DELAY_BEFORE_RESET       300        /* in milliseconds */
#define DEF_DELAY_BEFORE_REBOOT      3  /* in seconds */
#define DEF_MAX_RETRY_TIME           60
/* power saving */
#define DEF_DELAY_BEFORE_MODEM_SHUTDOWN 600     /* in seconds */
/* mmgr interface */
#define DEF_NB_ALLOWED_CLIENT        12
#define DEF_TIME_BANNED              600
#define DEF_REQUESTS_BANNED          128

#define SET_STRING_PARAM(dest, src) do { \
    strncpy(dest, src, MAX_SIZE_CONF_VAL + 1); \
    dest[MAX_SIZE_CONF_VAL] = '\0'; \
} while (0);

#define SET_INTEGER_PARAM(dest, src) do { \
    *dest = src; \
} while (0);

#define GET_VALUE(fd, group, key, dest, func, copy, type, print, err)  do { \
    GError *gerror = NULL; \
    if ((fd == NULL) || (group == NULL) || (key == NULL) || (dest == NULL)) { \
        LOG_ERROR("At least one NULL parameter"); \
        err = E_ERR_BAD_PARAMETER; \
    } else { \
        type read = func(fd, group, key, &gerror); \
        if (gerror != NULL) { \
            g_error_free(gerror); \
            LOG_ERROR("READ ERROR: (%s)", gerror->message); \
        } else { \
            copy(dest, read); \
            LOG_CONFIG("{group= %s ; key= %s} = " print, group, key, dest); \
        } \
        err = E_ERR_SUCCESS; \
    } \
} while (0);

#define PRINT_GROUP "------ Group: %s ------\n"

/**
 * get boolean value from file
 *
 * @param [in] fd file descriptor
 * @param [in] group configuration file group
 * @param [in] key value key
 * @param [out] dest destination
 *
 * @return E_ERR_BAD_PARAMETER if config_file or param is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t get_boolean(GKeyFile *fd, const char *group,
                                   const char *key, bool *dest)
{
    int err;
    GET_VALUE(fd, group, key, dest, g_key_file_get_boolean, SET_INTEGER_PARAM,
              bool, "%d", err);
    return err;
}

/**
 * get integer value from file
 *
 * @param [in] fd file descriptor
 * @param [in] group configuration file group
 * @param [in] key value key
 * @param [out] dest destination
 *
 * @return E_ERR_BAD_PARAMETER if config_file or param is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t get_integer(GKeyFile *fd, const char *group,
                                   const char *key, int *dest)
{
    int err;
    GET_VALUE(fd, group, key, dest, g_key_file_get_integer, SET_INTEGER_PARAM,
              int, "%d", err);
    return err;
}

/**
 * get string value from file
 *
 * @param [in] fd file descriptor
 * @param [in] group configuration file group
 * @param [in] key value key
 * @param [out] dest destination
 *
 * @return E_ERR_BAD_PARAMETER if config_file or param is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t get_string(GKeyFile *fd, const char *group,
                                  const char *key, char *dest)
{
    int err;
    GET_VALUE(fd, group, key, dest, g_key_file_get_string, SET_STRING_PARAM,
              char *, "%s", err);
    return err;
}

/**
 * Read the Modem Manager configuration file and update the structure
 *
 * @param [in] config_file configuration file path
 * @param [in,out] param mmgr parameters
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if config_file or param is NULL
 * @return E_ERR_MISSING_FILE if config_file is missing
 */
static e_mmgr_errors_t read_config_file(const char *config_file,
                                        mmgr_configuration_t *param)
{
    int err = E_ERR_SUCCESS;
    const char *state[] = { "DISABLED", "ENABLED" };

    const char gnl_grp[] = "GENERAL";
    const char modem_port_key[] = "ModemPort";
    const char latest_tty_name_key[] = "LatestTTYName";
    const char delay_at_key[] = "DelayBeforeFirstAt";
    const char max_frame_size_key[] = "MaxFrameSize";

    const char recov_grp[] = "RECOVERY";
    const char modem_reset_enable_key[] = "ModemResetEnable";
    const char mcdr_enable_key[] = "ModemCoreDumpEnable";
    const char nb_warm_reset_key[] = "MaxModemWarmReset";
    const char cold_reset_enabled_key[] = "ModemColdResetEnable";
    const char nb_cold_reset_key[] = "MaxModemColdReset";
    const char reboot_enabled_key[] = "PlatformRebootEnable";
    const char nb_reboot_key[] = "MaxPlatformReboot";
    const char reset_delay_key[] = "ModemResetDelay";
    const char min_time_issue_key[] = "MinTimeIssue";
    const char delay_reset_key[] = "DelayBeforeReset";
    const char delay_reboot_key[] = "DelayBeforeReboot";
    const char max_retry_time_key[] = "MaximumRetryTime";

    const char power_grp[] = "POWER";
    const char delay_before_mshutdown_key[] = "DelayBeforeModemShutdown";

    const char interface_grp[] = "MMGR_INTERFACE";
    const char max_clients_key[] = "NumberOfAllowedClient";
    const char time_banned_key[] = "TimeBeforeBeingBanned";
    const char request_banned_key[] = "RequestsBeforeBeingBanned";

    GKeyFile *fd = g_key_file_new();
    GError *gerror = NULL;

    CHECK_PARAM(config_file, err, out);
    CHECK_PARAM(param, err, out);

    LOG_DEBUG("filename: %s", config_file);
    if (access(config_file, F_OK) != 0) {
        LOG_ERROR("config file is missing. Keeping default values");
        err = E_ERR_MISSING_FILE;
        goto out;
    }

    g_key_file_load_from_file(fd, config_file, G_KEY_FILE_NONE, &gerror);
    if (gerror != NULL) {
        LOG_ERROR("%s", gerror->message);
        g_error_free(gerror);
    }

    get_string(fd, gnl_grp, modem_port_key, param->modem_port);
    get_string(fd, gnl_grp, latest_tty_name_key, param->latest_tty_name);
    get_integer(fd, gnl_grp, delay_at_key, &param->delay_before_at);
    get_integer(fd, gnl_grp, max_frame_size_key, &param->max_frame_size);

    get_boolean(fd, recov_grp, modem_reset_enable_key,
                &param->modem_reset_enable);
    get_boolean(fd, recov_grp, mcdr_enable_key, &param->modem_core_dump_enable);
    get_integer(fd, recov_grp, reset_delay_key, &param->modem_reset_delay);
    get_integer(fd, recov_grp, nb_warm_reset_key, &param->nb_warm_reset);
    get_boolean(fd, recov_grp, cold_reset_enabled_key,
                &param->modem_cold_reset_enable);
    get_integer(fd, recov_grp, nb_cold_reset_key, &param->nb_cold_reset);
    get_boolean(fd, recov_grp, reboot_enabled_key,
                &param->platform_reboot_enable);
    get_integer(fd, recov_grp, nb_reboot_key, &param->nb_platform_reboot);
    get_integer(fd, recov_grp, min_time_issue_key, &param->min_time_issue);
    get_integer(fd, recov_grp, delay_reset_key, &param->delay_before_reset);
    get_integer(fd, recov_grp, delay_reboot_key, &param->delay_before_reboot);
    get_integer(fd, recov_grp, max_retry_time_key, &param->max_retry_time);

    get_integer(fd, power_grp, delay_before_mshutdown_key,
                &param->delay_before_modem_shtdwn);

    get_integer(fd, interface_grp, max_clients_key, &param->max_clients);
    get_integer(fd, interface_grp, time_banned_key, &param->time_banned);
    get_integer(fd, interface_grp, request_banned_key,
                &param->max_requests_banned);

    g_key_file_free(fd);
out:
    LOG_DEBUG("%s parameters:\n"
              PRINT_GROUP
              PRINT_STRING
              PRINT_STRING
              PRINT_INTEGER
              PRINT_INTEGER
              PRINT_GROUP
              PRINT_BOOLEAN
              PRINT_BOOLEAN
              PRINT_INTEGER
              PRINT_BOOLEAN
              PRINT_INTEGER
              PRINT_BOOLEAN
              PRINT_INTEGER
              PRINT_INTEGER
              PRINT_INTEGER
              PRINT_INTEGER
              PRINT_INTEGER
              PRINT_INTEGER
              PRINT_GROUP
              PRINT_INTEGER
              PRINT_GROUP PRINT_INTEGER PRINT_INTEGER PRINT_INTEGER,
              /* feed it: */
              MODULE_NAME,
              gnl_grp,
              modem_port_key, param->modem_port,
              latest_tty_name_key, param->latest_tty_name,
              delay_at_key, param->delay_before_at,
              max_frame_size_key, param->max_frame_size,
              recov_grp,
              modem_reset_enable_key, state[param->modem_reset_enable],
              mcdr_enable_key, state[param->modem_core_dump_enable],
              nb_warm_reset_key, param->nb_warm_reset,
              cold_reset_enabled_key, state[param->modem_cold_reset_enable],
              nb_cold_reset_key, param->nb_cold_reset,
              reboot_enabled_key, state[param->platform_reboot_enable],
              nb_reboot_key, param->nb_platform_reboot,
              reset_delay_key, param->modem_reset_delay,
              min_time_issue_key, param->min_time_issue,
              delay_reset_key, param->delay_before_reset,
              delay_reboot_key, param->delay_before_reboot,
              max_retry_time_key, param->max_retry_time,
              power_grp,
              delay_before_mshutdown_key, param->delay_before_modem_shtdwn,
              interface_grp,
              max_clients_key, param->max_clients,
              time_banned_key, param->time_banned,
              request_banned_key, param->max_requests_banned);
    return err;
}

/**
 * initialize the Modem Manager parameters with default values
 *
 * @param [in,out] parameters mmgr parameters
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if parameters is NULL
 */
static e_mmgr_errors_t set_default_values(mmgr_configuration_t *parameters)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int max_frame_size = (MODEM_MAX_FRAME_SIZE < GPP_MAX_FRAME_SIZE) ?
        MODEM_MAX_FRAME_SIZE : GPP_MAX_FRAME_SIZE;

    CHECK_PARAM(parameters, ret, out);

    LOG_CONFIG("Setting default values");
    /* general */
    SET_STRING_PARAM(parameters->modem_port, DEF_MODEM_PORT);
    SET_STRING_PARAM(parameters->latest_tty_name, DEF_LATEST_TTY_NAME);
    parameters->delay_before_at = DEF_DELAY_BEFORE_AT;
    parameters->max_frame_size = max_frame_size;
    /* modem recovery parameters */
    parameters->modem_reset_enable = DEF_MODEM_RESET_ENABLE;
    parameters->modem_core_dump_enable = DEF_MODEM_CORE_DUMP;
    parameters->nb_warm_reset = DEF_NB_WARM_RESET;
    parameters->modem_cold_reset_enable = DEF_MODEM_COLD_RESET_ENABLE;
    parameters->nb_cold_reset = DEF_NB_COLD_RESET;
    parameters->platform_reboot_enable = DEF_PLATFORM_REBOOT_ENABLE;
    parameters->nb_platform_reboot = DEF_NB_PLATFORM_REBOOT;
    parameters->modem_reset_delay = DEF_MODEM_RESET_DELAY;
    parameters->min_time_issue = DEF_MIN_TIME_ISSUE;
    parameters->delay_before_reset = DEF_DELAY_BEFORE_RESET;
    parameters->delay_before_reboot = DEF_DELAY_BEFORE_REBOOT;
    parameters->delay_before_modem_shtdwn = DEF_DELAY_BEFORE_MODEM_SHUTDOWN;
    parameters->max_retry_time = DEF_MAX_RETRY_TIME;
    /* power saving */
    parameters->delay_before_modem_shtdwn = DEF_DELAY_BEFORE_MODEM_SHUTDOWN;
    /* interface */
    parameters->max_clients = DEF_NB_ALLOWED_CLIENT;
    parameters->time_banned = DEF_TIME_BANNED;
    parameters->max_requests_banned = DEF_REQUESTS_BANNED;
out:
    return ret;
}

/**
 * This function initialize Modem Manager parameters. The variables are
 * configured from the configuration file. If the file doesn't exist or
 * if the paramater is not defined, the default value is used
 *
 * @param [in,out] parameters mmgr parameters
 * @param [in] config_file configuration file path
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if parameters or config_file is NULL
 * @return E_ERR_MISSING_FILE if config_file is missing
 *                            (default values are used)
 */
e_mmgr_errors_t mmgr_configure(mmgr_configuration_t *parameters,
                               const char *config_file)
{
    int ret;

    CHECK_PARAM(parameters, ret, out_mmgr_init);
    CHECK_PARAM(config_file, ret, out_mmgr_init);

    ret = set_default_values(parameters);
    if (ret != E_ERR_SUCCESS)
        goto out_mmgr_init;
    ret = read_config_file(config_file, parameters);
out_mmgr_init:
    return ret;
}
