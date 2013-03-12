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
#include <utils/Log.h>

#define INTEGER(a) (int[]) {a}

/* MMGR default value for configuration */
#define DEF_MODEM_PORT "/dev/ttyIFX0"
#define DEF_SHTDWN_DLC "/dev/gsmtty22"
#define DEF_LATEST_TTY_NAME  "/dev/gsmtty63"
#define DEF_LINK_LAYER "hsi"
#define DEF_DELAY_BEFORE_AT INTEGER(3456)
/* 27.010 5.7.2 max frame size */
#define GPP_MAX_FRAME_SIZE INTEGER(32768)
/* modem max frame size */
#define MODEM_MAX_FRAME_SIZE INTEGER(1509)

/* flashless data */
#define DEF_IS_FLASHLESS INTEGER(false)
#define DEF_BB_PID "0x0452"
#define DEF_BB_VID "0x1519"
#define DEF_FLASH_PID "0x0716"
#define DEF_FLASH_VID "0x8087"

/* Modem recovery */
#define DEF_MODEM_RESET_ENABLE INTEGER(true)
#define DEF_NB_WARM_RESET INTEGER(5)
#define DEF_NB_COLD_RESET INTEGER(1)
#define DEF_NB_PLATFORM_REBOOT INTEGER(1)
#define DEF_MODEM_RESET_DELAY INTEGER(5)        /* in seconds */
#define DEF_MIN_TIME_ISSUE INTEGER(600) /* in seconds */
#define DEF_DELAY_BEFORE_RESET INTEGER(300)     /* in milliseconds */
#define DEF_DELAY_BEFORE_REBOOT INTEGER(3)      /* in seconds */
#define DEF_MAX_RETRY_TIME INTEGER(60)
#define DEF_MAX_TIMEOUT_ACK_COLD INTEGER(1)     /* in seconds */
#define DEF_MAX_TIMEOUT_ACK_SHTDWN INTEGER(1)   /* in seconds */
/* mmgr interface */
#define DEF_NB_ALLOWED_CLIENT INTEGER(12)
/*mcdr default values */
#define DEF_MODEM_CORE_DUMP INTEGER(true)
#define DEF_MCDR_OUTPUT "/logs/modemcrash"
#define DEF_MCDR_DEVICE "/dev/ttyMFD1"
#define DEF_MCDR_BAUDRATE INTEGER(3000000)
#define DEF_MCDR_PID "0x0020"
#define DEF_MCDR_VID "0x1519"
#define DEF_MCDR_PROTOCOL "YMODEM"

/* flashless default params: */
#define DEF_NVM_FILES_PATH "/config/telephony"
#define DEF_FLS_IN "modembinary.fls"
#define DEF_CALIBRATION_PATH "calib.nvm"

#define PRINT_GROUP "------ Group: %s ------\n"

struct set_param;
typedef void *(*read_param) (GKeyFile *, char *, char *, GError **);
typedef void (*copy) (void *dest, void *src);
typedef void (*display) (struct set_param * param);

typedef struct type_setter {
    read_param read;
    size_t size;
    copy init;
    copy copy;
    display display;
} type_setter_t;

typedef struct set_param {
    char *key;
    void *dest;
    void *def;
    type_setter_t set;
} set_param_t;

/**
 * copy an integer default data. This function should be used
 * to initialize an integer or boolean data with a default value declared
 * with define
 *
 * @param [out] dest destination
 * @param [in] src source
 *
 * @return none
 */
static void init_integer(void *dest, void *src)
{
    /* copy the content of the unnamed tab */
    int *in = src;
    int *out = dest;
    *out = *in;
}

/**
 * copy an string data provided by glib
 *
 * @param [out] dest destination
 * @param [in] src source
 *
 * @return none
 */
static void copy_string(void *dest, void *src)
{
    sscanf((char *)src, "%s", (char *)dest);
}

/**
 * copy an integer/boolean data provided by glib
 *
 * @param [out] dest destination
 * @param [in] src source
 *
 * @return none
 */
static void copy_integer(void *dest, void *src)
{
    int *in = src;
    int *out = dest;
    *out = (int)in;
}

/**
 * display a value with its key
 *
 * @param [in] param parameter to display
 *
 * @return none
 */
static void display_integer(set_param_t *param)
{
    int *tmp = param->dest;
    LOGV(PRINT_INTEGER, param->key, *tmp);
}

/**
 * display a value with its key
 *
 * @param [in] param parameter to display
 *
 * @return none
 */
static void display_boolean(set_param_t *param)
{
    bool *tmp = param->dest;
    const char *state[] = { "DISABLED", "ENABLED" };
    LOGV(PRINT_STRING, param->key, state[*tmp]);
}

/**
 * display a value with its key
 *
 * @param [in] param parameter to display
 *
 * @return none
 */
static void display_string(set_param_t *param)
{
    LOGV(PRINT_STRING, param->key, (char *)param->dest);
}

/**
 * This function initialize one parameter. The variable is
 * configured from the configuration file. If the file doesn't exist or
 * if the parameter key/group is not defined, the default value is used
 *
 * @param [in] fd configuration file
 * @param [in] grp group configuration file group
 * @param [in] param list of param to configure
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if parameters or config_file is NULL
 */
static e_mmgr_errors_t set_param(GKeyFile *fd, char *grp, set_param_t *param)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    GError *gerror = NULL;

    void *src = NULL;

    CHECK_PARAM(grp, ret, out);
    CHECK_PARAM(param, ret, out);
    CHECK_PARAM(param->set.init, ret, out);
    CHECK_PARAM(param->set.read, ret, out);
    CHECK_PARAM(param->set.copy, ret, out);
    CHECK_PARAM(param->set.display, ret, out);

    /* init value */
    memset(param->dest, 0, param->set.size);
    param->set.init(param->dest, param->def);

    if (fd != NULL) {
        src = param->set.read(fd, grp, param->key, &gerror);

        if (gerror == NULL) {
            param->set.copy(param->dest, src);
            ret = E_ERR_SUCCESS;
        } else {
            LOG_ERROR("READ ERROR: (%s)", gerror->message);
            g_error_free(gerror);
        }
    }
    param->set.display(param);
out:
    return ret;
}

/**
 * This function initialize a list of parameters. Variables are
 * configured from the configuration file. If the file doesn't exist or
 * if the parameter key/group is not defined, the default value is used
 *
 * @param [in] fd configuration file
 * @param [in] grp group configuration file group
 * @param [in] param list of param to configure
 * @param [in] size size of list
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if parameters or config_file is NULL
 */
static e_mmgr_errors_t parse(GKeyFile *fd, char *grp, set_param_t *param,
                             size_t size)
{
    size_t i;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    /* do not check fd here */
    CHECK_PARAM(grp, ret, out);
    CHECK_PARAM(param, ret, out);

    LOGV(PRINT_GROUP, grp);
    for (i = 0; i < size; i++) {
        set_param(fd, grp, &param[i]);
    }
out:
    return ret;
}

/**
 * This function initialize Modem Manager parameters. The variables are
 * configured from the configuration file. If the file doesn't exist or
 * if the paramater is not defined, the default value is used
 *
 * @param [in,out] params mmgr parameters
 * @param [in] config_file configuration file path
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if parameters or config_file is NULL
 * @return E_ERR_MISSING_FILE if config_file is missing
 *                            (default values are used)
 */
e_mmgr_errors_t mmgr_configure(mmgr_configuration_t *params,
                               const char *config_file)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(config_file, ret, out);
    CHECK_PARAM(params, ret, out);

    GKeyFile *fd = NULL;
    GError *gerror = NULL;

    type_setter_t string = {.read = (read_param) g_key_file_get_string,
        .size = MAX_SIZE_CONF_VAL,.init = copy_string,
        .copy = copy_string,.display = display_string
    };
    type_setter_t integer = {.read = (read_param) g_key_file_get_integer,
        .size = sizeof(int),.init = init_integer,
        .copy = copy_integer,.display = display_integer
    };
    type_setter_t boolean = {.read = (read_param) g_key_file_get_boolean,
        .size = sizeof(bool),.init = init_integer,
        .copy = copy_integer,.display = display_boolean
    };

    /* special test case: */
    int *max_frame_size = (MODEM_MAX_FRAME_SIZE < GPP_MAX_FRAME_SIZE) ?
        MODEM_MAX_FRAME_SIZE : GPP_MAX_FRAME_SIZE;

    set_param_t gnl[] = {
        {.key = "ModemPort",.dest = &params->modem_port,.def =
         DEF_MODEM_PORT,.set = string},
        {.key = "ShutdownDLC",.dest = &params->shtdwn_dlc,.def =
         DEF_SHTDWN_DLC,.set = string},
        {.key = "LatestTTYName",.dest = &params->latest_tty_name,
         .def = DEF_LATEST_TTY_NAME,.set = string},
        {.key = "LinkLayer",.dest = &params->link_layer,
         .def = DEF_LINK_LAYER,.set = string},
        {.key = "DelayBeforeFirstAt",.dest = &params->delay_before_at,
         .def = DEF_DELAY_BEFORE_AT,.set = integer},
        {.key = "MaxFrameSize",.dest = &params->max_frame_size,
         .def = max_frame_size,.set = integer},
        {.key = "isFlashLess",.dest = &params->is_flashless,
         .def = DEF_IS_FLASHLESS,.set = boolean},
        {.key = "BaseBandPid",.dest = &params->bb_pid,.def = DEF_BB_PID,
         .set = string},
        {.key = "BaseBandVid",.dest = &params->bb_vid,.def = DEF_BB_VID,
         .set = string},
        {.key = "FlashPid",.dest = &params->flash_pid,
         .def = DEF_FLASH_PID,.set = string},
        {.key = "FlashVid",.dest = &params->flash_vid,
         .def = DEF_FLASH_VID,.set = string},
    };

    set_param_t recov[] = {
        {.key = "ModemResetEnable",.dest = &params->modem_reset_enable,.def =
         DEF_MODEM_RESET_ENABLE,.set = boolean},
        {.key = "MaxModemWarmReset",.dest = &params->nb_warm_reset,.def =
         DEF_NB_WARM_RESET,.set = integer},
        {.key = "MaxModemColdReset",.dest = &params->nb_cold_reset,.def =
         DEF_NB_COLD_RESET,.set = integer},
        {.key = "MaxPlatformReboot",.dest = &params->nb_platform_reboot,.def =
         DEF_NB_PLATFORM_REBOOT,.set = integer},
        {.key = "ModemResetDelay",.dest = &params->modem_reset_delay,.def =
         DEF_MODEM_RESET_DELAY,.set = integer},
        {.key = "MinTimeIssue",.dest = &params->min_time_issue,.def =
         DEF_MIN_TIME_ISSUE,.set = integer},
        {.key = "DelayBeforeReset",.dest = &params->delay_before_reset,.def =
         DEF_DELAY_BEFORE_RESET,.set = integer},
        {.key = "DelayBeforeReboot",.dest = &params->delay_before_reboot,.def =
         DEF_DELAY_BEFORE_REBOOT,.set = integer},
        {.key = "MaximumRetryTime",.dest = &params->max_retry_time,.def =
         DEF_MAX_RETRY_TIME,.set = integer},
        {.key = "MaxAckColdReset",.dest = &params->timeout_ack_cold,.def =
         DEF_MAX_TIMEOUT_ACK_COLD,.set = integer},
        {.key = "MaxAckShtdwn",.dest = &params->timeout_ack_shtdwn,.def =
         DEF_MAX_TIMEOUT_ACK_SHTDWN,.set = integer},
    };

    set_param_t interface[] = {
        {.key = "NumberOfAllowedClient",.dest = &params->max_clients,.def =
         DEF_NB_ALLOWED_CLIENT,.set = integer},
    };

    set_param_t mcdr[] = {
        {.key = "ModemCoreDumpEnable",.dest =
         &params->modem_core_dump_enable,.def = DEF_MODEM_CORE_DUMP,.set =
         boolean},
        {.key = "OutpoutPath",.dest = &params->mcdr_path,.def =
         DEF_MCDR_OUTPUT,.set = string},
        {.key = "McdrPort",.dest = &params->mcdr_device,.def =
         DEF_MCDR_DEVICE,.set = string},
        {.key = "Baudrate",.dest = &params->mcdr_baudrate,.def =
         DEF_MCDR_BAUDRATE,.set = integer},
        {.key = "McdrPid",.dest = &params->mcdr_pid,.def =
         DEF_MCDR_PID,.set = string},
        {.key = "McdrVid",.dest = &params->mcdr_vid,.def =
         DEF_MCDR_VID,.set = string},
        {.key = "McdrProtocol",.dest = &params->mcdr_protocol,.def =
         DEF_MCDR_PROTOCOL,.set = string},
    };

    LOG_DEBUG("filename: %s", config_file);
    if (access(config_file, F_OK) != 0) {
        LOG_ERROR("config file is missing. Keeping default values");
        ret = E_ERR_MISSING_FILE;
    } else {
        fd = g_key_file_new();
        g_key_file_load_from_file(fd, config_file, G_KEY_FILE_NONE, &gerror);
        if (gerror != NULL) {
            LOG_ERROR("%s", gerror->message);
            g_error_free(gerror);
        }
    }
    parse(fd, "GENERAL", gnl, sizeof(gnl) / sizeof(*gnl));
    parse(fd, "RECOVERY", recov, sizeof(recov) / sizeof(*recov));
    parse(fd, "MMGR_INTERFACE", interface,
          sizeof(interface) / sizeof(*interface));
    parse(fd, "MCDR", mcdr, sizeof(mcdr) / sizeof(*mcdr));

out:
    return ret;
}

/**
 * Read the Modem Manager configuration file related to flashless modem
 * and update the structure
 *
 * @param [in] config_file configuration file path
 * @param [out] fls_in fls input file
 * @param [out] fls_out fls output file
 * @param [out] cal calibration NVM file
 * @param [out] nvm_path nvm path folder
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if config_file or param is NULL
 * @return E_ERR_MISSING_FILE if config_file is missing
 */
e_mmgr_errors_t modem_info_flashless_config(char *config_file, char *fls_in,
                                            char *fls_out, char *cal,
                                            char *nvm_path)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(config_file, ret, out);
    CHECK_PARAM(fls_in, ret, out);
    CHECK_PARAM(fls_out, ret, out);
    CHECK_PARAM(cal, ret, out);
    CHECK_PARAM(nvm_path, ret, out);

    char tmp_fls[MAX_SIZE_CONF_VAL];
    char tmp_cal[MAX_SIZE_CONF_VAL];

    type_setter_t string = {.read = (read_param) g_key_file_get_string,
        .size = MAX_SIZE_CONF_VAL,.init = copy_string,
        .copy = copy_string,.display = display_string
    };

    GKeyFile *fd = NULL;
    GError *gerror = NULL;

    set_param_t list[] = {
        {.key = "Binary",.dest = tmp_fls,.def = DEF_FLS_IN,.set = string},
        {.key = "Calibration",.dest = tmp_cal,.def =
         DEF_CALIBRATION_PATH,.set = string},
        {.key = "Folder",.dest = nvm_path,.def =
         DEF_NVM_FILES_PATH,.set = string},
    };

    LOG_DEBUG("filename: %s", config_file);
    if (access(config_file, F_OK) != 0) {
        LOG_ERROR("config file is missing. Keeping default values");
        ret = E_ERR_MISSING_FILE;
    } else {
        fd = g_key_file_new();
        g_key_file_load_from_file(fd, config_file, G_KEY_FILE_NONE, &gerror);
        if (gerror != NULL) {
            LOG_ERROR("%s", gerror->message);
            g_error_free(gerror);
        }
    }
    parse(fd, "RUNTIME", list, sizeof(list) / sizeof(*list));

    /* set full path */
    snprintf(fls_in, MAX_SIZE_CONF_VAL - 1, "%s/%s", nvm_path, tmp_fls);
    snprintf(cal, MAX_SIZE_CONF_VAL - 1, "%s/%s", nvm_path, tmp_cal);

    memset(fls_out, 0, MAX_SIZE_CONF_VAL);
    snprintf(fls_out, MAX_SIZE_CONF_VAL - 1, "%s.out", fls_in);
    LOGV(PRINT_STRING, "fls_out", fls_out);
out:
    return ret;
}
