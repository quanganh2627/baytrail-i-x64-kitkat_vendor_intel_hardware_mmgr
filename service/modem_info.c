/* Modem Manager - modem info source file
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
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/hsi_ffl_tty.h>
#include "at.h"
#include "errors.h"
#include "logs.h"
#include "modem_info.h"
#include "reset_escalation.h"
#include "mux.h"
#include "tty.h"

#define AT_MCDR_PROTOCOL "at@cdd:paramdump()\r"
#define AT_XLOG_GET "AT+XLOG=0\r"
#define AT_XLOG_RESET "AT+XLOG=2\r"
#define AT_XLOG_TIMEOUT 25000
#define AT_ANSWER_SIZE 254

/* give some time to modem to self reset */
#define SELF_RESET_SLEEP 100    /* in ms */

/* switch to MUX timings */
#define STAT_DELAY 250          /* in milliseconds */
#define MAX_TIME_DELAY 4000     /* in milliseconds */
#define MAX_STAT_RETRIES (MAX_TIME_DELAY / STAT_DELAY)

/* @TODO: remove me when Modem Boot Driver will be used */
/* sysfs file to get hangup reason */
#define HANGUP_REASON_SYSFS "parameters/hangup_reasons"
/* sysfs file to launch modem warm reset */
#define RESET_MODEM_SYSFS "parameters/reset_modem"
/* sysfs file to launch modem cold reset */
#define COLD_RESET_MODEM_SYSFS "parameters/cold_reset_modem"
/* sysfs file to power off modem */
#define POWER_OFF_MODEM_SYSFS "parameters/power_off_modem"
/* handle hsi driver type */
#define HSI_DLP_FOLDER_SYSFS "/sys/module/hsi_dlp"
#define HSI_FFL_FOLDER_SYSFS "/sys/module/hsi_ffl_tty"

typedef enum e_switch_to_mux_states {
    E_MUX_HANDSHAKE,
    E_MUX_XLOG,
    E_MUX_CD_PROTOCOL,
    E_MUX_AT_CMD,
    E_MUX_DRIVER,
} e_switch_to_mux_states_t;

/* @TODO: remove me when modem boot driver will be used */
/**
 * detech which type of HSI driver is used
 *
 * @param [in,out] hsi_type type of HSI driver
 *
 * @return E_ERR_BAD_PARAMETER if hsi is NULL
 * @return E_ERR_FAILED if HSI driver not detected
 * @return E_ERR_SUCCESS if successful
 */
static int detect_hsi_driver(e_hsi_type_t *hsi_type)
{
    struct stat st;
    int err;
    int ret = E_ERR_FAILED;

    CHECK_PARAM(hsi_type, ret, out);

    err = stat(HSI_DLP_FOLDER_SYSFS, &st);
    if ((err == 0) && (S_ISDIR(st.st_mode))) {
        LOG_DEBUG("HSI DLP detected");
        *hsi_type = E_HSI_DLP;
        ret = E_ERR_SUCCESS;
        goto out;
    }

    err = stat(HSI_FFL_FOLDER_SYSFS, &st);
    if ((err == 0) && (S_ISDIR(st.st_mode))) {
        LOG_DEBUG("HSI FFL detected");
        *hsi_type = E_HSI_FFL;
        ret = E_ERR_SUCCESS;
        goto out;
    }

    LOG_ERROR("HSI driver not found");
out:
    return ret;
}

/* @TODO: remove me when modem boot driver will be used */
/**
 * build sysfs path regarding the hsi_type
 *
 * @param [in,out] path sysfs path to build
 * @param [in] len size of path
 * @param [in] filename name of the syfs file
 * @param [in] hsi_type type of hsi driver
 *
 * @return E_ERR_BAD_PARAMETER if path or/and filename is/are NULL
 * @return E_ERR_FAILED if HSI driver not detected
 * @return E_ERR_SUCCESS if successful
 */
static int set_sysfs_path(char *path, size_t len, char *filename,
                          e_hsi_type_t hsi_type)
{
    int err;
    int ret = E_ERR_FAILED;

    CHECK_PARAM(path, ret, out);
    CHECK_PARAM(filename, ret, out);

    if (hsi_type == E_HSI_DLP) {
        err = snprintf(path, len, "%s/%s", HSI_DLP_FOLDER_SYSFS, filename);
    } else {
        err = snprintf(path, len, "%s/%s", HSI_FFL_FOLDER_SYSFS, filename);
    }

    if ((err > 0) && ((size_t)err <= len))
        ret = E_ERR_SUCCESS;

out:
    return ret;
}

int get_sysfs_path(modem_info_t *info, e_hsi_path_t hsi_path, char **path)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);
    CHECK_PARAM(path, ret, out);

    if (hsi_path >= E_HSI_PATH_NUM) {
        *path = NULL;
        ret = E_ERR_FAILED;
    } else
        *path = info->hsi_path[hsi_path];

out:
    return ret;
}

/**
 * initialize modem info structure and mcdr
 *
 * @param [in] config mmgr config
 * @param [in,out] info modem info
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_FAILED if mcdr init fails
 * @return E_ERR_SUCCESS if successful
 */
int modem_info_init(const mmgr_configuration_t *config, modem_info_t *info)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(info, ret, out);

    info->ev = E_EV_NONE;
    ret = core_dump_init(config, &info->mcdr);
    if (ret != E_ERR_SUCCESS)
        goto out;

    if ((ret = detect_hsi_driver(&info->hsi_type)) != E_ERR_SUCCESS)
        goto out;
    ret = set_sysfs_path(info->hsi_path[E_HSI_PATH_WARM], PATH_MAX,
                         RESET_MODEM_SYSFS, info->hsi_type);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = set_sysfs_path(info->hsi_path[E_HSI_PATH_COLD], PATH_MAX,
                         COLD_RESET_MODEM_SYSFS, info->hsi_type);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = set_sysfs_path(info->hsi_path[E_HSI_PATH_HANGUP], PATH_MAX,
                         HANGUP_REASON_SYSFS, info->hsi_type);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = set_sysfs_path(info->hsi_path[E_HSI_PATH_POWER_OFF], PATH_MAX,
                         POWER_OFF_MODEM_SYSFS, info->hsi_type);
out:
    return ret;
}

/**
 * get_hangup_reason
 *
 * @param [in] info modem info
 * @param [out] reason hang-up reason
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED if a non decimal value is read
 * @return E_ERR_BAD_PARAMETER if reason is NULL
 */
static int get_hangup_reason(modem_info_t *info, int *reason)
{
    char read_value;
    int fd = 0;
    int ret = E_ERR_FAILED;
    char *path;

    CHECK_PARAM(info, ret, out);
    CHECK_PARAM(reason, ret, out);

    ret = get_sysfs_path(info, E_HSI_PATH_HANGUP, &path);
    if (ret != E_ERR_SUCCESS)
        goto out;

    fd = open(path, O_RDWR);
    if (fd == CLOSED_FD) {
        LOG_ERROR("open of %s failed (%s)", path, strerror(errno));
    } else {
        /* the HANGUP_REASON_SYSFS should contain a decimal value */
        if (read(fd, &read_value, 1) != 1) {
            LOG_ERROR("unable to catch the reason (%s)", strerror(errno));
        } else {
            char *p = NULL;
            *reason = strtol(&read_value, &p, 10);
            if (&read_value != p) {
                /* with the sysfs filestystem, writing the read value
                   performs a reset */
                write(fd, &read_value, 1);
                ret = E_ERR_SUCCESS;
            } else {
                LOG_ERROR("invalid read value");
            }
        }
        close(fd);
    }
out:
    return ret;
}

/**
 * get_panic_id: get the panic_id from the xlog
 *
 * @param [in] xlog modem answer of an xlog command
 * @param [in,out] info modem info
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if xlog or/and info is/are NULL
 * @return E_ERR_FAILED otherwise
 */
static int get_panic_id(char *xlog, modem_info_t *info)
{
    const char class_pattern[] = "Trap Class:";
    const char id_pattern[] = "Identification:";
    int class;
    int panic_id;
    char *end_ptr = NULL;
    char *p_str = NULL;
    int ret = E_ERR_FAILED;

    CHECK_PARAM(xlog, ret, out);
    CHECK_PARAM(info, ret, out);

    /* looking for class pattern */
    p_str = strstr(xlog, class_pattern);
    if (p_str == NULL)
        goto out;

    p_str = strstr(p_str + strlen(class_pattern), "0x");
    if (p_str == NULL)
        goto out;

    class = strtol(p_str, &end_ptr, 16);
    if (p_str == end_ptr)
        goto out;

    if ((class == 0xAAAA) || (class == 0xBBBB) || (class == 0xCCCC)) {
        /* the panic id is extracted only if class id is equal to
           0xAAAA or 0xBBBB or OxCCCC */

        /* looking for panic id */
        p_str = strstr(xlog, id_pattern);
        if (p_str == NULL)
            goto out;

        panic_id = strtol(p_str, &end_ptr, 10);
        if (p_str == end_ptr)
            goto out;

        info->panic_id = panic_id;
        ret = E_ERR_SUCCESS;
        LOG_DEBUG("panic id: %d", info->panic_id);
    }
out:
    return ret;
}

/**
 * Log the self reset reason
 *
 * @param [in] fd_tty tty file descriptor
 * @param [in] config mmgr config
 * @param [in,out] info modem info
 *
 * @return E_ERR_BAD_PARAMETER if config or info is/are NULL
 * @return E_ERR_TTY_BAD_FD
 * @return E_ERR_TTY_POLLHUP if a pollhup occurs
 * @return E_ERR_TTY_ERROR error during write
 * @return E_ERR_TTY_TIMEOUT no response from modem
 * @return E_ERR_AT_CMD_RESEND generic failure
 * @return E_ERR_SUCCESS if successful
 */
static int run_at_xlog(int fd_tty, mmgr_configuration_t *config,
                       modem_info_t *info)
{
    int ret = E_ERR_SUCCESS;
    char data[AT_ANSWER_SIZE + 1];
    int read_size = 0;
    char *p = NULL;

    CHECK_PARAM(config, ret, out_xlog);
    CHECK_PARAM(info, ret, out_xlog);

    tcflush(fd_tty, TCIOFLUSH);

    ret = write_to_tty(fd_tty, AT_XLOG_GET, strlen(AT_XLOG_GET));
    if (ret != E_ERR_SUCCESS)
        goto out_xlog;

    memset(data, 0, AT_ANSWER_SIZE + 1);

    if (info->ev & E_EV_CORE_DUMP) {
        /* set default panic id value */
        info->panic_id = UNKNOWN_PANIC_ID;
    }

    do {
        read_size = AT_ANSWER_SIZE;
        ret = read_from_tty(fd_tty, data, &read_size, AT_READ_MAX_RETRIES);
        data[read_size] = '\0';
        if (ret != E_ERR_SUCCESS)
            goto out_xlog;

        if (read_size > 0) {
            data[read_size] = '\0';
            /* erasing \r characters to improve display */
            while ((p = strchr(data, '\r')) != NULL)
                *p = ' ';
            /* to improve display, do not use LOG_DEBUG macro here */
            LOGD("%s", data);
            if (info->ev & E_EV_CORE_DUMP) {
                if ((ret = get_panic_id(data, info)) == E_ERR_BAD_PARAMETER)
                    goto out_xlog;
            }
        }
    } while (read_size > 0);

    ret = send_at_timeout(fd_tty, AT_XLOG_RESET, strlen(AT_XLOG_RESET),
                          config->max_retry_time);
out_xlog:
    return ret;
}

/**
 * detect the modem core dump protocol
 *
 * @param [in] fd file descriptor
 * @param [in,out] info modem info
 *
 * @return E_ERR_BAD_PARAMETER if info is NULL
 * @return E_ERR_FAILED if protocol not found
 * @return E_ERR_SUCCESS if successful
 */
static int detect_mcdr_protocol(int fd, modem_info_t *info)
{
    int ret = E_ERR_FAILED;
    const char key[] = "ymodemProtocolEnabled=";
    const char disabled[] = "false";
    char data[AT_ANSWER_SIZE + 1];
    int read_size = 0;
    char *p = NULL;

    CHECK_PARAM(info, ret, out);

    ret = write_to_tty(fd, AT_MCDR_PROTOCOL, strlen(AT_MCDR_PROTOCOL));
    if (ret != E_ERR_SUCCESS)
        goto out;

    do {
        read_size = AT_ANSWER_SIZE;
        ret = read_from_tty(fd, data, &read_size, AT_READ_MAX_RETRIES);
        data[read_size] = '\0';
        if (ret != E_ERR_SUCCESS)
            goto out;

        if (read_size > 0) {
            p = strstr(data, key);
            if (p != NULL) {
                if (strncmp(p + strlen(key), disabled, strlen(disabled)) == 0) {
                    LOG_DEBUG("LCDP protocol detected");
                    info->mcdr.protocol = LCDP;
                } else {
                    LOG_DEBUG("YMODEM protocol detected");
                    info->mcdr.protocol = YMODEM;
                }
                ret = E_ERR_SUCCESS;
                break;
            }
        }
    } while (read_size > 0);
out:
    return ret;
}

/**
 * Activate the MUX
 *
 * To activate the MUX this function will do the following step
 *      1. Ping modem port and wait good response
 *      2. Send AT+XLOG to print modem info and get panic id if available
 *      3. Detect core dump protocol
 *      4. Send AT+CMUX command
 *      5. Configure the MUX driver
 *      6. Wait creation of all MUX tty ports
 *
 * @param [in,out] fd_tty modem file descriptor
 * @param [in] config mmgr config
 * @param [in,out] info modem info
 * @param [in] timeout switch to mux timeout
 *
 * @return E_ERR_BAD_PARAMETER if config or info is/are NULL
 * @return E_ERR_TTY_BAD_FD bad file descriptor
 * @return E_ERR_TTY_POLLHUP POLLHUP detected during read
 * @return E_ERR_AT_CMD_RESEND  generic failure
 * @return E_ERR_FAILED bad driver configuration
 * @return E_ERR_TTY_ERROR error during write
 * @return E_ERR_TTY_TIMEOUT no response from modem
 * @return E_ERR_SUCCESS
 */
int switch_to_mux(int *fd_tty, mmgr_configuration_t *config,
                  modem_info_t *info, int timeout)
{
    struct stat st;
    int retry;
    int ret = E_ERR_BAD_PARAMETER;
    e_switch_to_mux_states_t state;
    struct timespec current, start;
    int remaining_time;
    int mask = 0;
    int reason;

    CHECK_PARAM(fd_tty, ret, out);
    CHECK_PARAM(config, ret, out);
    CHECK_PARAM(info, ret, out);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (state = E_MUX_HANDSHAKE; state != E_MUX_DRIVER; /* none */ ) {
        clock_gettime(CLOCK_MONOTONIC, &current);
        remaining_time = timeout - (current.tv_sec - start.tv_sec);
        if (remaining_time <= 0) {
            LOG_DEBUG("timeout");
            info->ev |= mask;
            goto out;
        }

        switch (state) {
        case E_MUX_HANDSHAKE:
            mask = E_EV_MODEM_HANDSHAKE_FAILED;
            ret = modem_handshake(*fd_tty, config, remaining_time);
            break;
        case E_MUX_XLOG:
            mask = 0;
            ret = run_at_xlog(*fd_tty, config, info);
            break;
        case E_MUX_CD_PROTOCOL:
            if (info->mcdr.enabled)
                detect_mcdr_protocol(*fd_tty, info);
            break;
        case E_MUX_AT_CMD:
            mask = E_EV_MODEM_MUX_INIT_FAILED;
            ret = send_at_cmux(*fd_tty, config, remaining_time);
            break;
        case E_MUX_DRIVER:
            /* nothing to do here */
            break;
        default:
            LOG_ERROR("bad state");
            ret = E_ERR_BAD_PARAMETER;
            goto out;
        }

        if (ret == E_ERR_SUCCESS) {
            /* state are ordered. go to next one */
            state++;
            clock_gettime(CLOCK_MONOTONIC, &start);
            timeout = config->max_retry_time;
        } else if ((ret == E_ERR_TTY_BAD_FD) || (ret == E_ERR_AT_CMD_RESEND)) {
            LOG_DEBUG("reopen tty device: %s", config->modem_port);
            close_tty(fd_tty);
            open_tty(config->modem_port, fd_tty);
        } else {
            LOG_ERROR("event: 0x%.2X", mask);
            info->ev |= mask;
            goto out;
        }
    }

    ret = configure_cmux_driver(*fd_tty, config->max_frame_size);
    if (ret != E_ERR_SUCCESS) {
        info->ev |= E_EV_LINE_DISCIPLINE_FAILED;
        goto out;
    }

    /* Wait the mux file to appear on the filesystem.
       We cannot open it yet due to permissions.
       Will retry for up to MAX_STAT_RETRIES seconds. */
    LOG_DEBUG("looking for %s", config->latest_tty_name);
    for (retry = 0; retry < MAX_STAT_RETRIES; retry++) {
        usleep(STAT_DELAY * 1000);
        if (stat(config->latest_tty_name, &st) == 0) {
            ret = E_ERR_SUCCESS;
            break;
        }
    }
    if (ret != E_ERR_SUCCESS) {
        LOG_ERROR("%s does not appear", config->latest_tty_name);
    } else {
        /* It's necessary to reset the terminal configuration after MUX init */
        ret = set_termio(*fd_tty);

        /* Reset the HSI HANGUP reason by reading it. */
        get_hangup_reason(info, &reason);
    }

out:
    return ret;
}

/**
 * Launch retrieve core dump process
 *
 * @param [in] config mmgr config
 * @param [in,out] info modem info
 *
 * @return E_ERR_BAD_PARAMETER if config or/and info is/are NULL
 * @return E_ERR_SUCCESS if successful
 */
int manage_core_dump(mmgr_configuration_t *config, modem_info_t *info)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(config, ret, out);
    CHECK_PARAM(info, ret, out);

    if (!info->mcdr.enabled) {
        info->ev |= E_EV_CORE_DUMP_FAILED;
    } else {
        if (retrieve_core_dump(&info->mcdr) == E_ERR_SUCCESS) {
            LOG_INFO("%s STATE: MODEM SHOULD PERFORM SELF RESET - "
                     "CORE DUMP", MODULE_NAME);
            info->ev |= E_EV_CORE_DUMP_SUCCEED;
        } else {
            LOG_INFO("%s STATE: MODEM RESET INITIATED BY %s - "
                     "CORE DUMP", MODULE_NAME, MODULE_NAME);
            info->ev |= E_EV_CORE_DUMP_FAILED;
        }
    }
out:
    return E_ERR_SUCCESS;
}

/**
 * this function find out if modem must be reset or not according to HSI
 * information and mmgr events
 *
 * @param [in] config mmgr config
 * @param [in,out] info modem info
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if config or/and info is/are NULL
 */
int check_modem_state(mmgr_configuration_t *config, modem_info_t *info)
{
    int ret = E_ERR_SUCCESS;
    int reason = 0;

    CHECK_PARAM(config, ret, out);
    CHECK_PARAM(info, ret, out);

    if (get_hangup_reason(info, &reason) != E_ERR_SUCCESS) {
        LOG_ERROR("CAN'T DETERMINE POLLHUP REASON");
        goto out;
    }

    LOG_VERBOSE("hangup reason: 0x%.2X", reason);
    if (reason & HU_TIMEOUT) {
        LOG_ERROR("%s STATE: HU_TIMEOUT ERROR", MODULE_NAME);
        if ((info->ev & E_EV_MODEM_HANDSHAKE_FAILED) ||
            (info->ev & E_EV_MODEM_MUX_INIT_FAILED)) {
            LOG_DEBUG("Timeout during MUX configuration. "
                      "Skip escalation recovery");
        }
    }
    if (reason & HU_RESET) {
        LOG_INFO("%s STATE: MODEM SELF RESET", MODULE_NAME);
        info->ev |= E_EV_MODEM_SELF_RESET;
        /* give some time to modem to self reset */
        usleep(SELF_RESET_SLEEP);
    }
    if (reason & HU_COREDUMP) {
        LOG_INFO("%s STATE: MODEM CORE DUMP AVAILABLE", MODULE_NAME);
        info->ev |= E_EV_CORE_DUMP;
    }
out:
    return ret;
}
