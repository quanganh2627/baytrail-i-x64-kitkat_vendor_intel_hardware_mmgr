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

#define MMGR_FW_OPERATIONS
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <linux/hsi_ffl_tty.h>
#include <linux/mdm_ctrl.h>
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

/* switch to MUX timings */
#define STAT_DELAY 250          /* in milliseconds */
#define MAX_TIME_DELAY 4000     /* in milliseconds */
#define MAX_STAT_RETRIES (MAX_TIME_DELAY / STAT_DELAY)

typedef enum e_switch_to_mux_states {
    E_MUX_HANDSHAKE,
    E_MUX_XLOG,
    E_MUX_AT_CMD,
    E_MUX_DRIVER,
} e_switch_to_mux_states_t;

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
e_mmgr_errors_t modem_info_init(const mmgr_configuration_t *config,
                                modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    CHECK_PARAM(info, ret, out);

    info->ev = E_EV_MODEM_OFF;  /* modem is OFF at boot-up */
    info->polled_states = MDM_CTRL_STATE_COREDUMP;
    info->is_flashless = config->is_flashless;
    if (strcmp(config->link_layer, "hsic") == 0)
        info->link = E_LINK_HSIC;
    else
        info->link = E_LINK_HSI;

    if (config->is_flashless)
        modem_info_flashless_config(FLASHLESS_CFG, &info->fl_conf);

    ret = core_dump_init(config, &info->mcdr);
    if (ret != E_ERR_SUCCESS)
        goto out;

    info->fd_mcd = open(MBD_DEV, O_RDWR);
    if (info->fd_mcd == -1) {
        LOG_DEBUG("failed to open Modem Control Driver interface: %s",
                  strerror(errno));
        ret = E_ERR_FAILED;
        goto out;
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
static e_mmgr_errors_t get_panic_id(char *xlog, modem_info_t *info)
{
    const char class_pattern[] = "Trap Class:";
    const char id_pattern[] = "Identification:";
    int class;
    char *end_ptr = NULL;
    char *p_str = NULL;
    e_mmgr_errors_t ret = E_ERR_FAILED;

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

        info->mcdr.panic_id = strtol(p_str, &end_ptr, 10);
        if (p_str == end_ptr)
            goto out;

        LOG_DEBUG("panic id: %d", info->mcdr.panic_id);
        if (info->mcdr.state == E_CD_SUCCEED_WITHOUT_PANIC_ID)
            info->mcdr.state = E_CD_SUCCEED;
        else
            info->mcdr.state = E_CD_FAILED_WITH_PANIC_ID;
        ret = E_ERR_SUCCESS;
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
static e_mmgr_errors_t run_at_xlog(int fd_tty, mmgr_configuration_t *config,
                                   modem_info_t *info)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
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
 * Activate the MUX
 *
 * To activate the MUX this function will do the following step
 *      1. Ping modem port and wait good response
 *      2. Send AT+XLOG to print modem info and get panic id if available
 *      3. Send AT+CMUX command
 *      4. Configure the MUX driver
 *      5. Wait creation of all MUX tty ports
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
e_mmgr_errors_t switch_to_mux(int *fd_tty, mmgr_configuration_t *config,
                              modem_info_t *info, int timeout)
{
    int retry;
    e_mmgr_errors_t ret = E_ERR_BAD_PARAMETER;
    e_switch_to_mux_states_t state;
    struct timespec current, start;
    int remaining_time;

    CHECK_PARAM(fd_tty, ret, out);
    CHECK_PARAM(config, ret, out);
    CHECK_PARAM(info, ret, out);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (state = E_MUX_HANDSHAKE; state != E_MUX_DRIVER; /* none */ ) {
        clock_gettime(CLOCK_MONOTONIC, &current);
        remaining_time = timeout - (current.tv_sec - start.tv_sec);
        if (remaining_time <= 0) {
            LOG_DEBUG("timeout");
            ret = E_ERR_TTY_TIMEOUT;
            goto out;
        }

        switch (state) {
        case E_MUX_HANDSHAKE:
            ret = modem_handshake(*fd_tty, config, remaining_time);
            break;
        case E_MUX_XLOG:
            ret = run_at_xlog(*fd_tty, config, info);
            break;
        case E_MUX_AT_CMD:
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
            /* states are ordered. go to next one */
            state++;
            clock_gettime(CLOCK_MONOTONIC, &start);
            timeout = config->max_retry_time;
        } else if ((ret == E_ERR_TTY_BAD_FD) || (ret == E_ERR_AT_CMD_RESEND)) {
            LOG_DEBUG("reopen tty device: %s", config->modem_port);
            close_tty(fd_tty);
            if ((ret = open_tty(config->modem_port, fd_tty)) != E_ERR_SUCCESS)
                goto out;
        } else {
            ret = E_ERR_FAILED;
            goto out;
        }
    }

    ret = configure_cmux_driver(*fd_tty, config->max_frame_size);
    if (ret != E_ERR_SUCCESS) {
        goto out;
    }

    ret = E_ERR_FAILED;

    /* Wait to be able to open a GSM TTY before sending MODEM_UP to clients (this
       guarantees that the MUX control channel has been established with the modem).

       Will retry for up to MAX_TIME_DELAY milliseconds. */
    LOG_DEBUG("looking for %s", config->waitloop_tty_name);
    for (retry = 0; retry < MAX_STAT_RETRIES; retry++) {
        int tmp_fd;

        if ((tmp_fd = open(config->waitloop_tty_name, O_RDWR)) >= 0) {
            close(tmp_fd);
            ret = E_ERR_SUCCESS;
            break;
        }
        usleep(STAT_DELAY * 1000);
    }
    if (ret != E_ERR_SUCCESS) {
        LOG_ERROR("was not able to open TTY %s", config->waitloop_tty_name);
    } else {
        LOG_DEBUG("opened TTY %s after %d loop(s)", config->waitloop_tty_name,
                  retry);
        /* It's necessary to reset the terminal configuration after MUX init */
        ret = set_termio(*fd_tty);
    }

out:
    return ret;
}
