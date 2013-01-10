/* Modem Manager - at source file
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

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include <linux/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "at.h"
#include "errors.h"
#include "logs.h"
#include "tty.h"

#define AT_TIMEOUT 2500
#define AT_SIZE 20

/**
 * Send an AT command to a tty devices
 *
 * @param [in] fd tty file descriptor
 * @param [in] command at command to send
 * @param [in] command_size length of command
 *
 * @return E_ERR_SUCCESS command sends and 'OK' received
 * @return E_ERR_AT_CMD_RESEND generic failure. Command to resend
 * @return E_ERR_TTY_POLLHUP POLLHUP detected during read
 * @return E_ERR_TTY_BAD_FD if a bad file descriptor is provided
 * @return E_ERR_BAD_PARAMETER if data is NULL
 */
static int send_at(int fd, const char *command, int command_size)
{
    int ret;
    int data_size = AT_SIZE;
    char data[AT_SIZE + 1];

    CHECK_PARAM(command, ret, failure);

    /* Send AT command to modem */
    LOG_DEBUG("Send of %s", command);
    tcflush(fd, TCIOFLUSH);
    ret = write_to_tty(fd, command, command_size);
    if (ret != E_ERR_SUCCESS)
        goto failure;

    LOG_DEBUG("Wait answer...");
    for (;;) {

        /* Give time to receive response or POLLHUP. Timing diagram shows
           200 ms timeout for CAREADY and 500 ms timeout to receive OK.
           Instead of having two timeouts (one for 200ms and one for 300ms),
           make one timeout value of 500 ms. This one timeout should cover
           both possible negative outcomes.
           Note: Per request poll timeout has now been increased to 2.5s
           because HSI TTY_HANGUP_DELAY is 2s */
        ret = wait_for_tty_event(fd, AT_TIMEOUT);
        if (ret != E_ERR_SUCCESS) {
            if (ret != E_ERR_TTY_POLLHUP)
                ret = E_ERR_AT_CMD_RESEND;
            goto failure;
        }

        /* Read response data but give up after AT_READ_MAX_RETRIES tries */
        ret = read_from_tty(fd, data, &data_size, AT_READ_MAX_RETRIES);
        data[data_size] = '\0';
        if (ret != E_ERR_SUCCESS) {
            if (ret != E_ERR_TTY_BAD_FD)
                ret = E_ERR_AT_CMD_RESEND;
            goto failure;
        }

        /* Did we get an "OK" back? */
        if (strstr(data, "OK")) {
            LOG_DEBUG("OK received");
            ret = E_ERR_SUCCESS;
            break;
        } else if (strstr(data, "PBREADY")) {
            LOG_DEBUG("PBREADY received");
            continue;
        } else {
            LOG_ERROR("Wrong anwser (%s)", data);
            ret = E_ERR_AT_CMD_RESEND;
            break;
        }
    }                           /* Loop waiting answer */

    tcflush(fd, TCIFLUSH);
failure:
    return ret;
}

/**
 * Try to send an AT command to modem with timeout
 * Timeout can't be less than AT_TIMEOUT
 *
 * @param [in] fd_tty tty file descriptor
 * @param [in] at_cmd AT command to send
 * @param [in] at_cmd_size AT command size
 * @param [in] timeout timeout (in seconds)
 *
 * @return E_ERR_SUCCESS command sends and 'OK' received
 * @return E_ERR_TTY_POLLHUP POLLHUP detected during read
 * @return E_ERR_AT_CMD_RESEND generic failure. Command to resend
 * @return E_ERR_TTY_BAD_FD bad file descriptor
 * @return E_ERR_BAD_PARAMETER if at_cmd is NULL
 */
int send_at_timeout(int fd_tty, const char *at_cmd, int at_cmd_size,
                    int timeout)
{
    struct timespec start;
    struct timespec current;
    struct timespec end;
    int err;

    CHECK_PARAM(at_cmd, err, out);

    clock_gettime(CLOCK_MONOTONIC, &start);
    end = start;
    end.tv_sec += timeout;

    /* Send AT until we get a valid response from modem,
       or after timeout (in seconds) of trying */
    do {
        err = send_at(fd_tty, at_cmd, at_cmd_size);
        if ((err == E_ERR_TTY_BAD_FD) || (err == E_ERR_TTY_POLLHUP) ||
            (err == E_ERR_BAD_PARAMETER))
            goto out;

        if (err == E_ERR_SUCCESS) {
            break;
        } else {
            sleep(1);
            clock_gettime(CLOCK_MONOTONIC, &current);
        }
    } while (current.tv_sec < end.tv_sec);

    if (err == E_ERR_AT_CMD_RESEND)
        LOG_ERROR("Invalid or no response from modem");

out:
    return err;
}
