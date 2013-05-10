/* Modem Manager - tty source file
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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include "errors.h"
#include "logs.h"
#include "tty.h"

#define MAX_OPEN_RETRY 5

/**
 * add fd to epoll
 *
 * @param [out] epollfd epoll fd
 * @param [in] fd file descriptor
 * @param [in] events events to catch
 *
 * @return E_ERR_BAD_PARAMETER clients is NULL
 * @return E_ERR_FAILED initialization fails
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t add_fd_ev(int epollfd, int fd, int events)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    struct epoll_event ev;

    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        LOG_ERROR("Failed to add fd: (%s)", strerror(errno));
        ret = E_ERR_FAILED;
    }

    return ret;
}

e_mmgr_errors_t init_ev_hdler(int *epollfd)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(epollfd, ret, out);

    *epollfd = epoll_create(1);
    if (*epollfd == -1) {
        LOG_ERROR("epoll initialization failed");
        ret = E_ERR_FAILED;
    }
out:
    return ret;
}

/**
 * wait for an event on tty
 *
 * @param [in] fd file descriptor
 * @param [in] timeout timeout
 *
 * @return E_ERR_TTY_ERROR if an unexpected event occurs or poll failed
 * @return E_ERR_TTY_TIMEOUT if any event occurs
 * @return E_ERR_TTY_POLLHUP if a pollhup occurs
 * @return E_ERR_FAILED if epoll create fails
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t wait_for_tty_event(int fd, int timeout)
{
    struct epoll_event ev;
    int epollfd;
    int err;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    if ((ret = init_ev_hdler(&epollfd)) != E_ERR_SUCCESS)
        goto out;

    ret = add_fd_ev(epollfd, fd, EPOLLIN | EPOLLHUP);
    if (ret != E_ERR_SUCCESS)
        goto out;

    err = epoll_wait(epollfd, &ev, 1, timeout);
    if (err > 0) {
        if (ev.events & EPOLLHUP) {
            LOG_VERBOSE("POLLHUP received");
            ret = E_ERR_TTY_POLLHUP;
        } else if (ev.events & EPOLLIN) {
            LOG_VERBOSE("Received response data");
        } else {
            LOG_ERROR("Unexpected event (%d)", ev.events);
            ret = E_ERR_TTY_ERROR;
        }
    } else if (err == 0) {
        LOG_ERROR("WAIT ANSWER TIMEOUT");
        ret = E_ERR_TTY_TIMEOUT;
    } else {
        LOG_ERROR("Poll failed (%s)", strerror(errno));
        ret = E_ERR_TTY_ERROR;
    }
out:
    return ret;
}

/**
 * read data from tty
 *
 * @param [in] fd file descriptor
 * @param [out] data buffer
 * @param [in,out] data_size available buffer size, updated with read size
 * @param [in] max_retries max read retries
 *
 * @return E_ERR_SUCCESS if successful,
 * @return E_ERR_TTY_BAD_FD if a bad fd is provided,
 * @return E_ERR_BAD_PARAMETER if data or data_size is/are NULL
 * @return E_ERR_TTY_ERROR otherwise
 */
e_mmgr_errors_t read_from_tty(int fd, char *data, int *data_size,
                              int max_retries)
{
    int i;
    int err;
    int read_size = 0;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(data, ret, failure);
    CHECK_PARAM(data_size, ret, failure);

    memset(data, 0, *data_size);
    for (i = 0; i < max_retries; i++) {
        err = read(fd, data + read_size, *data_size - read_size);
        if (err < 0) {
            LOG_ERROR("Read failed (%s)", strerror(errno));
            if (errno == EBADF) {
                ret = E_ERR_TTY_BAD_FD;
            } else {
                ret = E_ERR_TTY_ERROR;
            }
            goto failure;
        } else if (err == 0) {
            if (read_size > 0) {
                /* We have read nothing but a data was read before */
                break;
            } else
                usleep(DELAY_BETWEEN_SUCCESSIVE_READ);
        } else
            read_size += err;
    }

    *data_size = read_size;
failure:
    return ret;
}

/**
 * write data to a tty device
 *
 * @param [in] fd file descriptor
 * @param [in] data to be written
 * @param [in] data_size data size
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_TTY_ERROR if nothing has been written
 * @return E_ERR_TTY_BAD_FD if write fails
 */
e_mmgr_errors_t write_to_tty(int fd, const char *data, int data_size)
{
    int err = 0;
    int cur = 0;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    do {
        err = write(fd, data + cur, data_size - cur);
        cur += ret;

        if (err == 0) {
            LOG_ERROR("write nothing (%s) fd=%d", strerror(errno), fd);
            ret = E_ERR_TTY_ERROR;
            break;
        } else if (err < 0) {
            LOG_ERROR("write error (%s) fd=%d", strerror(errno), fd);
            ret = E_ERR_TTY_BAD_FD;
            break;
        }
    } while (cur < data_size);

    return ret;
}

/**
 * Set tty configuration
 *
 * @param [in] fd tty file descriptor
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_TTY_ERROR if nothing has been written
 */
e_mmgr_errors_t set_termio(int fd)
{
    struct termios newtio;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        LOG_ERROR("fcntl failed (%s)", strerror(errno));
        ret = E_ERR_TTY_ERROR;
        goto out;
    }

    memset(&newtio, 0, sizeof(newtio));

    /* disable postprocess output characters */
    /* *INDENT-OFF* */
    newtio.c_oflag &= ~OPOST;
    newtio.c_lflag &= ~(ECHO /* disable echo input characters */
                        | ECHONL /* disable echo new line */
                        | ICANON /* disable erase, kill, werase, and */
                        /* print special characters */
                        | ISIG /* disable interrupt, quit, and suspend */
                        /* special characters */
                        | IEXTEN); /* disable non-POSIX special characters */

    newtio.c_cflag &= ~(CSIZE /* no size */
                        | PARENB /* disable parity bit */
                        | CBAUD /* clear current baud rate */
                        | CBAUDEX); /* clear current buad rate */
    newtio.c_cflag |= CS8; /* character size 8 bits */
    newtio.c_cflag |= CLOCAL | CREAD; /* Ignore modem control lines */
    newtio.c_cflag |= B115200; /* baud rate 115200 */
    /* *INDENT-ON* */

    tcflush(fd, TCIFLUSH);
    tcsetattr(fd, TCSANOW, &newtio);
out:
    return ret;
}

/**
 * Open a TTY device and set the terminal configuration
 *
 * @param [in] tty_name tty path
 * @param [out] fd tty file descriptor
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_TTY_BAD_FD if open fails
 * @return E_ERR_BAD_PARAMETER tty_name or fd is/are NULL
 */
e_mmgr_errors_t open_tty(const char *tty_name, int *fd)
{
    e_mmgr_errors_t ret = E_ERR_TTY_BAD_FD;
    int count;

    CHECK_PARAM(tty_name, ret, out);
    CHECK_PARAM(fd, ret, out);

    LOG_DEBUG("trying to open tty device: %s", tty_name);
    for (count = 0; count < MAX_OPEN_RETRY; count++) {
        *fd = open(tty_name, O_RDWR);
        if (*fd > 0) {
            break;
        } else {
            if ((errno == EAGAIN) || (errno == EACCES)) {
                sleep(1);
                LOG_DEBUG("retry to open %s due to (%s) failure",
                          tty_name, strerror(errno));
            } else {
                break;
            }
        }
    }

    if (*fd < 0) {
        LOG_ERROR("open of %s failed (%s)", tty_name, strerror(errno));
    } else {
        if (set_termio(*fd) != E_ERR_SUCCESS) {
            LOG_ERROR("Failed to set discipline");
            close(*fd);
            *fd = CLOSED_FD;
        } else {
            ret = E_ERR_SUCCESS;
            LOG_DEBUG("done");
        }
    }
out:
    return ret;
}

/**
 * Close a TTY devices
 *
 * @param [in,out] fd file descriptor to close
 *
 * @return E_ERR_BAD_PARAMETER if fd is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_TTY_ERROR if nothing has been written
 */
e_mmgr_errors_t close_tty(int *fd)
{
    e_mmgr_errors_t ret = E_ERR_TTY_ERROR;

    CHECK_PARAM(fd, ret, out);

    LOG_DEBUG("trying to close tty");
    if (*fd > CLOSED_FD) {
        close(*fd);
        *fd = CLOSED_FD;
        ret = E_ERR_SUCCESS;
        LOG_DEBUG("closed");
    }
out:
    return ret;
}
