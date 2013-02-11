/* Modem Manager - cnx source file
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

#include <arpa/inet.h>
#include <cutils/sockets.h>
#include <sys/socket.h>
#include <unistd.h>

#include "client_cnx.h"
#include "errors.h"
#include "logs.h"
#include "mmgr.h"

#define DEFAULT_BACKLOG 5

/**
 * open MMGR cnx
 *
 * @param [out] fd cnx file descriptor
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t open_cnx(int *fd)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(fd, ret, out);

    LOG_DEBUG("configure socket: %s", MMGR_SOCKET_NAME);
    *fd = android_get_control_socket(MMGR_SOCKET_NAME);

    if (listen(*fd, DEFAULT_BACKLOG) < 0) {
        LOG_ERROR("listen failed (%s)", strerror(errno));
        goto out;
    }
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * accept cnx connection
 *
 * @param [in] fd cnx file descriptor
 *
 * @return file descriptor
 */
e_mmgr_errors_t accept_cnx(int fd)
{
    return accept(fd, NULL, NULL);
}

/**
 * read data from cnx
 *
 * @param [in] fd cnx file descriptor
 * @param [out] data output buffer
 * @param [in,out] len size of data. the value returned is the read size
 *
 * @return E_ERR_BAD_PARAMETER if fd is NULL
 * @return E_ERR_FAILED read fails
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t read_cnx(int fd, void *data, size_t *len)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int err;

    CHECK_PARAM(data, ret, out);
    CHECK_PARAM(len, ret, out);

    memset(data, 0, *len);
    err = recv(fd, data, *len, 0);
    if (err < 0) {
        LOG_ERROR("read fails (%s)", strerror(errno));
        ret = E_ERR_FAILED;
    } else
        *len = err;

out:
    return ret;
}

/**
 * write data to cnx
 *
 * @param [in] fd cnx file descriptor
 * @param [in] data data to write
 * @param [in] len data length
 *
 * @return E_ERR_BAD_PARAMETER if fd is NULL
 * @return E_ERR_FAILED send fails
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t write_cnx(int fd, void *data, size_t *len)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    int err;

    CHECK_PARAM(data, ret, out);
    CHECK_PARAM(len, ret, out);

    err = send(fd, data, *len, MSG_NOSIGNAL);
    if (err < 0) {
        LOG_ERROR("send fails (%s)", strerror(errno));
        ret = E_ERR_FAILED;
    }
out:
    return ret;
}

/**
 * close cnx
 *
 * @param [in,out] fd cnx file descriptor
 *
 * @return E_ERR_BAD_PARAMETER if fd is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t close_cnx(int *fd)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(fd, ret, out);

    shutdown(*fd, SHUT_RDWR);
    if (close(*fd) < 0) {
        LOG_ERROR("(fd=%d) reason: (%s)", *fd, strerror(errno));
        ret = E_ERR_FAILED;
    }
    *fd = CLOSED_FD;
out:
    return ret;
}

/**
 * set header
 *
 * @param [in,out] msg received message
 *
 * @return E_ERR_BAD_PARAMETER if msg is NULL
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t set_header(msg_t *msg)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    struct timeval ts;
    uint32_t tmp;

    CHECK_PARAM(msg, ret, out);

    /* setting id */
    tmp = htonl(msg->hdr.id);
    memcpy(msg->data, &tmp, sizeof(uint32_t));

    /* setting timestamp */
    gettimeofday(&ts, NULL);
    memcpy(&tmp, &ts.tv_sec, sizeof(ts.tv_sec));
    tmp = htonl(tmp);
    memcpy(msg->data + sizeof(uint32_t), &tmp, sizeof(uint32_t));

    /* setting size */
    memcpy(&tmp, &msg->hdr.len, sizeof(uint32_t));
    tmp = htonl(tmp);
    memcpy(msg->data + (2 * sizeof(uint32_t)), &tmp, sizeof(uint32_t));
out:
    return ret;
}

/**
 * read data from cnx and extract header
 *
 * @param [in] fd cnx file descriptor
 * @param [out] hdr message header
 *
 * @return E_ERR_BAD_PARAMETER if hdr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_DISCONNECTED if client is disconnected
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t get_header(int fd, msg_hdr_t *hdr)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    char buffer[SIZE_HEADER];
    size_t len = SIZE_HEADER;

    CHECK_PARAM(hdr, ret, out);

    if ((ret = read_cnx(fd, buffer, &len)) != E_ERR_SUCCESS)
        goto out;

    if (len == 0) {
        ret = E_ERR_DISCONNECTED;
        LOG_DEBUG("client disconnected");
        goto out;
    } else if (len < SIZE_HEADER) {
        ret = E_ERR_FAILED;
        LOG_ERROR("Invalid message. Header is missing");
        goto out;
    }

    /* extract request id */
    memcpy(&hdr->id, buffer, sizeof(uint32_t));
    hdr->id = ntohl(hdr->id);

    /* extract timestamp */
    memcpy(&hdr->ts, buffer + sizeof(uint32_t), sizeof(uint32_t));
    hdr->ts = ntohl(hdr->ts);

    /* extract data len */
    memcpy(&hdr->len, buffer + (2 * sizeof(uint32_t)), sizeof(uint32_t));
    hdr->len = ntohl(hdr->len);

    if (hdr->len < (len - SIZE_HEADER)) {
        LOG_ERROR("Invalid message. Bad buffer len");
        goto out;
    } else {
        ret = E_ERR_SUCCESS;
    }

out:
    return ret;
}
