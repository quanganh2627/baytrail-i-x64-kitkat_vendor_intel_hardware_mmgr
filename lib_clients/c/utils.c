/* Modem Manager client library - utils source file
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

#include <cutils/sockets.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "utils.h"

const char *g_mmgr_events[] = {
#undef X
#define X(a) #a
    MMGR_EVENTS
};

/**
 * function to handle cnx event
 *
 * @private
 *
 * @param [in] p_lib library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if p_lib is invalid
 * @return E_ERR_CLI_FAILED if not connected or invalid request id
 * @return E_ERR_CLI_SUCCEED
 */
static e_err_mmgr_cli_t handle_cnx_event(mmgr_lib_context_t *p_lib)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_FAILED;
    e_mmgr_errors_t err;
    msg_t msg = {.data = NULL };
    e_mmgr_events_t id;
    mmgr_cli_event_t event = {.context = p_lib->cli_ctx };
    size_t size;
    size_t read_size;

    CHECK_CLI_PARAM(p_lib, ret, out);

    /* read msg data */
    err = get_header(p_lib->fd_socket, &msg.hdr);
    if (err == E_ERR_DISCONNECTED) {
        LOG_DEBUG("(fd=%d client=%s) connection closed by MMGR",
                  p_lib->fd_socket, p_lib->cli_name);
        goto out;
    }
    memcpy(&id, &msg.hdr.id, sizeof(e_mmgr_events_t));
    memcpy(&size, &msg.hdr.len, sizeof(size_t));
    read_size = size;
    if (size != 0) {
        msg.data = calloc(size, sizeof(char));
        if (msg.data == NULL) {
            LOG_ERROR("memory allocation fails");
            goto out;
        }
        if (read_cnx(p_lib->fd_socket, msg.data, &read_size) != E_ERR_SUCCESS) {
            LOG_ERROR("read fails");
            goto out;
        }
    }

    if (read_size != size) {
        LOG_ERROR("Read error. bad size (%d/%d)", read_size, size);
        goto out;
    }

    if (id < E_MMGR_NUM_EVENTS) {
        if (p_lib->func[id] != NULL) {
            LOG_DEBUG("(fd=%d client=%s) event (%s) received",
                      p_lib->fd_socket, p_lib->cli_name, g_mmgr_events[id]);
            event.id = id;
            p_lib->set_data[id] (&msg, &event);
            p_lib->func[id] (&event);
            p_lib->free_data[id] (&event);
            ret = E_ERR_CLI_SUCCEED;
        } else {
            LOG_ERROR("(fd=%d client=%s) func is NULL",
                      p_lib->fd_socket, p_lib->cli_name);
        }
    } else {
        LOG_DEBUG("(fd=%d client=%s) unkwnown event received (0x%.2X)",
                  p_lib->fd_socket, p_lib->cli_name, msg.hdr.id);
    }
out:
    if (msg.data != NULL)
        free(msg.data);
    return ret;
}

/**
 * handle events provided by select
 *
 * @private
 *
 * @param [in] p_lib private structure
 * @param [in] rfds read events
 *
 * @return E_ERR_CLI_FAILED
 * @return E_ERR_CLI_SUCCEED
 */
static e_err_mmgr_cli_t handle_events(mmgr_lib_context_t *p_lib, fd_set *rfds)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_FAILED;
    char buffer[PIPE_BUF];

    CHECK_CLI_PARAM(p_lib, ret, out);
    CHECK_CLI_PARAM(rfds, ret, out);

    if (FD_ISSET(p_lib->fd_pipe[READ], rfds)) {
        read(p_lib->fd_pipe[READ], buffer, PIPE_BUF);
        LOG_DEBUG("(fd=%d client=%s) stopping thread",
                  p_lib->fd_socket, p_lib->cli_name);
    } else if (FD_ISSET(p_lib->fd_socket, rfds)) {
        ret = handle_cnx_event(p_lib);
    } else {
        LOG_DEBUG("event not handled");
    }
out:
    return ret;
}

/**
 * check if client is connected or not. This is a sensitive data
 *
 * @param [in] p_lib private structure
 * @param [out] answer true if connected, false otherwise
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t is_connected(mmgr_lib_context_t *p_lib, bool *answer)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;

    CHECK_CLI_PARAM(p_lib, ret, out);

    pthread_mutex_lock(&p_lib->mtx);
    *answer = p_lib->connected;
    pthread_mutex_unlock(&p_lib->mtx);
out:
    return ret;
}

/**
 * send registration sequence to MMGR
 *
 * @param [in] handle private structure
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t register_client(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_FAILED;
    e_mmgr_errors_t err;
    msg_hdr_t answer = {.id = E_MMGR_NACK };
    int i;
    mmgr_cli_requests_t request[2];
    mmgr_lib_context_t *p_lib = NULL;

    CHECK_CLI_PARAM(handle, ret, out);

    ret = check_state(handle, &p_lib, false);
    if (ret != E_ERR_CLI_SUCCEED)
        goto out;

    request[0].id = E_MMGR_SET_NAME;
    request[0].len = strnlen(p_lib->cli_name, CLIENT_NAME_LEN);
    request[0].data = &p_lib->cli_name;

    request[1].id = E_MMGR_SET_EVENTS;
    request[1].len = sizeof(uint32_t);
    request[1].data = &p_lib->events;

    for (i = 0; i < 2; i++) {
        if ((ret = send_msg(handle, &request[i], false)) != E_ERR_CLI_SUCCEED)
            break;

        err = get_header(p_lib->fd_socket, &answer);
        if ((err != E_ERR_SUCCESS) || (answer.id != E_MMGR_ACK))
            break;
    }

    if (answer.id == E_MMGR_ACK) {
        LOG_DEBUG("(fd=%d client=%s) connected successfully",
                  p_lib->fd_socket, p_lib->cli_name);
        ret = E_ERR_CLI_SUCCEED;

        pthread_mutex_lock(&p_lib->mtx);
        p_lib->connected = true;
        pthread_mutex_unlock(&p_lib->mtx);
    } else {
        LOG_ERROR("(fd=%d client=%s) failed to connect",
                  p_lib->fd_socket, p_lib->cli_name);
        ret = E_ERR_CLI_FAILED;
    }
out:
    return ret;
}

/**
 * check current library state
 *
 * @param [in] handle library handle
 * @param [out] p_lib library handle with correct cast
 * @param [in] connected check if client is connected or not
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if bad data state
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t check_state(mmgr_cli_handle_t *handle,
                             mmgr_lib_context_t **p_lib, bool connected)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    char *state_str[] = { "disconnected", "connected" };
    bool state = false;

    CHECK_CLI_PARAM(handle, ret, out);
    CHECK_CLI_PARAM(p_lib, ret, out);

    *p_lib = (mmgr_lib_context_t *)handle;

#ifdef DEBUG_MMGR_CLI
    if ((*p_lib)->init != INIT_CHECK) {
        LOG_ERROR("handle is not configured");
        ret = E_ERR_CLI_BAD_HANDLE;
        goto out;
    }
#endif

    is_connected(*p_lib, &state);
    if (state != connected) {
        ret = E_ERR_CLI_FAILED;
        LOG_ERROR("(fd=%d client=%s) WRONG STATE: client is %s instead of %s",
                  (*p_lib)->fd_socket, (*p_lib)->cli_name,
                  state_str[state], state_str[connected]);
    }
out:
    return ret;
}

/**
 * send an mmgr request
 *
 * @param [in] handle library handle
 * @param [in] request request to send to the mmgr
 * @param [in] cnx_state send data if cnx_state is equal to
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if not connected or invalid request id
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t send_msg(mmgr_cli_handle_t *handle,
                          const mmgr_cli_requests_t *request, bool cnx_state)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_FAILED;
    mmgr_lib_context_t *p_lib = NULL;
    bool connected;
    msg_t msg = {.data = NULL };
    size_t size;
    const char *mmgr_requests[] = {
#undef X
#define X(a) #a
        MMGR_REQUESTS
    };

    ret = check_state(handle, &p_lib, cnx_state);
    if (ret != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("request not sent");
        goto out;
    }

    ret = E_ERR_CLI_FAILED;

    if (request == NULL) {
        LOG_ERROR("request is NULL");
        goto out;
    }

    if (request->id >= E_MMGR_NUM_REQUESTS) {
        LOG_ERROR("bad request");
        goto out;
    }

    p_lib->set_msg[request->id] (&msg, (void *)request);

    is_connected(p_lib, &connected);
    if (connected == cnx_state) {
        size = SIZE_HEADER + msg.hdr.len;
        if (write_cnx(p_lib->fd_socket, msg.data, &size) == E_ERR_SUCCESS) {
            if (size == (SIZE_HEADER + msg.hdr.len)) {
                LOG_DEBUG("(fd=%d client=%s) request (%s) sent successfully",
                          p_lib->fd_socket, p_lib->cli_name,
                          mmgr_requests[request->id]);
                ret = E_ERR_CLI_SUCCEED;
            }
        }
    }
out:
    delete_msg(&msg);
    return ret;
}

/**
 * handle mmgr events and dispatch them
 *
 * @param [in] p_lib private structure
 *
 * @return E_ERR_CLI_BAD_HANDLE if p_lib is NULL
 * @return E_ERR_CLI_SUCCEED at the end
 */
e_err_mmgr_cli_t read_events(mmgr_lib_context_t *p_lib)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    fd_set rfds;
    int fd_max;

    CHECK_CLI_PARAM(p_lib, ret, out);

    if (p_lib->fd_socket > p_lib->fd_pipe[READ])
        fd_max = p_lib->fd_socket;
    else
        fd_max = p_lib->fd_pipe[READ];

    do {
        FD_ZERO(&rfds);
        FD_SET(p_lib->fd_pipe[READ], &rfds);
        FD_SET(p_lib->fd_socket, &rfds);

        if (select(fd_max + 1, &rfds, NULL, NULL, NULL) < 0) {
            LOG_ERROR("select failed (%s)", strerror(errno));
            break;
        }
        ret = handle_events(p_lib, &rfds);
    } while (ret != E_ERR_CLI_FAILED);

out:
    pthread_mutex_lock(&p_lib->mtx);
    p_lib->connected = false;
    shutdown(p_lib->fd_socket, SHUT_RDWR);
    close(p_lib->fd_socket);
    close(p_lib->fd_pipe[READ]);
    close(p_lib->fd_pipe[WRITE]);
    p_lib->fd_socket = CLOSED_FD;
    p_lib->fd_pipe[READ] = CLOSED_FD;
    p_lib->fd_pipe[WRITE] = CLOSED_FD;
    pthread_mutex_unlock(&p_lib->mtx);

    LOG_DEBUG("(fd=%d client=%s) disconnected", p_lib->fd_socket,
              p_lib->cli_name);
    pthread_exit(&ret);
    return ret;
}
