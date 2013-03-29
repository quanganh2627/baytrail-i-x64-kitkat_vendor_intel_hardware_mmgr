/* Modem Manager - client library source file
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

#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <cutils/sockets.h>
#include <sys/types.h>

#include "logs.h"

#undef LOG_TAG
#define LOG_TAG "MMGR_CLI"

#include "client_cnx.h"
#include "errors.h"
#include "msg_to_data.h"
#include "data_to_msg.h"
#include "mmgr_cli.h"

typedef e_mmgr_errors_t (*msg_handler) (msg_t *, mmgr_cli_event_t *);
typedef e_mmgr_errors_t (*free_handler) (mmgr_cli_event_t *);

/**
 * internal structure for mmgr_cli
 *
 * @private
 */
typedef struct mmgr_lib_context {
    uint32_t events;
    pthread_t thr_id;
    pthread_mutex_t mtx;
    void *cli_ctx;
    bool connected;
    int fd_socket;
    int fd_pipe[2];
    event_handler func[E_MMGR_NUM_EVENTS];
    char cli_name[CLIENT_NAME_LEN];
    bool lock;
    msg_handler set_msg[E_MMGR_NUM_REQUESTS];
    msg_handler set_data[E_MMGR_NUM_EVENTS];
    free_handler free_data[E_MMGR_NUM_EVENTS];
#ifdef DEBUG_MMGR_CLI
    /* the purpose of this variable is to check that this structure
       has correctly been initialized */
    uint32_t init;
#endif
} mmgr_lib_context_t;

#define INIT_CHECK 0xCE5A12BB
#define CLOSED_FD -1

#define xstr(s) str(s)
#define str(s) #s

#define CHECK_CLI_PARAM(handle, err, out) do { \
    if (handle == NULL) { \
        LOG_ERROR(xstr(handle)" is NULL"); \
        err = E_ERR_CLI_BAD_HANDLE; \
        goto out; \
    } \
} while (0)

#define CHECK_EVENT(id, err, out) do { \
    if (id>= E_MMGR_NUM_EVENTS) { \
        LOG_ERROR("unknown event"); \
        ret = E_ERR_CLI_FAILED; \
        goto out; \
    } \
} while (0)

const char *g_mmgr_events[] = {
#undef X
#define X(a) #a
    MMGR_EVENTS
};

#define READ 0
#define WRITE 1

/**
 * check if client is connected or not. This is a sensitive data
 *
 * @private
 *
 * @param [in] p_lib private structure
 * @param [out] answer true if connected, false otherwise
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_SUCCEED
 */
static inline e_err_mmgr_cli_t is_connected(mmgr_lib_context_t *p_lib,
                                            bool *answer)
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
 * check current library state
 *
 * @private
 *
 * @param [in] handle library handle
 * @param [out] p_lib library handle with correct cast
 * @param [in] connected check if client is connected or not
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if bad data state
 * @return E_ERR_CLI_SUCCEED
 */
static e_err_mmgr_cli_t check_state(mmgr_cli_handle_t *handle,
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
 * @private
 *
 * @param [in] handle library handle
 * @param [in] request request to send to the mmgr
 * @param [in] cnx_state send data if cnx_state is equal to
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if not connected or invalid request id
 * @return E_ERR_CLI_SUCCEED
 */
static e_err_mmgr_cli_t send_msg(mmgr_cli_handle_t *handle,
                                 const mmgr_cli_requests_t *request,
                                 bool cnx_state)
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
 * send registration sequence to MMGR
 *
 * @private
 *
 * @param [in] handle private structure
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED
 * @return E_ERR_CLI_SUCCEED
 */
static inline e_err_mmgr_cli_t register_client(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_FAILED;
    e_mmgr_errors_t err;
    msg_hdr_t answer = {.id = E_MMGR_NACK };
    int i;
    mmgr_cli_requests_t request[2];
    mmgr_lib_context_t *p_lib = NULL;

    CHECK_CLI_PARAM(handle, ret, out);

    ret = check_state(handle, &p_lib, false);
    if (ret != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("TODO");
        goto out;
    }

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
    }
out:
    return ret;
}

/**
 * function to send an mmgr request
 *
 * @param [in] handle library handle
 * @param [in] request request to send to the mmgr
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if not connected or invalid request id
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_send_msg(mmgr_cli_handle_t *handle,
                                   const mmgr_cli_requests_t *request)
{
    return send_msg(handle, request, true);
}

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
static inline e_err_mmgr_cli_t handle_cnx_event(mmgr_lib_context_t *p_lib)
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
static inline e_err_mmgr_cli_t handle_events(mmgr_lib_context_t *p_lib,
                                             fd_set *rfds)
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
 * handle mmgr events and dispatch them
 *
 * @private
 *
 * @param [in] p_lib private structure
 *
 * @return E_ERR_CLI_BAD_HANDLE if p_lib is NULL
 * @return E_ERR_CLI_SUCCEED at the end
 */
static e_err_mmgr_cli_t read_events(mmgr_lib_context_t *p_lib)
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

/**
 * create mmgr client library handle. This function should be called first.
 * To avoid memory leaks *handle must be set to NULL by the caller.
 *
 * @param [out] handle library handle
 * @param [in] client_name name of the client
 * @param [in] context pointer to a struct that shall be passed to function
 *             context handle can be NULL if unused.
 *
 * @return E_ERR_CLI_FAILED if client_name is NULL or handle creation failed
 * @return E_ERR_CLI_BAD_HANDLE if handle is already created
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_create_handle(mmgr_cli_handle_t **handle,
                                        const char *client_name, void *context)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    mmgr_lib_context_t *p_lib = NULL;
    int i;

    CHECK_CLI_PARAM(handle, ret, out);

    if (*handle != NULL) {
        LOG_ERROR("*handle is not NULL");
        ret = E_ERR_CLI_BAD_HANDLE;
        goto out;
    }

    if (client_name == NULL) {
        LOG_ERROR("client_name is NULL");
        ret = E_ERR_CLI_FAILED;
        goto out;
    }

    p_lib = malloc(sizeof(mmgr_lib_context_t));
    if (p_lib == NULL) {
        LOG_ERROR("failed to allocate");
        ret = E_ERR_CLI_FAILED;
        goto out;
    }

    pthread_mutex_init(&p_lib->mtx, NULL);
    p_lib->events = 0;
    p_lib->cli_ctx = context;
    p_lib->fd_socket = CLOSED_FD;
    p_lib->fd_pipe[READ] = CLOSED_FD;
    p_lib->fd_pipe[WRITE] = CLOSED_FD;
    p_lib->connected = false;
    p_lib->thr_id = -1;
    strncpy(p_lib->cli_name, client_name, CLIENT_NAME_LEN - 1);
#if DEBUG_MMGR_CLI
    p_lib->init = INIT_CHECK;
#endif

    for (i = 0; i < E_MMGR_NUM_REQUESTS; i++)
        p_lib->set_msg[i] = set_msg_empty;

    for (i = 0; i < E_MMGR_NUM_EVENTS; i++) {
        p_lib->set_data[i] = set_data_empty;
        p_lib->free_data[i] = free_data_empty;
    }

    for (i = 0; i < E_MMGR_NUM_EVENTS; i++)
        p_lib->func[i] = NULL;

    p_lib->set_msg[E_MMGR_SET_NAME] = set_msg_name;
    p_lib->set_msg[E_MMGR_SET_EVENTS] = set_msg_filter;
    p_lib->set_msg[E_MMGR_REQUEST_MODEM_FW_UPDATE] = set_msg_fw_update;
    p_lib->set_msg[E_MMGR_REQUEST_MODEM_NVM_UPDATE] = set_msg_nvm_update;

    p_lib->set_data[E_MMGR_RESPONSE_MODEM_RND] = set_data_rnd_id;
    p_lib->free_data[E_MMGR_RESPONSE_MODEM_RND] = free_data_rnd_id;

    p_lib->set_data[E_MMGR_RESPONSE_MODEM_HW_ID] = set_data_hw_id;
    p_lib->free_data[E_MMGR_RESPONSE_MODEM_HW_ID] = free_data_hw_id;

    p_lib->set_data[E_MMGR_RESPONSE_MODEM_NVM_ID] = set_data_nvm_id;
    p_lib->free_data[E_MMGR_RESPONSE_MODEM_NVM_ID] = free_data_nvm_id;

    p_lib->set_data[E_MMGR_RESPONSE_MODEM_FW_PROGRESS] = set_data_fw_progress;
    p_lib->free_data[E_MMGR_RESPONSE_MODEM_FW_PROGRESS] =
        free_one_element_struct;

    p_lib->set_data[E_MMGR_RESPONSE_MODEM_FW_RESULT] = set_data_fw_result;
    p_lib->free_data[E_MMGR_RESPONSE_MODEM_FW_RESULT] = free_one_element_struct;

    p_lib->set_data[E_MMGR_RESPONSE_MODEM_NVM_RESULT] = set_data_nvm_result;
    p_lib->free_data[E_MMGR_RESPONSE_MODEM_NVM_RESULT] =
        free_one_element_struct;

    p_lib->set_data[E_MMGR_RESPONSE_MODEM_NVM_PROGRESS] = set_data_nvm_progress;
    p_lib->free_data[E_MMGR_RESPONSE_MODEM_NVM_PROGRESS] =
        free_one_element_struct;

    p_lib->set_data[E_MMGR_RESPONSE_FUSE_INFO] = set_data_fuse_info;
    p_lib->free_data[E_MMGR_RESPONSE_FUSE_INFO] = free_one_element_struct;

    p_lib->set_data[E_MMGR_RESPONSE_GET_BACKUP_FILE_PATH] = set_data_bckup_file;
    p_lib->free_data[E_MMGR_RESPONSE_GET_BACKUP_FILE_PATH] =
        free_data_bckup_file;

    p_lib->set_data[E_MMGR_NOTIFY_AP_RESET] = set_data_ap_reset;
    p_lib->free_data[E_MMGR_NOTIFY_AP_RESET] = free_data_ap_reset;

    p_lib->set_data[E_MMGR_NOTIFY_CORE_DUMP_COMPLETE] = set_data_core_dump;
    p_lib->free_data[E_MMGR_NOTIFY_CORE_DUMP_COMPLETE] = free_data_core_dump;

    p_lib->set_data[E_MMGR_NOTIFY_ERROR] = set_data_error;
    p_lib->free_data[E_MMGR_NOTIFY_ERROR] = free_data_error;

    *handle = (mmgr_cli_handle_t *)p_lib;
    LOG_DEBUG("handle created successfully");
out:
    return ret;
}

/**
 * delete mmgr client library handle
 *
 * @param [in, out] handle library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid or handle already deleted
 * @return E_ERR_CLI_FAILED if client is connected
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_delete_handle(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    mmgr_lib_context_t *p_lib = NULL;

    CHECK_CLI_PARAM(handle, ret, out);

    ret = check_state(handle, &p_lib, false);
    if (ret == E_ERR_CLI_SUCCEED) {
        free(p_lib);
        LOG_DEBUG("handle freed successfully");
    } else {
        LOG_ERROR("handle not freed");
    }

out:
    return ret;
}

/**
 * subscribe to an event. This function shall only be invoked on a valid
 * unconnected handle.
 *
 * @param [in,out] handle library handle
 * @param [in] func function pointer to the handle
 * @param [in] id event to subscribe to
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if connected or event already configured or func is
 *                          NULL or unknown event
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_subscribe_event(mmgr_cli_handle_t *handle,
                                          event_handler func,
                                          e_mmgr_events_t id)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    mmgr_lib_context_t *p_lib = NULL;

    ret = check_state(handle, &p_lib, false);
    if (ret != E_ERR_CLI_SUCCEED) {
        LOG_ERROR
            ("To subscribe to an event, you should provide a valid handle"
             " and be disconnected");
        goto out;
    }

    CHECK_EVENT(id, ret, out);

    if (func == NULL) {
        LOG_ERROR("function is NULL");
        ret = E_ERR_CLI_FAILED;
        goto out;
    }

    pthread_mutex_lock(&p_lib->mtx);
    if (p_lib->func[id] != NULL) {
        ret = E_ERR_CLI_FAILED;
    } else {
        p_lib->events |= (0x01 << id);
        p_lib->func[id] = func;
    }
    pthread_mutex_unlock(&p_lib->mtx);

    if (ret == E_ERR_CLI_SUCCEED) {
        LOG_DEBUG("(fd=%d client=%s) event (%s) subscribed successfully",
                  p_lib->fd_socket, p_lib->cli_name, g_mmgr_events[id]);
    } else {
        LOG_ERROR("(fd=%d client=%s) event (%s) already configured",
                  p_lib->fd_socket, p_lib->cli_name, g_mmgr_events[id]);
    }

out:
    return ret;
}

/**
 * unsubscribe to an event. This function shall only be invoked on a valid
 * unconnected handle.
 *
 * @param [in, out] handle library handle
 * @param [in] id event to unsubscribe to
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if connected or unknown event
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_unsubscribe_event(mmgr_cli_handle_t *handle,
                                            e_mmgr_events_t id)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    mmgr_lib_context_t *p_lib = NULL;

    ret = check_state(handle, &p_lib, false);
    if (ret != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("To subscribe to an event, you should be disconnected");
        goto out;
    }

    CHECK_EVENT(id, ret, out);

    pthread_mutex_lock(&p_lib->mtx);
    p_lib->events &= ~(0x01 << id);
    p_lib->func[id] = NULL;
    pthread_mutex_unlock(&p_lib->mtx);

    LOG_DEBUG("(fd=%d client=%s) event (%s) unsubscribed successfully",
              p_lib->fd_socket, p_lib->cli_name, g_mmgr_events[id]);
out:
    return ret;
}

/**
 * connect the client to the mmgr. This function shall only be invoked on a
 * valid unconnected handle. subscribe/unsubscribe cannot be used on this
 * when handle is connected.
 * Client can do a connect even there is no event subscribed
 *
 * @param [in] handle library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if already connected
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_connect(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret;
    mmgr_lib_context_t *p_lib = NULL;
    int fd = CLOSED_FD;

    ret = check_state(handle, &p_lib, false);
    if (ret != E_ERR_CLI_SUCCEED)
        goto out;

    ret = E_ERR_CLI_FAILED;
    if (pipe(p_lib->fd_pipe) < 0) {
        LOG_ERROR("(client=%s) failed to create pipe (%s)", p_lib->cli_name,
                  strerror(errno));
        goto out;
    }

    fd = socket_local_client(MMGR_SOCKET_NAME,
                             ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    if (fd < 0) {
        LOG_ERROR("(client=%s) failed to open socket", p_lib->cli_name);
        goto out;
    }

    pthread_mutex_lock(&p_lib->mtx);
    p_lib->fd_socket = fd;
    p_lib->connected = false;
    p_lib->lock = false;
    pthread_mutex_unlock(&p_lib->mtx);

    if (register_client(handle) != E_ERR_CLI_SUCCEED)
        goto out;

    if (pthread_create(&p_lib->thr_id, NULL, (void *)read_events, p_lib) != 0) {
        LOG_ERROR
            ("(fd=%d client=%s) failed to launch read_events. Disconnect "
             "the client", fd, p_lib->cli_name);
        mmgr_cli_disconnect(handle);
        ret = E_ERR_CLI_FAILED;
    } else {
        ret = E_ERR_CLI_SUCCEED;
    }

out:
    return ret;
}

/**
 * disconnect from mmgr. If a lock is set, the unlock is done automatically
 *
 * @param [in] handle library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if already disconnected
 * @return E_ERR_CLI_SUCCEED
 */
int mmgr_cli_disconnect(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_FAILED;
    mmgr_lib_context_t *p_lib = NULL;
    bool connected;
    char msg[PIPE_BUF];
    ssize_t size;

    ret = check_state(handle, &p_lib, true);
    if (ret == E_ERR_CLI_BAD_HANDLE)
        goto out;

    memset(msg, 0, sizeof(msg));

    is_connected(p_lib, &connected);
    if (connected) {
        LOG_DEBUG("(fd=%d client=%s) writing signal", p_lib->fd_socket,
                  p_lib->cli_name);
        if ((size = write(p_lib->fd_pipe[WRITE], msg, sizeof(msg))) < -1) {
            LOG_ERROR("(fd=%d client=%s) write failed (%s)",
                      p_lib->fd_socket, p_lib->cli_name, strerror(errno));
        }
    }

    LOG_DEBUG("(fd=%d client=%s) waiting for end of reading thread",
              p_lib->fd_socket, p_lib->cli_name);
    if (p_lib->thr_id != -1) {
        pthread_join(p_lib->thr_id, NULL);
        p_lib->thr_id = -1;
    }

    LOG_DEBUG("(fd=%d client=%s) reading thread stopped",
              p_lib->fd_socket, p_lib->cli_name);

    is_connected(p_lib, &connected);
    if (!connected) {
        LOG_DEBUG("(fd=%d client=%s) is disconnected", p_lib->fd_socket,
                  p_lib->cli_name);
        ret = E_ERR_CLI_SUCCEED;
    } else {
        LOG_ERROR("(fd=%d client=%s) failed to disconnect",
                  p_lib->fd_socket, p_lib->cli_name);
    }
out:
    return ret;
}

/**
 * acquire the modem resource
 *
 * @param [in] handle library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if not connected
 * @return E_ERR_CLI_ALREADY_LOCK if already locked
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_lock(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    mmgr_lib_context_t *p_lib = NULL;
    mmgr_cli_requests_t request;
    request.id = E_MMGR_RESOURCE_ACQUIRE;

    ret = check_state(handle, &p_lib, true);
    if (ret != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("not locked");
        goto out;
    }

    if (p_lib->lock) {
        LOG_ERROR("(fd=%d client=%s) Already locked", p_lib->fd_socket,
                  p_lib->cli_name);
        ret = E_ERR_CLI_ALREADY_LOCK;
    } else {
        ret = mmgr_cli_send_msg(handle, &request);
        p_lib->lock = true;
    }
out:
    return ret;
}

/**
 * release the modem resource
 *
 * @param [in] handle library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if not connected
 * @return E_ERR_CLI_ALREADY_UNLOCK if already unlocked
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_unlock(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    mmgr_lib_context_t *p_lib = NULL;
    mmgr_cli_requests_t request;
    request.id = E_MMGR_RESOURCE_RELEASE;

    ret = check_state(handle, &p_lib, true);
    if (ret != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("not unlocked");
        goto out;
    }

    if (!p_lib->lock) {
        LOG_ERROR("(fd=%d client=%s) Already unlocked", p_lib->fd_socket,
                  p_lib->cli_name);
        ret = E_ERR_CLI_ALREADY_UNLOCK;
    } else {
        ret = mmgr_cli_send_msg(handle, &request);
        p_lib->lock = false;
    }
out:
    return ret;
}
