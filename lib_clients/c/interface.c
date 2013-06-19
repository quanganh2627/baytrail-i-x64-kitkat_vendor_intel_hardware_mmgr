/* Modem Manager client library - interface source file
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

#include "utils.h"
#include "mmgr_cli.h"

#define CHECK_EVENT(id, err, out) do { \
    if (id>= E_MMGR_NUM_EVENTS) { \
        LOG_ERROR("unknown event"); \
        ret = E_ERR_CLI_FAILED; \
        goto out; \
    } \
} while (0)

/**
 * Send a request to MMGR.
 * This function returns when the request is sent successfully,
 * or fail on error, or fail after a timeout of 20s.
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
    e_err_mmgr_cli_t ret = E_ERR_CLI_FAILED;
    mmgr_lib_context_t *p_lib = NULL;

    ret = check_state(handle, &p_lib, true);
    if (ret != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("request not sent");
    } else {
        ret = send_msg(p_lib, request, E_SEND_THREADED,
                       DEF_MMGR_RESPONSIVE_TIMEOUT);
    }

    return ret;
}

/**
 * Create mmgr client library handle. This function should be called first.
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
    pthread_mutex_init(&p_lib->mtx_signal, NULL);
    pthread_cond_init(&p_lib->cond, NULL);
    p_lib->events = (0x1 << E_MMGR_ACK) | (0x1 << E_MMGR_NACK);
    p_lib->cli_ctx = context;
    p_lib->fd_socket = CLOSED_FD;
    p_lib->fd_pipe[READ] = CLOSED_FD;
    p_lib->fd_pipe[WRITE] = CLOSED_FD;
    p_lib->connected = E_CNX_DISCONNECTED;
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

    p_lib->set_data[E_MMGR_RESPONSE_MODEM_HW_ID] = set_data_hw_id;
    p_lib->free_data[E_MMGR_RESPONSE_MODEM_HW_ID] = free_data_hw_id;

    p_lib->set_data[E_MMGR_RESPONSE_FUSE_INFO] = set_data_fuse_info;
    p_lib->free_data[E_MMGR_RESPONSE_FUSE_INFO] = free_one_element_struct;

    p_lib->set_data[E_MMGR_NOTIFY_AP_RESET] = set_data_ap_reset;
    p_lib->free_data[E_MMGR_NOTIFY_AP_RESET] = free_data_ap_reset;

    p_lib->set_data[E_MMGR_NOTIFY_CORE_DUMP_COMPLETE] = set_data_core_dump;
    p_lib->free_data[E_MMGR_NOTIFY_CORE_DUMP_COMPLETE] = free_data_core_dump;

    p_lib->set_data[E_MMGR_NOTIFY_ERROR] = set_data_error;
    p_lib->free_data[E_MMGR_NOTIFY_ERROR] = free_data_error;

    p_lib->set_data[E_MMGR_RESPONSE_MODEM_FW_RESULT] = set_data_fw_result;
    p_lib->free_data[E_MMGR_RESPONSE_MODEM_FW_RESULT] = free_one_element_struct;

    *handle = (mmgr_cli_handle_t *)p_lib;
    LOG_DEBUG("handle created successfully");
out:
    return ret;
}

/**
 * Delete mmgr client library handle
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
 * Subscribe to an event. This function shall only be invoked on a valid
 * unconnected handle.
 * NB: users can't subscribe to ACK or NACK events.
 *
 * @param [in,out] handle library handle
 * @param [in] func function pointer to the handle
 * @param [in] id event to subscribe to
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if connected or event already configured or func is
 *                          NULL or unknown/invalid event
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
        LOG_ERROR("To subscribe to an event, you should provide a valid handle"
                  " and be disconnected");
        goto out;
    }

    CHECK_EVENT(id, ret, out);
    if ((id == E_MMGR_ACK) || (id == E_MMGR_NACK)) {
        ret = E_ERR_CLI_FAILED;
        goto out;
    }

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
 * Unsubscribe to an event. This function shall only be invoked on a valid
 * unconnected handle.
 * NB: users can't subscribe to ACK or NACK events.
 *
 * @param [in, out] handle library handle
 * @param [in] id event to unsubscribe to
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if connected or unknown/invalid event
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
    if ((id == E_MMGR_ACK) || (id == E_MMGR_NACK)) {
        ret = E_ERR_CLI_FAILED;
        goto out;
    }

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
 * Connect a previously not connected client to MMGR.
 * This function returns when the connection is achieved successfully,
 * or fail on error, or fail after a timeout of 20s.
 * This function shall only be invoked on a valid unconnected handle.
 *
 * @param [in] handle library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if already connected or timeout raised
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_connect(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret;
    mmgr_lib_context_t *p_lib = NULL;
    int err = 0;

    ret = check_state(handle, &p_lib, false);
    if (ret != E_ERR_CLI_SUCCEED)
        goto out;

    if (pipe(p_lib->fd_pipe) < 0) {
        LOG_ERROR("(client=%s) failed to create pipe (%s)", p_lib->cli_name,
                  strerror(errno));
        ret = E_ERR_CLI_FAILED;
    } else {
        ret = cli_connect(p_lib);
    }

    if (ret == E_ERR_CLI_SUCCEED) {
        err = pthread_create(&p_lib->thr_id, NULL, (void *)read_events, p_lib);
        if (err != 0) {
            LOG_ERROR("(fd=%d client=%s) failed to create the reader thread. "
                      "Disconnect the client", p_lib->fd_socket,
                      p_lib->cli_name);
            ret = E_ERR_CLI_FAILED;
        } else {
            pthread_mutex_lock(&p_lib->mtx);
            p_lib->connected = E_CNX_CONNECTED;
            pthread_mutex_unlock(&p_lib->mtx);
        }
    }

out:
    return ret;
}

/**
 * Disconnect from MMGR. If a lock is set, the unlock is done automatically.
 *
 * @param [in] handle library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if already disconnected
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_disconnect(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_FAILED;
    mmgr_lib_context_t *p_lib = NULL;

    ret = check_state(handle, &p_lib, true);
    if (ret == E_ERR_CLI_SUCCEED)
        ret = cli_disconnect(p_lib);

    return ret;
}

/**
 * Acquire the modem resource. This will start the modem if needed.
 * This function returns when acquire request is accepted by MMGR (but not handled yet).
 * It could fail if MMGR is not responsive or after a timeout of 20s.
 *
 * @param [in] handle library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if not connected or timeout raised
 * @return E_ERR_CLI_ALREADY_LOCK if the modem resource is already acquired
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_lock(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    mmgr_lib_context_t *p_lib = NULL;
    mmgr_cli_requests_t request = {.id = E_MMGR_RESOURCE_ACQUIRE };

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
        ret = send_msg(p_lib, &request, E_SEND_THREADED,
                       DEF_MMGR_RESPONSIVE_TIMEOUT);
        if (ret == E_ERR_CLI_SUCCEED) {
            pthread_mutex_lock(&p_lib->mtx);
            p_lib->lock = true;
            pthread_mutex_unlock(&p_lib->mtx);
        } else
            ret = E_ERR_FAILED;
    }
out:
    return ret;
}

/**
 * Release the modem resource. This can stop the modem if no one else holds the resource.
 * This function returns when release request is accepted by MMGR (but not handled yet).
 * It could fail if MMGR is not responsive or after a timeout of 20s.
 *
 * @param [in] handle library handle
 *
 * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
 * @return E_ERR_CLI_FAILED if not connected or timeout
 * @return E_ERR_CLI_ALREADY_UNLOCK if already unlocked
 * @return E_ERR_CLI_SUCCEED
 */
e_err_mmgr_cli_t mmgr_cli_unlock(mmgr_cli_handle_t *handle)
{
    e_err_mmgr_cli_t ret = E_ERR_CLI_SUCCEED;
    mmgr_lib_context_t *p_lib = NULL;
    mmgr_cli_requests_t request = {.id = E_MMGR_RESOURCE_RELEASE };

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
        ret = send_msg(p_lib, &request, E_SEND_THREADED,
                       DEF_MMGR_RESPONSIVE_TIMEOUT);
        if (ret == E_ERR_CLI_SUCCEED) {
            pthread_mutex_lock(&p_lib->mtx);
            p_lib->lock = false;
            pthread_mutex_unlock(&p_lib->mtx);
        } else
            ret = E_ERR_FAILED;
    }
out:
    return ret;
}
