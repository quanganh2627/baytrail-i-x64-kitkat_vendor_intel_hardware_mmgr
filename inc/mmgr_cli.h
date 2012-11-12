/* Modem Manager - client library external include file
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

#ifndef __MMGR_C_CLI__
#define __MMGR_C_CLI__

#ifdef __cplusplus
extern "C" {
#endif

#include "mmgr.h"

    typedef enum e_err_mmgr_cli {
        E_ERR_CLI_SUCCEED,
        E_ERR_CLI_FAILED,
        E_ERR_CLI_ALREADY_LOCK,
        E_ERR_CLI_ALREADY_UNLOCK,
        E_ERR_CLI_BAD_HANDLE,
    } e_err_mmgr_cli_t;

    typedef struct mmgr_cli_event {
        e_mmgr_events_t id;
        void *context;
        size_t len;
        void *data;
    } mmgr_cli_event_t;

    typedef struct mmgr_cli_request {
        e_mmgr_requests_t id;
        size_t len;
        void *data;
    } mmgr_cli_requests_t;

    typedef int (*event_handler) (mmgr_cli_event_t *);

    typedef void *mmgr_cli_handle_t;

    /**
     * create mmgr client library handle. This function should be called first.
     * To avoid memory leaks *handle must be set to NULL by the caller.
     *
     * @param [out] handle library handle
     * @param [in] client_name name of the client
     * @param [in] context pointer to a struct that shall be passed to function
     *             context handle can be NULL if unused.
     *
     * @return E_ERR_CLI_FAILED if client_name is NULL or create handle failed
     * @return E_ERR_CLI_BAD_HANDLE if handle is already created
     * @return E_ERR_CLI_SUCCEED
     */
    e_err_mmgr_cli_t mmgr_cli_create_handle(mmgr_cli_handle_t **handle,
                                            const char *client_name,
                                            void *context);

    /**
     * delete mmgr client library handle
     *
     * @param [in, out] handle library handle
     *
     * @return E_ERR_CLI_BAD_HANDLE if handle is invalid or handle already
     *         deleted
     * @return E_ERR_CLI_FAILED if client is connected
     * @return E_ERR_CLI_SUCCEED
     */
    e_err_mmgr_cli_t mmgr_cli_delete_handle(mmgr_cli_handle_t *handle);

    /**
     * subscribe to an event. This function shall only be invoked on a valid
     * unconnected handle.
     *
     * @param [in, out] handle library handle
     * @param [in] func function pointer to the handle
     * @param [in] id event to subscribe to
     *
     * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
     * @return E_ERR_CLI_FAILED if connected or event already configured or func
     *         is NULL or unknown event
     * @return E_ERR_CLI_SUCCEED
     */
    e_err_mmgr_cli_t mmgr_cli_subscribe_event(mmgr_cli_handle_t *handle,
                                              event_handler func,
                                              e_mmgr_events_t id);

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
                                                e_mmgr_events_t ev);

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
    e_err_mmgr_cli_t mmgr_cli_connect(mmgr_cli_handle_t *handle);

    /**
     * disconnect from mmgr. If a lock is set, the unlock is done automatically
     *
     * @param [in] handle library handle
     *
     * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
     * @return E_ERR_CLI_FAILED if already disconnected
     * @return E_ERR_CLI_SUCCEED
     */
    int mmgr_cli_disconnect(mmgr_cli_handle_t *handle);

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
    e_err_mmgr_cli_t mmgr_cli_lock(mmgr_cli_handle_t *handle);

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
    e_err_mmgr_cli_t mmgr_cli_unlock(mmgr_cli_handle_t *handle);

    /**
     * send an mmgr request
     *
     * @param [in] handle library handle
     * @param [in] request request to send to the mmgr
     *
     * @return E_ERR_CLI_BAD_HANDLE if handle is invalid
     * @return E_ERR_CLI_FAILED if not connected or invalid request id
     * @return E_ERR_CLI_SUCCEED
     */
    e_err_mmgr_cli_t mmgr_cli_send_msg(mmgr_cli_handle_t *handle,
                                       const mmgr_cli_requests_t *request);

    /**
     * Example:
     *
     *   mmgr_create_handle
     *       mmgr_subscribe_event(E1)
     *       mmgr_subscribe_event(E2)
     *       mmgr_subscribe_event(E3)
     *           mmgr_connect (Listen E1, E2 and E3)
     *           mmgr_lock(); // Lock shall be sent once the client is connected
     *           mmgr_disconnect (Stop listening and automatic Unlock )
     *       mmgr_unsubscribe_event(E3)
     *           mmgr_connect (Listen E1 and E2)
     *           mmgr_disconnect(Stop listening)
     *   mmgr_delete_handle
     */

#ifdef __cplusplus
}
#endif
#endif                          /* __MMGR_C_CLI__ */
