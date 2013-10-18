/* Modem Manager - data to message source file
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
#define MMGR_FW_OPERATIONS
#include "data_to_msg.h"
#include "logs.h"

/**
 * serialize uint32_t data to buffer
 *
 * @param [out] buffer output buffer
 * @param [in] value size_t value to serialize
 *
 * @return none
 */
static void serialize_uint32(char **buffer, uint32_t value)
{
    value = htonl(value);
    memcpy(*buffer, &value, sizeof(uint32_t));
    *buffer += sizeof(uint32_t);
}

/**
 * serialize int data to buffer
 *
 * @param [out] buffer output buffer
 * @param [in] value size_t value to serialize
 *
 * @return none
 */
static void serialize_int(char **buffer, int value)
{
    uint32_t tmp;

    memcpy(&tmp, &value, sizeof(int));
    serialize_uint32(buffer, tmp);
}

/**
 * serialize size_t data to buffer
 *
 * @param [out] buffer output buffer
 * @param [in] value size_t value to serialize
 *
 * @return none
 */
static void serialize_size_t(char **buffer, size_t value)
{
    uint32_t tmp;

    memcpy(&tmp, &value, sizeof(size_t));
    serialize_uint32(buffer, tmp);
}

/**
 * set header
 *
 * @param [in,out] msg received message
 *
 * @return E_ERR_BAD_PARAMETER if msg is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t set_header(msg_t *msg)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    struct timeval ts;
    uint32_t tmp;
    char *msg_data = msg->data;

    CHECK_PARAM(msg, ret, out);

    /* setting id */
    serialize_uint32(&msg_data, msg->hdr.id);

    /* setting timestamp */
    gettimeofday(&ts, NULL);
    memcpy(&tmp, &ts.tv_sec, sizeof(ts.tv_sec));
    serialize_uint32(&msg_data, tmp);

    /* setting size */
    serialize_uint32(&msg_data, msg->hdr.len);
out:
    return ret;
}

/**
 * free message data
 *
 * @param [in] msg data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t delete_msg(msg_t *msg)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(msg, ret, out);

    if (msg->data != NULL)
        free(msg->data);
    else
        ret = E_ERR_FAILED;

out:
    return ret;
}

/**
 * handle message allocation memory and set message header
 *
 * @private
 *
 * @param [in,out] msg data to send
 * @param [in] msg_data data to send
 * @param [in] id message id
 * @param [in] size data size
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
static e_mmgr_errors_t prepare_msg(msg_t *msg, char **msg_data,
                                   e_mmgr_events_t id, size_t *size)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(msg_data, ret, out);

    len = SIZE_HEADER + *size;
    msg->data = calloc(len, sizeof(char));
    if (msg->data == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    memcpy(&msg->hdr.id, &id, sizeof(id));
    memcpy(&msg->hdr.len, size, sizeof(size_t));
    ret = set_header(msg);
    *size = len;
    *msg_data = msg->data + SIZE_HEADER;

out:
    return ret;
}

/**
 * handle E_MMGR_RESPONSE_MODEM_HW_ID message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_modem_hw_id(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_hw_id_t *hw = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* msg->hdr.len is used to provide string lengh */
    size = sizeof(char) * hw->len;
    ret = prepare_msg(msg, &msg_data, E_MMGR_RESPONSE_MODEM_HW_ID, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    memcpy(msg_data, hw->id, sizeof(char) * hw->len);

    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle E_MMGR_RESPONSE_FUSE_INFO message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_fuse_info(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_fuse_info_t *fuse = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* msg->hdr.len is used to provide string lengh */
    size = sizeof(char) * FUSE_LEN;
    ret = prepare_msg(msg, &msg_data, E_MMGR_RESPONSE_FUSE_INFO, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    memcpy(msg_data, fuse->id, sizeof(char) * FUSE_LEN);

    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle E_MMGR_NOTIFY_AP_RESET message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_ap_reset(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_internal_ap_reset_t *ap = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    size = sizeof(uint32_t) + ap->len + ap->extra_len;
    ret = prepare_msg(msg, &msg_data, E_MMGR_NOTIFY_AP_RESET, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    serialize_size_t(&msg_data, ap->len);
    memcpy(msg_data, ap->name, sizeof(char) * ap->len);
    if (ap->extra_len)
        /* Note that 'extra_data' is already serialized (as it's the raw data
         * from the client recovery request) so can be copied 'as is'. */
        memcpy(msg_data + ap->len, ap->extra_data,
               sizeof(char) * ap->extra_len);
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle E_MMGR_RESPONSE_MODEM_FW_RESULT message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_modem_fw_result(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    uint32_t tmp;
    size_t size;
    mmgr_cli_fw_update_result_t *result = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    size = sizeof(uint32_t);
    ret = prepare_msg(msg, &msg_data, E_MMGR_RESPONSE_MODEM_FW_RESULT, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    memcpy(&tmp, &result->id, sizeof(e_modem_fw_error_t));
    serialize_uint32(&msg_data, tmp);
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle E_MMGR_NOTIFY_CORE_DUMP_COMPLETE message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_core_dump(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    uint32_t tmp;
    size_t size;
    mmgr_cli_core_dump_t *cd = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* this structure is composed of 5 elements: 3 integers and two string */
    size = 3 * sizeof(uint32_t) +
           sizeof(char) * (cd->path_len + cd->reason_len);
    ret = prepare_msg(msg, &msg_data, E_MMGR_NOTIFY_CORE_DUMP_COMPLETE, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    memcpy(&tmp, &cd->state, sizeof(cd->state));
    serialize_uint32(&msg_data, tmp);
    serialize_size_t(&msg_data, cd->path_len);
    serialize_size_t(&msg_data, cd->reason_len);
    memcpy(msg_data, cd->path, sizeof(char) * cd->path_len);
    if (cd->reason_len > 0)
        memcpy(msg_data + cd->path_len, cd->reason,
               sizeof(char) * cd->reason_len);

    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle E_MMGR_NOTIFY_ERROR message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_error(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_error_t *err = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* this structure is composed of 3 elements: 2 integers and a string */
    size = 2 * sizeof(uint32_t) + sizeof(char) * err->len;
    ret = prepare_msg(msg, &msg_data, E_MMGR_NOTIFY_ERROR, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    serialize_int(&msg_data, err->id);
    serialize_size_t(&msg_data, err->len);
    memcpy(msg_data, err->reason, sizeof(char) * err->len);
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle SET_NAME message allocation
 *
 * @param [out] msg data to send
 * @param [in] request request to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_name(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    if (request->len <= 0) {
        LOG_ERROR("name is empty");
        goto out;
    }

    /* msg.hdr is used to store the string length */
    size = request->len;
    ret = prepare_msg(msg, &msg_data, request->id, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    /* set name */
    memcpy(msg->data + SIZE_HEADER, request->data, sizeof(char) * request->len);
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle SET_EVENTS message allocation
 *
 * @param [out] msg data to send
 * @param [in] request request to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_filter(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    uint32_t tmp;
    size_t size;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    size = sizeof(uint32_t);
    ret = prepare_msg(msg, &msg_data, request->id, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    /* set filter */
    memcpy(&tmp, request->data, sizeof(int));
    serialize_uint32(&msg_data, tmp);
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle REQUEST_MODEM_RESTART message allocation
 *
 * @param [out] msg data to send
 * @param [in] request request to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_restart(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    char *msg_data = NULL;
    size_t size = 0;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* restart is optional */
    mmgr_cli_restart_t *restart = request->data;
    if (restart)
        size = sizeof(uint32_t);
    ret = prepare_msg(msg, &msg_data, request->id, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    if (restart)
        serialize_uint32(&msg_data, restart->optional);
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle REQUEST_MODEM_RECOVERY message allocation
 *
 * @param [out] msg data to send
 * @param [in] request request to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_recovery(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size = 0, string_size = 0;
    char *msg_data = NULL;
    size_t i, req_size = request->len;
    mmgr_cli_recovery_cause_t *req_extra_data = request->data;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* Some sanity checks */
    if ((req_size > (MMGR_CLI_MAX_RECOVERY_CAUSES *
                     sizeof(mmgr_cli_recovery_cause_t))) ||
        ((req_size % sizeof(mmgr_cli_recovery_cause_t)) != 0)) {
        LOG_ERROR("invalid extra data size (%d), ignoring", req_size);
        req_size = 0;
    }
    if ((req_size != 0) &&
        ((req_extra_data == NULL) ||
         ((((int)req_extra_data) %
           __alignof__(mmgr_cli_recovery_cause_t)) != 0))) {
        LOG_ERROR("invalid extra data pointer (%p), ignoring", req_extra_data);
        req_size = 0;
    }
    req_size /= sizeof(mmgr_cli_recovery_cause_t);
    for (i = 0; i < req_size; i++) {
        if ((req_extra_data[i].len > MMGR_CLI_MAX_RECOVERY_CAUSE_LEN) ||
            (req_extra_data[i].cause == NULL)) {
            LOG_ERROR("invalid extra data entry (index %d, len %d, ptr %p)", i,
                      req_extra_data[i].len, req_extra_data[i].cause);
            req_size = 0;
            break;
        }
        string_size += req_extra_data[i].len;
    }

    if (req_size != 0)
        size = sizeof(size_t) + req_size * sizeof(size_t) + string_size;

    ret = prepare_msg(msg, &msg_data, request->id, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    /* Serialize client request */
    if (req_size != 0) {
        serialize_size_t(&msg_data, req_size);
        for (i = 0; i < req_size; i++) {
            serialize_size_t(&msg_data, req_extra_data[i].len);
            memcpy(msg_data, req_extra_data[i].cause, req_extra_data[i].len);
            msg_data += req_extra_data[i].len;
        }
    }
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * set buffer to send empty message
 *
 * @param [out] msg data to send
 * @param [in] request request to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_empty(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    size = 0;
    ret = prepare_msg(msg, &msg_data, request->id, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = E_ERR_SUCCESS;

out:
    return ret;
}
