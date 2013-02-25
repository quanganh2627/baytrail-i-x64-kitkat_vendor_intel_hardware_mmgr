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
static inline void serialize_uint32(char **buffer, uint32_t value)
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
static inline void serialize_int(char **buffer, int value)
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
static inline void serialize_size_t(char **buffer, size_t value)
{
    uint32_t tmp;
    memcpy(&tmp, &value, sizeof(size_t));
    serialize_uint32(buffer, tmp);
}

/**
 * serialize bool data to buffer
 *
 * @param [out] buffer output buffer
 * @param [in] value bool value to serialize
 *
 * @return none
 */
static inline void serialize_bool(char **buffer, bool value)
{
    uint32_t tmp;
    memcpy(&tmp, &value, sizeof(bool));
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
static inline e_mmgr_errors_t prepare_msg(msg_t *msg, char **msg_data,
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
 * handle E_MMGR_RESPONSE_GET_BACKUP_FILE_PATH message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_backup_file_path(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_backup_path_t *bckup = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* msg->hdr.len is used to provide string length */
    size = bckup->len;
    ret =
        prepare_msg(msg, &msg_data, E_MMGR_RESPONSE_GET_BACKUP_FILE_PATH,
                    &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    if (bckup->path != NULL) {
        memcpy(msg_data, bckup->path, sizeof(char) * bckup->len);
        ret = E_ERR_SUCCESS;
    }

out:
    return ret;
}

/**
 * handle E_MMGR_RESPONSE_MODEM_RND message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_rnd(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_rnd_path_t *rnd = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* msg->hdr.len is used to provide string lengh */
    size = sizeof(char) * rnd->len;
    ret = prepare_msg(msg, &msg_data, E_MMGR_RESPONSE_MODEM_RND, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    if (rnd->path != NULL) {
        memcpy(msg_data, rnd->path, sizeof(char) * rnd->len);
        ret = E_ERR_SUCCESS;
    }
out:
    return ret;
}

/**
 * handle E_MMGR_RESPONSE_MODEM_FW_PROGRESS message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_modem_fw_progress(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_fw_update_progress_t *progress = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    size = sizeof(uint32_t);
    ret = prepare_msg(msg, &msg_data, E_MMGR_RESPONSE_MODEM_FW_PROGRESS, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    serialize_int(&msg_data, progress->rate);

    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle E_MMGR_RESPONSE_MODEM_NVM_PROGRESS message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_modem_nvm_progress(msg_t *msg,
                                           mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_nvm_update_progress_t *progress = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    size = sizeof(uint32_t);
    ret =
        prepare_msg(msg, &msg_data, E_MMGR_RESPONSE_MODEM_NVM_PROGRESS, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    serialize_int(&msg_data, progress->rate);

    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * handle E_MMGR_RESPONSE_MODEM_NVM_ID message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_nvm_id(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_nvm_read_id_t *nvm = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    size = 2 * sizeof(uint32_t) + sizeof(char) * nvm->len;
    ret = prepare_msg(msg, &msg_data, E_MMGR_RESPONSE_MODEM_NVM_ID, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    serialize_bool(&msg_data, nvm->result);
    serialize_size_t(&msg_data, nvm->len);

    if (nvm->path != NULL)
        memcpy(msg_data, nvm->path, sizeof(char) * nvm->len);

    ret = E_ERR_SUCCESS;
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
 * handle E_MMGR_RESPONSE_MODEM_NVM_RESULT message allocation
 *
 * @param [in,out] msg data to send
 * @param [in] data data to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_modem_nvm_result(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    uint32_t tmp;
    size_t size;
    mmgr_cli_nvm_update_result_t *result = request->data;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    size = sizeof(uint32_t);
    ret = prepare_msg(msg, &msg_data, E_MMGR_RESPONSE_MODEM_NVM_RESULT, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    memcpy(&tmp, &result->id, sizeof(e_modem_nvm_error_t));
    serialize_uint32(&msg_data, tmp);
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
 * handle E_MMGR_REQUEST_MODEM_FW_UPDATE message allocation
 *
 * @param [out] msg data to send
 * @param [in] request request to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_fw_update(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_fw_update_t *fw = NULL;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    fw = request->data;

    size = 4 * sizeof(uint32_t) + sizeof(char) * fw->fls_path_len;
    ret = prepare_msg(msg, &msg_data, E_MMGR_REQUEST_MODEM_FW_UPDATE, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    serialize_bool(&msg_data, fw->precheck);
    serialize_bool(&msg_data, fw->no_modem_reset);
    serialize_bool(&msg_data, fw->erase_all);
    serialize_size_t(&msg_data, fw->fls_path_len);

    if (fw->fls_path != NULL)
        memcpy(msg_data, fw->fls_path, sizeof(char) * fw->fls_path_len);

    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * handle E_MMGR_REQUEST_MODEM_NVM_UPDATE message allocation
 *
 * @param [out] msg data to send
 * @param [in] request request to send
 *
 * @return E_ERR_BAD_PARAMETER if request or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_msg_nvm_update(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t size;
    mmgr_cli_nvm_update_t *nvm = NULL;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    nvm = request->data;

    size = 2 * sizeof(uint32_t) + sizeof(char) * nvm->nvm_path_len;
    ret = prepare_msg(msg, &msg_data, E_MMGR_REQUEST_MODEM_NVM_UPDATE, &size);
    if (ret != E_ERR_SUCCESS)
        goto out;

    serialize_bool(&msg_data, nvm->precheck);
    serialize_size_t(&msg_data, nvm->nvm_path_len);

    if (nvm->nvm_path != NULL)
        memcpy(msg_data, nvm->nvm_path, sizeof(char) * nvm->nvm_path_len);

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
