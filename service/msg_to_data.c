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
#include "msg_to_data.h"
#include <string.h>
#include "logs.h"

/**
 * deserialize uint32 data from buffer
 *
 * @param [in,out] buffer data received. the address is shifted of read size
 * @param [out] value data extracted
 *
 * @return none
 */
static void deserialize_uint32(char **buffer, uint32_t * value)
{
    memcpy(value, *buffer, sizeof(uint32_t));
    *value = ntohl(*value);
    *buffer += sizeof(uint32_t);
}

/**
 * deserialize int data from buffer
 *
 * @param [in,out] buffer data received. the address is shifted of read size
 * @param [out] value data extracted
 *
 * @return none
 */
static void deserialize_int(char **buffer, int *value)
{
    uint32_t tmp;
    deserialize_uint32(buffer, &tmp);
    memcpy(value, &tmp, sizeof(int));
}

/**
 * deserialize size_t data from buffer
 *
 * @param [in,out] buffer data received. the address is shifted of read size
 * @param [out] value data extracted
 *
 * @return none
 */
static void deserialize_size_t(char **buffer, size_t *value)
{
    uint32_t tmp;
    deserialize_uint32(buffer, &tmp);
    memcpy(value, &tmp, sizeof(size_t));
}

/**
 * deserialize bool data from buffer
 *
 * @param [in,out] buffer data received. the address is shifted of read size
 * @param [out] value data extracted
 *
 * @return none
 */
static void deserialize_bool(char **buffer, bool *value)
{
    uint32_t tmp;
    deserialize_uint32(buffer, &tmp);
    memcpy(value, &tmp, sizeof(bool));
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
    char *p = buffer;

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
    deserialize_uint32(&p, &hdr->id);

    /* extract timestamp */
    deserialize_uint32(&p, &hdr->ts);

    /* extract data len */
    deserialize_uint32(&p, &hdr->len);

    if (hdr->len < (len - SIZE_HEADER)) {
        LOG_ERROR("Invalid message. Bad buffer len");
        goto out;
    } else {
        ret = E_ERR_SUCCESS;
    }

out:
    return ret;
}

/**
 * set client structure for empty messages
 *
 * @param [in] event data to send to client
 * @param [out] msg data to send
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_empty(msg_t *msg, mmgr_cli_event_t *event)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(event, ret, out);

    event->data = NULL;
    event->len = 0;
out:
    return ret;
}

/**
 * set client structure for RESPONSE_GET_BACKUP_FILE_PATH message
 *
 * @param [in,out] msg data received
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_bckup_file(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;
    mmgr_cli_backup_path_t *bkup = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    bkup = malloc(sizeof(mmgr_cli_backup_path_t));
    if (bkup == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    bkup->path = calloc(len, sizeof(char));
    if (bkup->path == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    memcpy(&bkup->len, &len, sizeof(size_t));
    memcpy(bkup->path, msg->data, len);
    memset(bkup->path + len, '\0', sizeof(char));
    request->data = bkup;
out:
    return ret;
}

/**
 * set client structure for RESPONSE_FUSE_INFO message
 *
 * @param [in,out] msg data received
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_fuse_info(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;
    mmgr_cli_fuse_info_t *fuse = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    fuse = malloc(sizeof(mmgr_cli_fuse_info_t));
    if (fuse == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    memcpy(fuse->id, msg->data, len);
    request->data = fuse;
out:
    return ret;
}

/**
 * set client structure for RESPONSE_MODEM_NVM_PROGRESS message
 *
 * @param [in,out] msg data received
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_nvm_progress(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;
    mmgr_cli_nvm_update_progress_t *progress = NULL;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    progress = malloc(sizeof(mmgr_cli_nvm_update_progress_t));
    if (progress == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    msg_data = msg->data;
    deserialize_int(&msg_data, &progress->rate);
    request->data = progress;
out:
    return ret;
}

/**
 * set client structure for RESPONSE_MODEM_FW_PROGRESS message
 *
 * @param [in,out] msg data received
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_fw_progress(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;
    mmgr_cli_fw_update_progress_t *progress = NULL;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    progress = malloc(sizeof(mmgr_cli_fw_update_progress_t));
    if (progress == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    msg_data = msg->data;
    deserialize_int(&msg_data, &progress->rate);
    request->data = progress;
out:
    return ret;
}

/**
 * set client structure for RESPONSE_MODEM_FW_RESULT message
 *
 * @param [in,out] msg data received
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_fw_result(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;
    mmgr_cli_fw_update_result_t *result = NULL;
    uint32_t tmp;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    result = malloc(sizeof(mmgr_cli_fw_update_result_t));
    if (result == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    if (len != sizeof(e_modem_fw_error_t)) {
        LOG_ERROR("bad message size");
        goto out;
    }

    msg_data = msg->data;
    deserialize_uint32(&msg_data, &tmp);
    memcpy(&result->id, &tmp, sizeof(e_modem_fw_error_t));
    request->data = result;
out:
    return ret;
}

/**
 * set client structure for RESPONSE_MODEM_NVM_PROGRESS message
 *
 * @param [in,out] msg data received
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_nvm_result(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;
    mmgr_cli_nvm_update_result_t *result = NULL;
    uint32_t tmp = 0;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    result = malloc(sizeof(mmgr_cli_nvm_update_result_t));
    if (result == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    if (len != sizeof(e_modem_nvm_error_t)) {
        LOG_ERROR("bad message size");
        goto out;
    }

    msg_data = msg->data;
    deserialize_uint32(&msg_data, &tmp);
    memcpy(&result->id, &tmp, sizeof(e_modem_nvm_error_t));
    request->data = result;
out:
    return ret;
}

/**
 * set client structure for RESPONSE_MODEM_NVM_ID message
 *
 * @param [in,out] msg data received
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_nvm_id(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;
    mmgr_cli_nvm_read_id_t *nvm = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    nvm = malloc(sizeof(mmgr_cli_nvm_read_id_t));
    if (nvm == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    memcpy(&nvm->result, msg->data, sizeof(bool));
    memcpy(&nvm->len, msg->data + sizeof(uint32_t), sizeof(size_t));

    if ((nvm->len <= 0) && (nvm->len != (msg->hdr.len - 2 * sizeof(uint32_t)))) {
        LOG_ERROR("bad len");
        goto out;
    }

    nvm->path = calloc(len, sizeof(char));
    if (nvm->path == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    memcpy(nvm->path, msg->data + 2 * sizeof(uint32_t), nvm->len);
    memset(nvm->path + nvm->len, '\0', sizeof(char));
    request->data = nvm;
out:
    return ret;
}

/**
 * set client structure for RESPONSE_MODEM_HW_ID message
 *
 * @param [in,out] msg data received
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_hw_id(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;
    mmgr_cli_hw_id_t *hw = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    hw = malloc(sizeof(mmgr_cli_hw_id_t));
    if (hw == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    hw->id = calloc(len, sizeof(char));
    if (hw->id == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    memcpy(&hw->len, &len, sizeof(size_t));
    memcpy(hw->id, msg->data, len);
    memset(hw->id + len, '\0', sizeof(char));
    request->data = hw;
out:
    return ret;
}

/**
 * set client structure for RESPONSE_MODEM_RND message
 *
 * @param [in,out] msg data received
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_rnd_id(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    size_t len;
    mmgr_cli_rnd_path_t *rnd = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    rnd = malloc(sizeof(mmgr_cli_rnd_path_t));
    if (rnd == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    rnd->path = calloc(len, sizeof(char));
    if (rnd->path == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    memcpy(&rnd->len, &len, sizeof(size_t));
    memcpy(rnd->path, msg->data, len);
    memset(rnd->path + len, '\0', sizeof(char));
    request->data = rnd;
out:
    return ret;
}

/**
 * free client structure for message with one element structure
 *
 * @param [in] request data to provide to MMGR client
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t free_one_element_struct(mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    void *p = NULL;

    CHECK_PARAM(request, ret, out);

    p = request->data;
    if (p != NULL) {
        free(p);
        ret = E_ERR_SUCCESS;
    } else {
        LOG_ERROR("failed to free memory");
    }
out:
    return ret;
}

/**
 * free client structure for message RESPONSE_GET_BACKUP_FILE_PATH message
 *
 * @param [in] request data to delete
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t free_data_bckup_file(mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_backup_path_t *bkup = NULL;

    CHECK_PARAM(request, ret, out);

    bkup = request->data;
    if (bkup != NULL) {
        if (bkup->path != NULL)
            free(bkup->path);
        free(bkup);
        ret = E_ERR_SUCCESS;
    } else {
        LOG_ERROR("failed to free memory");
    }
out:
    return ret;
}

/**
 * free client structure for message RESPONSE_MODEM_NVM_ID message
 *
 * @param [in] request data to delete
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t free_data_nvm_id(mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_nvm_read_id_t *nvm = NULL;

    CHECK_PARAM(request, ret, out);

    nvm = request->data;
    if (nvm != NULL) {
        if (nvm->path != NULL)
            free(nvm->path);
        free(nvm);
        ret = E_ERR_SUCCESS;
    } else {
        LOG_ERROR("failed to free memory");
    }
out:
    return ret;
}

/**
 * free client structure for message RESPONSE_MODEM_HW_ID message
 *
 * @param [in] request data to delete
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t free_data_hw_id(mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_hw_id_t *hw = NULL;

    CHECK_PARAM(request, ret, out);

    hw = request->data;
    if (hw != NULL) {
        if (hw->id != NULL)
            free(hw->id);
        free(hw);
        ret = E_ERR_SUCCESS;
    } else {
        LOG_ERROR("failed to free memory");
    }
out:
    return ret;
}

/**
 * free client structure for message RESPONSE_MODEM_RND message
 *
 * @param [in] request data to delete
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t free_data_rnd_id(mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_rnd_path_t *rnd = NULL;

    CHECK_PARAM(request, ret, out);

    rnd = request->data;
    if (rnd != NULL) {
        if (rnd->path != NULL)
            free(rnd->path);
        free(rnd);
        ret = E_ERR_SUCCESS;
    } else {
        LOG_ERROR("failed to free memory");
    }
out:
    return ret;
}

/**
 * free client structure for message empty data message
 *
 * @param [in] event unused param
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t free_data_empty(mmgr_cli_event_t *event)
{
    (void)event;                /* unused */
    return E_ERR_SUCCESS;
}

/**
 * extract data from E_MMGR_RESPONSE_MODEM_FW_PROGRESS message
 *
 * @param [in] msg message received
 * @param [in] fw data extracted
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t extract_data_fw_update(msg_t *msg, mmgr_cli_fw_update_t *fw)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(fw, ret, out);

    if (msg->hdr.len < (4 * sizeof(uint32_t))) {
        LOG_ERROR("mandatory data is missing");
        goto out;
    }

    msg_data = msg->data;
    deserialize_bool(&msg_data, &fw->precheck);
    deserialize_bool(&msg_data, &fw->no_modem_reset);
    deserialize_bool(&msg_data, &fw->erase_all);
    deserialize_size_t(&msg_data, &fw->fls_path_len);

    if (fw->fls_path_len != (msg->hdr.len - (msg_data - msg->data))) {
        LOG_ERROR("bad string length");
        goto out;
    }

    fw->fls_path = malloc(sizeof(fw->fls_path_len) * sizeof(char));
    if (fw->fls_path == NULL) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }
    strncpy(fw->fls_path, msg_data, fw->fls_path_len);
    LOG_DEBUG("fls_path: %s", fw->fls_path);
    ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * extract data from E_MMGR_RESPONSE_MODEM_NVM_PROGRESS message
 *
 * @param [in] msg message received
 * @param [in] nvm data extracted
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t extract_data_nvm_update(msg_t *msg, mmgr_cli_nvm_update_t *nvm)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(nvm, ret, out);

    if (msg->hdr.len < (2 * sizeof(uint32_t))) {
        LOG_ERROR("mandatory data is missing");
        goto out;
    }

    msg_data = msg->data;
    deserialize_bool(&msg_data, &nvm->precheck);
    deserialize_size_t(&msg_data, &nvm->nvm_path_len);

    if (nvm->nvm_path_len != (msg->hdr.len - (msg_data - msg->data))) {
        LOG_ERROR("bad string length");
        goto out;
    }

    nvm->nvm_path = malloc(sizeof(nvm->nvm_path_len) * sizeof(char));
    if (nvm->nvm_path == NULL) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }
    strncpy(nvm->nvm_path, msg_data, nvm->nvm_path_len);
    LOG_DEBUG("nvm->nvm_path %s", nvm->nvm_path);
    ret = E_ERR_SUCCESS;
out:
    return ret;
}
