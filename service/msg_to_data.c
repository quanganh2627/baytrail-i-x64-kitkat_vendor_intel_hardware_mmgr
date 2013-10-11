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
static void deserialize_uint32(char **buffer, uint32_t *value)
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
    uint32_t tmp = 0;

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
    uint32_t tmp = 0;

    deserialize_uint32(buffer, &tmp);
    memcpy(value, &tmp, sizeof(size_t));
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
    /* the buffer will be freed by the matching freed function */
    fuse = malloc(sizeof(mmgr_cli_fuse_info_t));
    if (fuse == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    memcpy(fuse->id, msg->data, len);
    ret = E_ERR_SUCCESS;

out:
    request->data = fuse;
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
    mmgr_cli_hw_id_t *hw = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* calloc is used to be sure that id is NULL the buffer will be freed by
     * the matching freed function */
    hw = calloc(1, sizeof(mmgr_cli_hw_id_t));
    if (hw == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }
    memcpy(&hw->len, &msg->hdr.len, sizeof(size_t));

    /* the buffer will be freed by the matching freed function */
    hw->id = malloc((hw->len + 1) * sizeof(char));
    if (hw->id == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    memcpy(hw->id, msg->data, hw->len);
    memset(hw->id + hw->len, '\0', sizeof(char));
    ret = E_ERR_SUCCESS;

out:
    request->data = hw;
    return ret;
}

/**
 * extract data from E_MMGR_NOTIFY_AP_RESET message
 *
 * @param [in] msg message received
 * @param [in] request
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_ap_reset(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_ap_reset_t *ap = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* calloc is used to be sure that name is NULL the buffer will be freed by
     * the matching freed function */
    ap = calloc(1, sizeof(mmgr_cli_ap_reset_t));
    if (ap == NULL) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }
    memcpy(&ap->len, &msg->hdr.len, sizeof(size_t));

    /* the buffer will be freed by the matching freed function */
    ap->name = malloc((ap->len + 1) * sizeof(char));
    if (ap->name == NULL) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }

    memcpy(ap->name, msg->data, ap->len);
    memset(ap->name + ap->len, '\0', sizeof(char));
    ret = E_ERR_SUCCESS;

out:
    request->data = ap;
    return ret;
}

/**
 * extract data from E_MMGR_NOTIFY_CORE_DUMP_COMPLETE message
 *
 * @param [in] msg message received
 * @param [in] request
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_core_dump(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_core_dump_t *cd = NULL;
    char *msg_data = NULL;
    uint32_t tmp = 0;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* this structure is composed of 4 elements: 3 integer and a string */
    if (msg->hdr.len < (3 * sizeof(uint32_t))) {
        LOG_ERROR("mandatory data is missing");
        goto out;
    }

    /* calloc is used to be sure that path is NULL the buffer will be freed by
     * the matching freed function */
    cd = calloc(1, sizeof(mmgr_cli_core_dump_t));
    if (cd == NULL) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }
    msg_data = msg->data;
    deserialize_uint32(&msg_data, &tmp);
    memcpy(&cd->state, &tmp, sizeof(cd->state));
    deserialize_size_t(&msg_data, &cd->path_len);
    deserialize_size_t(&msg_data, &cd->reason_len);

    if ((cd->path_len + cd->reason_len) !=
        (msg->hdr.len - (msg_data - msg->data))) {
        LOG_ERROR("bad string length");
        goto out;
    }

    /* the buffer will be freed by the matching freed function */
    cd->path = malloc((cd->path_len + 1) * sizeof(char));
    if (cd->path == NULL) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }
    memcpy(cd->path, msg_data, cd->path_len);
    memset(cd->path + cd->path_len, '\0', sizeof(char));

    if (cd->reason_len > 0) {
        cd->reason = malloc((cd->reason_len + 1) * sizeof(char));
        if (cd->reason == NULL) {
            LOG_ERROR("memory allocation failed");
            goto out;
        }
        memcpy(cd->reason, msg_data + cd->path_len, cd->reason_len);
        memset(cd->reason + cd->reason_len, '\0', sizeof(char));
    } else {
        cd->reason = NULL;
    }

    ret = E_ERR_SUCCESS;

out:
    request->data = cd;
    return ret;
}

/**
 * extract data from E_MMGR_NOTIFY_ERROR message
 *
 * @param [in] msg message received
 * @param [in] request
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t set_data_error(msg_t *msg, mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_error_t *err = NULL;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    /* this structure is composed of 3 elements: 2 integer and a string */
    if (msg->hdr.len < (2 * sizeof(uint32_t))) {
        LOG_ERROR("mandatory data is missing");
        goto out;
    }

    /* calloc is used to be sure that reason is NULL the buffer will be freed
     * by the matching freed function */
    err = calloc(1, sizeof(mmgr_cli_error_t));
    if (err == NULL) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }
    msg_data = msg->data;
    deserialize_int(&msg_data, &err->id);
    deserialize_size_t(&msg_data, &err->len);

    if (err->len != (msg->hdr.len - (msg_data - msg->data))) {
        LOG_ERROR("bad string length");
        goto out;
    }

    /* the buffer will be freed by the matching freed function */
    err->reason = malloc((err->len + 1) * sizeof(char));
    if ((err == NULL) || (err->reason == NULL)) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }

    memcpy(err->reason, msg_data, err->len);
    memset(err->reason + err->len, '\0', sizeof(char));
    ret = E_ERR_SUCCESS;

out:
    request->data = err;
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
    uint32_t tmp = 0;
    char *msg_data = NULL;

    CHECK_PARAM(msg, ret, out);
    CHECK_PARAM(request, ret, out);

    memcpy(&len, &msg->hdr.len, sizeof(uint32_t));
    if (len != sizeof(e_modem_fw_error_t)) {
        LOG_ERROR("bad message size");
        goto out;
    }

    /* the buffer will be freed by the matching freed function */
    result = malloc(sizeof(mmgr_cli_fw_update_result_t));
    if (result == NULL) {
        LOG_ERROR("memory allocation fails");
        goto out;
    }

    msg_data = msg->data;
    deserialize_uint32(&msg_data, &tmp);
    memcpy(&result->id, &tmp, sizeof(e_modem_fw_error_t));
    ret = E_ERR_SUCCESS;

out:
    request->data = result;
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
 * free client structure for message CORE_DUMP_COMPLETE message
 *
 * @param [in] request data to delete
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t free_data_core_dump(mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_core_dump_t *cd = NULL;

    CHECK_PARAM(request, ret, out);

    cd = request->data;
    if (cd != NULL) {
        if (cd->path != NULL)
            free(cd->path);
        if (cd->reason != NULL)
            free(cd->reason);
        free(cd);
        ret = E_ERR_SUCCESS;
    } else {
        LOG_ERROR("failed to free memory");
    }
out:
    return ret;
}

/**
 * free client structure for message NOTIFY_AP_RESET message
 *
 * @param [in] request data to delete
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t free_data_ap_reset(mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_ap_reset_t *ap_rst = NULL;

    CHECK_PARAM(request, ret, out);

    ap_rst = request->data;
    if (ap_rst != NULL) {
        if (ap_rst->name != NULL)
            free(ap_rst->name);
        free(ap_rst);
        ret = E_ERR_SUCCESS;
    } else {
        LOG_ERROR("failed to free memory");
    }
out:
    return ret;
}

/**
 * free client structure for message NOTIFY_ERROR message
 *
 * @param [in] request data to delete
 *
 * @return E_ERR_BAD_PARAMETER if event or/and msg is/are invalid
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t free_data_error(mmgr_cli_event_t *request)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_error_t *err = NULL;

    CHECK_PARAM(request, ret, out);

    err = request->data;
    if (err != NULL) {
        if (err->reason != NULL)
            free(err->reason);
        free(err);
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
