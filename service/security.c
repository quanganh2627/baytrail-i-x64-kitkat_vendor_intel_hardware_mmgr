/* Modem Manager - secure source file
**
** Copyright (C) Intel 2013
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

#include "at.h"
#include "logs.h"
#include "security.h"
#include "tty.h"
#include <dlfcn.h>
#include <resolv.h>

#define AT_SEC_RETRY 4
#define AT_SIZE 1024
#define SECUR_LIB "libdx_cc7.so"
#define SECUR_CALLBACK "secure_channel_callback"

/* @TODO: avoid this dupplication */
#define SECURE_CH_DATA_FREE_RETURN_DATA   0

#define MSG_TYPE_INDX 0
#define MSG_LEN_INDX 2
#define MSG_DATA_INDX 4
#define AT_SECUR "xsecchannel"
#define MSG_START_STR "+"AT_SECUR ":"
#define MSG_ANSWER_START "+"AT_SECUR "="
#define MAX_TLV_LEN 2 * 1024

/**
 * read the message provided by the modem
 *
 * @param [in] fd file descriptor
 * @param [out] received buffer containing the read data. should be freed by the
 *              user (even if function failed)
 * @param [out] send_id send message id
 * @param [out] req_id request id
 * @param [out] len received length
 *
 * @return E_ERR_BAD_PARAMETER
 * @return E_ERR_FAILED
 * @return E_ERR_SUCCESS
 */
static e_mmgr_errors_t read_msg(int fd, char **received, int *send_id,
                                int *req_id, int *len)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    int read_size;
    int remain = 0;
    int tmp = 0;
    char buffer[AT_SIZE + 1];
    char *data = NULL;
    int header_len = 0;
    int data_len = 0;

    CHECK_PARAM(received, ret, out);
    CHECK_PARAM(send_id, ret, out);
    CHECK_PARAM(req_id, ret, out);
    CHECK_PARAM(len, ret, out);

    do {
        read_size = AT_SIZE;
        ret = read_from_tty(fd, buffer, &read_size, AT_READ_MAX_RETRIES);
        if ((read_size <= 0) || (ret != E_ERR_SUCCESS))
            goto out;
        buffer[read_size] = '\0';
        /* extract data +XSECCHANNEL: receiver/sender ID, request ID, length,
         * data */
        data = strcasestr(buffer, MSG_START_STR);
    } while (data == NULL);
    LOG_DEBUG("Received: %s", data);

    ret = E_ERR_FAILED;
    /* extract sender, request IDs and length. If the pattern is not present in
     * the chuck it will fail. But this should not happen as we should receive
     * it in one chunck */
    data += strlen(MSG_START_STR);
    if (sscanf(data, "%d,%d,%d,", send_id, req_id, len) != 3)
        goto out;

    if (*len > MAX_TLV_LEN) {
        LOG_ERROR("TLV size is too high");
        goto out;
    }

    /* extract the data. it begins with " */
    data = strstr(data, "\"");
    if (!data)
        goto out;
    /* remove " character */
    data++;

    /* add +3 (\r, \n, and ") in case we haven't read everything yet */
    *received = malloc(*len + 3);
    if (!*received) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }

    header_len = data - buffer;
    if (header_len > read_size)
        goto out;

    data_len = read_size - header_len;
    if (data_len < 0)
        goto out;
    /* remove useless received data */
    if (data_len > *len)
        data_len = *len;

    memcpy(*received, data, data_len);

    if (data_len != *len) {
        remain = *len - data_len + 2;
        tmp = remain;
        ret = read_from_tty(fd, *received + data_len, &tmp,
                            AT_READ_MAX_RETRIES);
        if ((ret != E_ERR_SUCCESS) || (tmp != remain))
            goto out;
    }

    memset(*received + *len, '\0', 1);
    ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * decode a message received by the modem
 *
 * @param [in] received data to decode
 * @param [in] rec_len size of received buffer
 * @param [out] type message type
 * @param [out] length length of the converted data
 * @param [out] conv converted data. should be freed by the user
 *
 * @return E_ERR_BAD_PARAMETER
 * @return E_ERR_FAILED
 * @return E_ERR_SUCCESS
 */
static e_mmgr_errors_t decode_data(char *received, int rec_len, uint32_t *type,
                                   uint32_t *length, uint8_t **conv)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    uint8_t *tmp = NULL;
    int len = 0;

    CHECK_PARAM(received, ret, out);
    CHECK_PARAM(type, ret, out);
    CHECK_PARAM(length, ret, out);
    CHECK_PARAM(conv, ret, out);

    *conv = NULL;
    tmp = calloc(rec_len, sizeof(uint8_t));
    if (!tmp)
        goto out;

    if ((len = b64_pton(received, tmp, rec_len)) < 0)
        goto out;

    /* extract type and length */
    memcpy(length, &len, sizeof(*length));
    memset(type, 0, sizeof(*type));
    memcpy(type, &tmp[MSG_TYPE_INDX], 2);

    *conv = malloc(sizeof(uint8_t) * *length);
    if (*conv) {
        memcpy(*conv, tmp, *length);
        ret = E_ERR_SUCCESS;
    }

out:
    if (ret != E_ERR_SUCCESS)
        LOG_ERROR("operation failed");
    if (tmp)
        free(tmp);
    return ret;
}

/**
 * encode a message received by the modem
 *
 * @param [in] send_id message id
 * @param [in] req_id request id
 * @param [in] src data received by the secur lib
 * @param [in] src_len src length
 * @param [out] send message encoded. should be freed by the user
 * @param [out] send_len message length
 *
 * @return E_ERR_BAD_PARAMETER
 * @return E_ERR_FAILED
 * @return E_ERR_SUCCESS
 */
static e_mmgr_errors_t encode_data(int send_id, int req_id, const uint8_t *src,
                                   uint32_t src_len, char **send, int *send_len)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    char *conv = NULL;
    size_t data_len = 0;
    int conv_len = 0;

    CHECK_PARAM(src, ret, out);
    CHECK_PARAM(send, ret, out);

    if (src_len <= 0)
        goto out;

    *send = NULL;
    data_len = src_len * sizeof(char);
    conv_len = data_len * 4 / 3 + 4;

    conv = calloc(conv_len, sizeof(char));
    if (!conv)
        goto out;

    /* convert data */
    conv_len = b64_ntop(src, data_len, conv, conv_len);
    if (conv_len < 0) {
        LOG_ERROR("conversion has failed");
        goto out;
    }

    /* send_id / req_id are on 16 bits they should not use more than 5 bytes
     * conv_len will not be more than 12 bytes */
    *send_len = conv_len + (5 * 2) + 12 +
                (sizeof(char) * (10 + strlen(MSG_ANSWER_START)));
    *send = malloc(sizeof(char) * *send_len);
    if (!*send)
        goto out;

    *send_len = snprintf(*send, *send_len, "at%s%d,%d,%d,\"%s\"\r\n",
                         MSG_ANSWER_START, send_id, req_id, conv_len, conv);
    ret = E_ERR_SUCCESS;

out:
    if (conv)
        free(conv);
    if (ret != E_ERR_SUCCESS)
        LOG_ERROR("operation failed");
    return ret;
}

/**
 * Handle secur event type
 *
 * @param [in] secur security handler
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t secur_event(secur_t *secur)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    char *received = NULL;
    char *send = NULL;
    int rec_len = 0;
    int send_len = 0;
    uint8_t *conv = NULL;
    uint8_t *p_conv = NULL;
    uint32_t type = 0;
    uint32_t length = 0;
    int send_id = 0;
    int req_id = 0;
    int err = 0;

    CHECK_PARAM(secur, ret, out);

    if (!secur->enable)
        goto out;

    ret = read_msg(secur->fd, &received, &send_id, &req_id, &rec_len);
    if ((ret != E_ERR_SUCCESS) || (received == NULL)) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = decode_data(received, rec_len, &type, &length, &conv);
    if ((ret != E_ERR_SUCCESS) || (conv == NULL)) {
        ret = E_ERR_FAILED;
        goto out;
    }

    /* the secure library will overwrite the pointer. Save the pointer to be
     * able to free the memory */
    p_conv = conv;
    if ((err = secur->callback(&type, &length, &conv)) < 0) {
        LOG_ERROR("secur channel failed with err=%d", err);
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = encode_data(send_id, req_id, conv, length, &send, &send_len);
    if (ret == E_ERR_SUCCESS)
        ret = send_at_retry(secur->fd, send, send_len, AT_SEC_RETRY,
                            AT_ANSWER_SHORT_TIMEOUT);

    /* free memory allocation on secure lib side */
    type = SECURE_CH_DATA_FREE_RETURN_DATA;
    secur->callback(&type, NULL, NULL);

out:
    if (received != NULL)
        free(received);
    if (p_conv != NULL)
        free(p_conv);
    if (send)
        free(send);
    return ret;
}

/**
 * register the secur module. It returns the file descriptor
 *
 * @param [in] secur security handler
 * @param [out] fd file descriptor to return
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t secur_register(secur_t *secur, int *fd)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(secur, ret, out);

    secur->fd = CLOSED_FD;
    if (secur->enable)
        ret = open_tty(secur->dlc, &secur->fd);

    *fd = secur->fd;

out:
    return ret;
}

/**
 * Start the security module
 *
 * @param [in] secur security handler
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t secur_start(secur_t *secur)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    const char at_cmd[] = "at+" AT_SECUR "?\r";

    CHECK_PARAM(secur, ret, out);

    if (secur->enable) {
        LOG_DEBUG("Send of: %s", at_cmd);
        /* The modem doesn't answer OK to this AT command. That's why this
         * function is used */
        ret = write_to_tty(secur->fd, at_cmd, strlen(at_cmd));
    }

out:
    return ret;
}

/**
 * Stop the security module
 *
 * @param [in] secur security handler
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t secur_stop(secur_t *secur)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(secur, ret, out);

    if (secur->enable)
        ret = close_tty(&secur->fd);

out:
    return ret;
}

/**
 * Initialize the security module
 *
 * @param [in] secur security handler
 * @param [in] config mmgr config data
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t secur_init(secur_t *secur, mmgr_configuration_t *config)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    char *p = NULL;

    CHECK_PARAM(secur, ret, out);
    CHECK_PARAM(config, ret, out);

    secur->fd = CLOSED_FD;
    secur->enable = config->secur_enable;

    if (config->secur_enable) {
        secur->dlc = config->secur_dlc;

        secur->hdle = dlopen(SECUR_LIB, RTLD_LAZY);
        if (secur->hdle == NULL) {
            LOG_ERROR("failed to open library");
            ret = E_ERR_FAILED;
            dlerror();
            goto out;
        }

        secur->callback = dlsym(secur->hdle, SECUR_CALLBACK);

        p = (char *)dlerror();
        if (p != NULL) {
            LOG_ERROR("An error ocurred during symbol resolution");
            ret = E_ERR_FAILED;
            dlclose(secur->hdle);
            secur->hdle = NULL;
        }
    } else {
        secur->hdle = NULL;
    }

out:
    return ret;
}

/**
 * Dispose the security module
 *
 * @param [in] secur security handler
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t secur_dispose(secur_t *secur)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(secur, ret, out);

    if (secur->enable)
        goto out;

    if (secur->hdle != NULL) {
        dlclose(secur->hdle);
        secur->hdle = NULL;
    } else {
        ret = E_ERR_FAILED;
    }

out:
    return ret;
}

/**
 * Provide the secur callback function
 *
 * @param [in] secur security handler
 * @param [out] callback callback function
 *
 * @return E_ERR_BAD_PARAMETER mmgr is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t secur_get_callback(secur_t *secur,
                                   secur_callback_fptr_t *callback)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(secur, ret, out);

    if (secur->enable)
        *callback = secur->callback;
    else
        *callback = NULL;

out:
    return ret;
}
