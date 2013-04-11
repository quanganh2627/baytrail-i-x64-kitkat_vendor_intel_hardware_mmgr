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

#define AT_SEC_TIMEOUT 10
#define AT_SIZE 1024
#define SECUR_LIB "libdx_cc7.so"
#define SECUR_CALLBACK "secure_channel_callback"

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
    char buffer[AT_SIZE];
    int read_size = 0;
    uint32_t data_size = 0;
    uint8_t *data = NULL;
    uint8_t *p = NULL;
    uint32_t type = 0;
    int header_size = 0;

    CHECK_PARAM(secur, ret, out);

    if (!secur->enable)
        goto out;

    for (;;) {
        read_size = AT_SIZE;
        memset(buffer, 0, AT_SIZE);
        ret = read_from_tty(secur->fd, buffer, &read_size, AT_READ_MAX_RETRIES);
        if (read_size <= 0)
            break;
        if (ret != E_ERR_SUCCESS)
            goto out;

        data = realloc(data, data_size + read_size);
        if (data == NULL) {
            LOG_ERROR("memory allocation failed");
            goto out;
        }

        p = data + data_size;
        memcpy(p, buffer, sizeof(char) * read_size);
        data_size += read_size;
    }

    /* extract data +xsecchannel: receiver/sender ID, request ID, length, data */
    p = (uint8_t *)strstr("+xsecchannel:", buffer);
    if (p == NULL)
        goto out;
    p = (uint8_t *)strstr(",", (char *)p);
    if (p == NULL)
        goto out;
    p++;
    header_size = p - data;
    data_size -= header_size;

    secur->callback(&type, &data_size, &p);

    /* @TODO: check if the reply is well formated currently, the received
     * header is kept and the data to send overwrites the receive data */
    send_at_timeout(secur->fd, (char *)data, data_size + header_size,
                    AT_SEC_TIMEOUT);

out:
    if (data != NULL)
        free(data);
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

    if (secur->enable) {
        ret = open_tty(secur->dlc, &secur->fd);
        *fd = secur->fd;
    } else
        *fd = CLOSED_FD;

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
    const char at_cmd[] = "AT+XSECCHANNEL?\r";

    CHECK_PARAM(secur, ret, out);

    if (secur->enable)
        ret = send_at_timeout(secur->fd, at_cmd, strlen(at_cmd),
                              AT_SEC_TIMEOUT);
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
            goto out;
        }

        /** see dlsym manpage to understand why this strange cast is used */
        *(void **)&secur->callback = dlsym(secur->hdle, SECUR_CALLBACK);

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
e_mmgr_errors_t secur_get_callback(secur_t *secur, void **callback)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(secur, ret, out);

    if (secur->enable) {
        *callback = (void *)secur->callback;
    } else {
        *callback = NULL;
    }

out:
    return ret;
}
