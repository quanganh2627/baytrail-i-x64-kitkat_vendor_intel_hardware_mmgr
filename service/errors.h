/* Modem Manager - errors header file
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

#ifndef __MMGR_ERRORS_HEADER__
#define __MMGR_ERRORS_HEADER__

typedef enum e_mmgr_errors {
    /* TTY errors */
    E_ERR_TTY_BAD_FD,
    E_ERR_TTY_ERROR,
    E_ERR_TTY_POLLHUP,
    E_ERR_TTY_TIMEOUT,
    /* AT errors */
    E_ERR_AT_CMD_RESEND,
    /* Config file errors */
    E_ERR_MISSING_FILE,
    /* mmgr-test purpose */
    E_ERR_MODEM_OUT,
    /* Client */
    E_ERR_DISCONNECTED,
    /* General */
    E_ERR_BAD_PARAMETER,
    E_ERR_FAILED,
    E_ERR_SUCCESS
} e_mmgr_errors_t;

#define CLOSED_FD -1

#define xstr(s) str(s)
#define str(s) #s

#define CHECK_PARAM(param, err, label) do { \
    if (param == NULL) {                    \
        LOG_DEBUG(xstr(param)" is NULL");   \
        err = E_ERR_BAD_PARAMETER;          \
        goto label;                         \
    }                                       \
} while(0)

#endif                          /* __MMGR_ERRORS_HEADER__ */
