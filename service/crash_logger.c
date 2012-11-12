/* Modem Manager - crash logger source file
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

#include <errno.h>
#include "crash_logger.h"
#include "errors.h"
#include "file.h"
#include "logs.h"

#define PANIC_ID_LENGTH_MAX 10

/**
 * Create the necessary files for the crashlogger if there is something to log
 *
 * @param [in,out] events event register
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED if write fails
 * @return E_ERR_BAD_PARAMETER if events is NULL
 */
int crash_logger(modem_info_t *events)
{
    int ret = E_ERR_SUCCESS;
    int err;
    size_t data_size;
    char panic_id[PANIC_ID_LENGTH_MAX];

    CHECK_PARAM(events, ret, out);

    LOG_DEBUG("event=0x%.2X", events->ev);

    if (events->ev & E_EV_AP_RESET) {
        create_empty_file(CL_AP_RESET_FILE, CL_FILE_PERMISSIONS);
    }
    if (events->ev & E_EV_MODEM_SELF_RESET) {
        create_empty_file(CL_MODEM_SELF_RESET_FILE, CL_FILE_PERMISSIONS);
    }
    if (events->ev & E_EV_CORE_DUMP) {
        if (events->panic_id != UNKNOWN_PANIC_ID)
            err = snprintf(panic_id, PANIC_ID_LENGTH_MAX, "%d",
                           events->panic_id);
        else
            err = snprintf(panic_id, PANIC_ID_LENGTH_MAX, "%s",
                           UNKNOWN_PANIC_ID_STR);

        if (err <= 0) {
            LOG_ERROR("failed to convert to string");
        } else {
            data_size = strnlen(panic_id, PANIC_ID_LENGTH_MAX);
            ret = write_to_file(CL_CORE_DUMP_FILE, CL_FILE_PERMISSIONS,
                                panic_id, data_size);
        }
        if (ret != E_ERR_SUCCESS) {
            LOG_ERROR("Failed to create panic file (%s)", strerror(errno));
            ret = E_ERR_FAILED;
        }
    }

    events->ev &= ~E_EV_FORCE_RESET;

    if (events->ev != E_EV_NONE)
        events->ev = E_EV_FORCE_RESET;
    else
        events->ev = E_EV_NONE;
out:
    return ret;
}
