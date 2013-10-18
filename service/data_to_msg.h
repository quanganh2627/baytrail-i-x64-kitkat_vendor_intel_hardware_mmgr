/* Modem Manager - data to message header file
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

#ifndef __MMGR_DATA_TO_MSG_HEADER__
#define __MMGR_DATA_TO_MSG_HEADER__

#define MMGR_FW_OPERATIONS
#include "mmgr.h"
#include "mmgr_cli.h"
#include "client_cnx.h"
#include "errors.h"

/* internal structure used by mmgr */
typedef struct mmgr_cli_internal_ap_reset {
    size_t len;
    char *name;
    size_t extra_len;
    char *extra_data;
} mmgr_cli_internal_ap_reset_t;

e_mmgr_errors_t delete_msg(msg_t *msg);

/* used by lib client: */
e_mmgr_errors_t set_msg_name(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_filter(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_recovery(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_empty(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_restart(msg_t *msg, mmgr_cli_event_t *request);
/* used by mmgr: */
e_mmgr_errors_t set_msg_modem_hw_id(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_fuse_info(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_modem_fw_result(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_ap_reset(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_core_dump(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_error(msg_t *msg, mmgr_cli_event_t *request);
#endif                          /* __MMGR_DATA_TO_MSG_HEADER__ */
