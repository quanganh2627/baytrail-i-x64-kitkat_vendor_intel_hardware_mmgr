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

e_mmgr_errors_t delete_msg(msg_t *msg);

/* used by lib client: */
e_mmgr_errors_t set_msg_name(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_filter(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_empty(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_fw_update(msg_t *msg, mmgr_cli_event_t *data);
e_mmgr_errors_t set_msg_nvm_update(msg_t *msg, mmgr_cli_event_t *data);
/* used by mmgr: */
e_mmgr_errors_t set_msg_backup_file_path(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_rnd(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_modem_fw_progress(msg_t *msg,
                                          mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_modem_nvm_progress(msg_t *msg,
                                           mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_nvm_id(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_modem_hw_id(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_fuse_info(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_modem_fw_result(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_msg_modem_nvm_result(msg_t *msg, mmgr_cli_event_t *request);

#endif                          /* __MMGR_DATA_TO_MSG_HEADER__ */
