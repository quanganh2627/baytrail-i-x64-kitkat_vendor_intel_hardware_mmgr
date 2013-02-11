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

#ifndef __MMGR_MSG_TO_DATA_HEADER__
#define __MMGR_MSG_TO_DATA_HEADER__

#define MMGR_FW_OPERATIONS
#include "mmgr.h"
#include "mmgr_cli.h"
#include "client_cnx.h"
#include "errors.h"

e_mmgr_errors_t set_data_bckup_file(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_data_fuse_info(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_data_nvm_progress(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_data_fw_progress(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_data_nvm_id(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_data_hw_id(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_data_rnd_id(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_data_fw_result(msg_t *msg, mmgr_cli_event_t *request);
e_mmgr_errors_t set_data_nvm_result(msg_t *msg, mmgr_cli_event_t *request);

e_mmgr_errors_t free_data_bckup_file(mmgr_cli_event_t *request);
e_mmgr_errors_t free_data_fuse_info(mmgr_cli_event_t *request);
e_mmgr_errors_t free_one_element_struct(mmgr_cli_event_t *request);
e_mmgr_errors_t free_data_nvm_id(mmgr_cli_event_t *request);
e_mmgr_errors_t free_data_hw_id(mmgr_cli_event_t *request);
e_mmgr_errors_t free_data_rnd_id(mmgr_cli_event_t *request);

e_mmgr_errors_t set_data_empty(msg_t *msg, mmgr_cli_event_t *event);
e_mmgr_errors_t free_data_empty(mmgr_cli_event_t *event);

e_mmgr_errors_t extract_data_fw_update(msg_t *msg, mmgr_cli_fw_update_t *fw);
e_mmgr_errors_t extract_data_nvm_update(msg_t *msg, mmgr_cli_nvm_update_t *nvm);

#endif                          /* __MMGR_MSG_TO_DATA_HEADER__ */
