/* Modem Manager - crash logger header file
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

#ifndef __MGR_CRASH_LOGGER_HEADER__
#define __MGR_CRASH_LOGGER_HEADER__

#include <sys/stat.h>
#include "events_manager.h"

/* File name for AP initiated modem reset */
#define CL_FILE_PERMISSIONS (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define MMGR_UMASK (S_IXUSR|S_IXGRP|S_IWOTH|S_IXOTH)
#define LOGS_FOLDER "/logs"
#define MODEM_LOGS_FOLDER LOGS_FOLDER"/modemcrash"
#define CL_AP_RESET_FILE MODEM_LOGS_FOLDER"/apimr.txt"
/* File name for modem reset without core dump */
#define CL_MODEM_SELF_RESET_FILE MODEM_LOGS_FOLDER"/mreset.txt"
/* File name for modem panic reason */
#define CL_CORE_DUMP_FILE MODEM_LOGS_FOLDER"/mpanic.txt"
/* File name for platform reboot */
#define CL_REBOOT_FILE MODEM_LOGS_FOLDER"/mshutdown.txt"
/* content of CL_CORE_DUMP_FILE when panic_id is unknown */
#define UNKNOWN_PANIC_ID_STR "unkwown"

e_mmgr_errors_t crash_logger(modem_info_t *events);

#endif                          /* __MGR_CRASH_LOGGER_HEADER__ */
