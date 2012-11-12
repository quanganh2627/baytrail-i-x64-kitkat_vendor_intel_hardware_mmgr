/* Modem Manager - configure header file
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

#ifndef __MMGR_CONFIG_HEADER__
#define __MMGR_CONFIG_HEADER__

#include "errors.h"
#include <stdbool.h>

/* Maximum size for configuration string value */
#define MAX_SIZE_CONF_VAL 50
/* Default configuration file name */
#define DEFAULT_MMGR_CONFIG_FILE "/system/etc/telephony/mmgr.conf"

/* MMGR configuration */
typedef struct mmgr_configuration {
    /* general parameters */
    char modem_port[MAX_SIZE_CONF_VAL + 1];
    char latest_tty_name[MAX_SIZE_CONF_VAL + 1];
    int delay_before_at;
    int max_frame_size;
    /* modem recovery parameters */
    bool modem_reset_enable;
    bool modem_core_dump_enable;
    int nb_warm_reset;
    bool modem_cold_reset_enable;
    int nb_cold_reset;
    bool platform_reboot_enable;
    int nb_platform_reboot;
    int modem_reset_delay;
    int min_time_issue;
    int delay_before_reset;
    int delay_before_reboot;
    int max_retry_time;
    /* power saving params */
    int delay_before_modem_shtdwn;
    /* interface */
    int max_clients;
    int time_banned;
    int max_requests_banned;
} mmgr_configuration_t;

e_mmgr_errors_t mmgr_configure(mmgr_configuration_t *parameters,
                               const char *config_file);

#endif                          /* __MMGR_CONFIG_HEADER__ */
