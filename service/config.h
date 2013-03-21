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

#include <stdbool.h>
#include "errors.h"
#include "dumpreader.h"

/* Maximum size for configuration string value */
#define MAX_SIZE_CONF_VAL 50
/* Default configuration file name */
#define DEFAULT_MMGR_CONFIG_FILE "/system/etc/telephony/mmgr.conf"

/* MMGR configuration */
typedef struct mmgr_configuration {
    /* general parameters */
    char modem_port[MAX_SIZE_CONF_VAL];
    char shtdwn_dlc[MAX_SIZE_CONF_VAL];
    char latest_tty_name[MAX_SIZE_CONF_VAL];
    char link_layer[MAX_SIZE_CONF_VAL];
    int delay_before_at;
    int max_frame_size;
    bool is_flashless;
    char bb_pid[MAX_SIZE_CONF_VAL];
    char bb_vid[MAX_SIZE_CONF_VAL];
    char flash_pid[MAX_SIZE_CONF_VAL];
    char flash_vid[MAX_SIZE_CONF_VAL];
    /* modem recovery parameters */
    bool modem_reset_enable;
    int nb_warm_reset;
    int nb_cold_reset;
    int nb_platform_reboot;
    int modem_reset_delay;
    int min_time_issue;
    int delay_before_reset;
    int delay_before_reboot;
    int max_retry_time;
    int timeout_ack_cold;
    int timeout_ack_shtdwn;
    /* interface */
    int max_clients;
    /* mcdr config */
    bool modem_core_dump_enable;
    char mcdr_path[MAX_SIZE_CONF_VAL];
    char mcdr_device[MAX_SIZE_CONF_VAL];
    int mcdr_baudrate;
    char mcdr_pid[MAX_SIZE_CONF_VAL];
    char mcdr_vid[MAX_SIZE_CONF_VAL];
    char mcdr_protocol[MAX_SIZE_CONF_VAL];
} mmgr_configuration_t;

typedef struct flashless_config {
    char bkup_path[MAX_SIZE_CONF_VAL];
    char bkup_cal[MAX_SIZE_CONF_VAL];
    char bkup_stat[MAX_SIZE_CONF_VAL];
    char bkup_rnd_cert[MAX_SIZE_CONF_VAL];

    char run_path[MAX_SIZE_CONF_VAL];
    char run_fw_path[MAX_SIZE_CONF_VAL];
    char run_boot_fls[MAX_SIZE_CONF_VAL];
    char run_inj_fls[MAX_SIZE_CONF_VAL];
    char run_cal[MAX_SIZE_CONF_VAL];
    char run_stat[MAX_SIZE_CONF_VAL];
    char run_dyn[MAX_SIZE_CONF_VAL];
} flashless_config_t;

e_mmgr_errors_t mmgr_configure(mmgr_configuration_t *parameters,
                               const char *config_file);

e_mmgr_errors_t modem_info_flashless_config(char *config_file,
                                            flashless_config_t *);

#endif                          /* __MMGR_CONFIG_HEADER__ */
