/* Modem Manager - secure header file
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

#ifndef __MMGR_SECURITY_HEADER__
#define __MMGR_SECURITY_HEADER__

#include "errors.h"
#include "config.h"

typedef int (*secur_callback_fptr_t) (uint32_t *type, uint32_t *length,
                                      uint8_t **data);

typedef struct secur {
    bool enable;
    char *dlc;
    int fd;
    void *hdle;
    secur_callback_fptr_t callback;
} secur_t;

e_mmgr_errors_t secur_init(secur_t *secur, mmgr_configuration_t *config);
e_mmgr_errors_t secur_register(secur_t *secur, int *fd);
e_mmgr_errors_t secur_start(secur_t *secur);
e_mmgr_errors_t secur_stop(secur_t *secur);
e_mmgr_errors_t secur_event(secur_t *secur);
e_mmgr_errors_t secur_dispose(secur_t *secur);
e_mmgr_errors_t secur_get_callback(secur_t *secur,
                                   secur_callback_fptr_t * callback);

#endif
