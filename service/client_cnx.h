/* Modem Manager - cnx header file
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

#ifndef __MMGR_CNX_HEADER__
#define __MMGR_CNX_HEADER__

#include <sys/types.h>
#include "errors.h"

#define SIZE_HEADER (sizeof(uint32_t) * 3)

typedef struct msg_hdr {
    uint32_t id;
    uint32_t ts;
    uint32_t len;
} msg_hdr_t;

typedef struct msg {
    msg_hdr_t hdr;
    char *data;
} msg_t;

e_mmgr_errors_t open_cnx(int *fd);
e_mmgr_errors_t close_cnx(int *fd);
e_mmgr_errors_t accept_cnx(int fd);
e_mmgr_errors_t read_cnx(int fd, void *data, size_t *len);
e_mmgr_errors_t write_cnx(int fd, void *data, size_t *len);

e_mmgr_errors_t set_header(msg_t *msg);
e_mmgr_errors_t get_header(int fd, msg_hdr_t *hdr);

#endif                          /* __MMGR_SOCKET_HEADER__ */
