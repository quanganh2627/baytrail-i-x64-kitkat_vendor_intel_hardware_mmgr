/* Modem Manager - socket header file
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

#ifndef __MMGR_SOCKET_HEADER__
#define __MMGR_SOCKET_HEADER__

e_mmgr_errors_t open_socket(int *fd);
e_mmgr_errors_t close_socket(int *fd);
e_mmgr_errors_t accept_socket(int fd);
e_mmgr_errors_t read_socket(int fd, void *data, size_t *len);
e_mmgr_errors_t write_socket(int fd, void *data, size_t *len);

#endif                          /* __MMGR_SOCKET_HEADER__ */
