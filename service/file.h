/* Modem Manager - file header file
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

#ifndef __MMGR_FILE_HEADER__
#define __MMGR_FILE_HEADER__

#include <sys/stat.h>
#define SYSFS_OPEN_MODE S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP

int write_to_file(char *path, unsigned long mode, char *value, size_t size);
int create_empty_file(char *filename, unsigned long rights);

#endif                          /* __MMGR_FILE_HEADER__ */
