/* Modem Manager - logs header file
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

#ifndef __MMGR_LOGS_HEADER__
#define __MMGR_LOGS_HEADER__

#define MODULE_NAME "MMGR"

#ifndef STDIO_LOGS

#define LOG_NDEBUG 0
#define LOG_TAG MODULE_NAME
#include <utils/Log.h>

/* define debug LOG functions */
#define LOG_ERROR(format, args...) \
    { LOGE("%s - " format, __FUNCTION__, ## args); }
#define LOG_DEBUG(format, args...) \
    { LOGD("%s - " format, __FUNCTION__, ## args); }
#define LOG_VERBOSE(format, args...) \
    { LOGV("%s - " format, __FUNCTION__, ## args); }
#define LOG_INFO(format, args...) \
    { LOGI("%s - " format, __FUNCTION__, ## args); }

#else                           /* STDIO_LOGS */

#include <stdio.h>
#define LOG_ERROR(format, args...) fprintf(stderr, "ERROR: %s - "   \
            format"\n", __FUNCTION__, ## args)
#define LOG_DEBUG(format, args...) fprintf(stdout, "DEBUG: %s - "   \
            format"\n", __FUNCTION__, ## args)
#define LOG_VERBOSE(format, args...) fprintf(stdout, "VERBOSE: %s - " \
            format"\n", __FUNCTION__, ## args)

#endif                          /* STDIO_LOGS */

/* Enable this to debug Modem Manager configuration */
#ifdef DEBUG_CONFIG
#define LOG_CONFIG(format, arg...) LOG_DEBUG(format, ## arg)
#else
#define LOG_CONFIG(format, arg...)
#endif

/* display macros */
#define PRINT_KEY     "%-25s: "
#define PRINT_STRING  PRINT_KEY "%s\n"
#define PRINT_INTEGER PRINT_KEY "%d\n"
#define PRINT_BOOLEAN PRINT_STRING

#endif                          /* __MMGR_LOGS_HEADER__ */
