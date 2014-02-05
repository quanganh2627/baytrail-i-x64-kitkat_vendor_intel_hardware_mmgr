/* Modem Manager - zip source file
**
** Copyright (C) Intel 2014
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#include <dirent.h>
#include "errors.h"
#include "logs.h"
#include <minzip/Zip.h>

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

/**
 * Extract file from archive
 *
 * @param [in] zip_entry
 * @param [in] filter
 * @param [in] dest
 *
 * @return -2 if no file found
 * @return -1 if an error happened
 * @return 0 if successful
 */
static int extract(const ZipArchive *zip,
                   const ZipEntry *zip_entry, const char *filter,
                   const char *dest,
                   mode_t dst_mode)
{
    int ret = 0;
    char entry[PATH_MAX] = { '\0' };
    char conv_match[2];
    size_t len = MIN(sizeof(entry) - 1, mzGetZipEntryFileName(zip_entry).len);

    strncpy(entry, mzGetZipEntryFileName(zip_entry).str, len);
    entry[len] = '\0';

    if (sscanf(entry, filter, conv_match) == 1) {
        LOG_DEBUG("Entry match found: %s", entry);
        int fd = open(dest, O_RDWR | O_TRUNC | O_CREAT, dst_mode);
        if (fd < 0) {
            LOG_ERROR("Error creating %s (%s)", dest, strerror(errno));
            ret = -1;
        } else {
            if (!mzExtractZipEntryToFile(zip, zip_entry, fd)) {
                LOG_ERROR("Error extracting file to %s", dest);
                ret = -1;
            }

            if (!close(fd)) {
                LOG_DEBUG("Entry successfully extracted to %s", dest);
            } else {
                ret = -1;
                LOG_ERROR("Write to (%s) failed. (%s)", dest,
                          strerror(errno));
            }
        }
    } else {
        ret = -2;
    }

    return ret;
}

e_mmgr_errors_t zip_extract_entry(const char *zip_filename,
                                  const char *filter,
                                  const char *dest, mode_t dst_mode)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    ZipArchive zip;
    mode_t old_umask = umask(~dst_mode & 0777);

    ASSERT(zip_filename != NULL);
    ASSERT(filter != NULL);
    ASSERT(dest != NULL);

    memset(&zip, 0, sizeof(zip));
    if (mzOpenZipArchive(zip_filename, &zip)) {
        LOG_DEBUG("Failed to open the archive");
    } else {
        LOG_DEBUG("Archive %s opened successfully. String match: %s",
                  zip_filename, filter);

        for (size_t i = 0; i < mzZipEntryCount(&zip); i++) {
            const ZipEntry *zip_entry = mzGetZipEntryAt(&zip, i);
            int err = extract(&zip, zip_entry, filter, dest, dst_mode);
            if (err != -2) {
                if (err == 0)
                    ret = E_ERR_SUCCESS;
                break;
            }
        }
        mzCloseZipArchive(&zip);
    }

    umask(old_umask & 0777);
    return ret;
}

bool zip_is_valid(const char *file)
{
    bool valid = false;
    ZipArchive zip;

    ASSERT(file != NULL);
    memset(&zip, 0, sizeof(zip));
    if (mzOpenZipArchive(file, &zip) == 0) {
        mzCloseZipArchive(&zip);
        valid = true;
    }

    return valid;
}
