/* Modem Manager - file source file
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

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "errors.h"
#include "file.h"
#include "logs.h"

/**
 * write a string to a file
 *
 * @param [in] path complete file path
 * @param [in] mode open permissions
 * @param [in] value string to write
 * @param [in] size string size
 *
 * @return E_ERR_FAILED if open fails
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if path or value is/are NULL
 */
e_mmgr_errors_t write_to_file(char *path, unsigned long mode, char *value,
                              size_t size)
{
    int fd;
    e_mmgr_errors_t ret = E_ERR_FAILED;
    ssize_t write_size;

    CHECK_PARAM(path, ret, out);
    CHECK_PARAM(value, ret, out);

    fd = open(path, O_WRONLY | O_CREAT, mode);
    if (fd == -1) {
        LOG_ERROR("open of (%s) failed (%s)", path, strerror(errno));
    } else {
        write_size = write(fd, value, size);
        if ((close(fd) == 0) && (write_size > 0) &&
            ((size_t)write_size == size)) {
            ret = E_ERR_SUCCESS;
            LOG_DEBUG("write to (%s) succeed", path);
        } else {
            LOG_ERROR("write to (%s) failed. (%s)", path, strerror(errno));
        }
    }
out:
    return ret;
}

/**
 * Create an empty file with rights
 *
 * @param [in] filename complete file name path
 * @param [in] rights file access permissions
 *
 * @return E_ERR_BAD_PARAMETER if filename is NULL
 * @return E_ERR_FAILED if failed
 * @return E_ERR_SUCCESS if sucessful
 */
e_mmgr_errors_t create_empty_file(char *filename, unsigned long rights)
{
    int fd;
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(filename, ret, out);

    fd = open(filename, O_RDWR | O_CREAT, rights);
    if (fd < 0) {
        LOG_ERROR("Failed to create file %s: (%s)", filename, strerror(errno));
    } else {
        if (close(fd) == -1) {
            LOG_ERROR("close failed (%s)", strerror(errno));
        } else {
            LOG_DEBUG("(%s) created", filename);
            ret = E_ERR_SUCCESS;
        }
    }
out:
    return ret;
}

/**
 * Look for file
 *
 * @param [in] path file path
 * @param [in] rights file rights should be equal to rights. if rights is 0 the
 * check is not performed
 *
 * @return E_ERR_BAD_PARAMETER if path is NULL
 * @return E_ERR_FAILED file not found
 * @return E_ERR_SUCCESS file found
 */
e_mmgr_errors_t is_file_exists(const char *path, unsigned long rights)
{
    struct stat statbuf;
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(path, ret, out);

    if (stat(path, &statbuf) == -1) {
        LOG_DEBUG("Failure with stat on %s (%s)", path, strerror(errno));
        ret = E_ERR_FAILED;
        goto out;
    }

    if (rights != 0) {
        if (!S_ISREG(statbuf.st_mode)) {
            LOG_DEBUG("not a file");
            ret = E_ERR_FAILED;
        } else if ((statbuf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) !=
                   (rights & ~MMGR_UMASK)) {
            LOG_DEBUG("bad file permissions");
            ret = E_ERR_FAILED;
        }
    }
out:
    return ret;
}
