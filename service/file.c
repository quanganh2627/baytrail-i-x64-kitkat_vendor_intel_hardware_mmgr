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

#define FILE_COPY_BUFFER_SIZE   4096

/**
 * read a string from a file
 *
 * @param [in] path complete file path
 * @param [in] mode open permissions
 * @param [out] value string to read
 * @param [out] size of the buffer. the size is updated with
 * read value
 *
 * @return E_ERR_FAILED if open fails
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if path or value is/are NULL
 */
e_mmgr_errors_t read_file(char *path, unsigned long mode, char *value,
                          size_t *size)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    int fd;
    int read_size = 0;

    CHECK_PARAM(path, ret, out);
    CHECK_PARAM(value, ret, out);

    memset(value, 0, *size);
    fd = open(path, O_RDONLY, mode);
    if (fd < 0) {
        LOG_ERROR("open of (%s) failed (%s)", path, strerror(errno));
    } else {
        read_size = read(fd, value, *size);
        if (close(fd) == 0) {
            ret = E_ERR_SUCCESS;
            LOG_DEBUG("read to (%s) succeed", path);
        } else {
            LOG_ERROR("read to (%s) failed. (%s)", path, strerror(errno));
        }
        *size = read_size;
    }
out:
    return ret;
}

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
    ssize_t write_size = 0;

    CHECK_PARAM(path, ret, out);
    CHECK_PARAM(value, ret, out);

    fd = open(path, O_WRONLY | O_CREAT, mode);
    if (fd < 0) {
        LOG_ERROR("open of (%s) failed (%s)", path, strerror(errno));
    } else {
        if (size > 0)
            write_size = write(fd, value, size);
        if ((close(fd) == 0) && ((size_t)write_size == size)) {
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

/**
* Copies a file from specified source to destination.
*
* @param [in] src Source file to copy.
* @param [in] dst Destination file to copy to.
* @param [in] dst_mode Mode to give to destination file.
*
* @return E_ERR_BAD_PARAMETER if src or dst is NULL
* @return E_ERR_FAILED file not copied
* @return E_ERR_SUCCESS file copied
*/
e_mmgr_errors_t copy_file(const char *src, const char *dst, mode_t dst_mode)
{
    int in_fd = -1;
    int out_fd = -1;
    char buff[FILE_COPY_BUFFER_SIZE];
    ssize_t read_count = 0;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mode_t old_umask = 0;

    CHECK_PARAM(src, ret, out);
    CHECK_PARAM(dst, ret, out);

    old_umask = umask(~dst_mode & 0777);

    in_fd = open(src, O_RDONLY);
    if (in_fd < 0) {
        ret = E_ERR_FAILED;
        LOG_DEBUG("Cannot open source file, errno = %d", errno);
        goto out;
    }

    out_fd = open(dst, O_CREAT | O_WRONLY | O_TRUNC, dst_mode);
    if (out_fd < 0) {
        ret = E_ERR_FAILED;
        LOG_DEBUG("Cannot create destination file, errno = %d", errno);
        goto out;
    }

    do {
        read_count = read(in_fd, buff, sizeof(buff));
        if (read_count > 0) {
            if (write(out_fd, buff, read_count) != read_count) {
                LOG_DEBUG("Failed writing destination file, errno = %d", errno);
                ret = E_ERR_FAILED;
                break;
            }
        } else if (read_count < 0) {
            LOG_DEBUG("Failed reading source file, errno = %d", errno);
            ret = E_ERR_FAILED;
        }
    } while (read_count > 0);

out:
    if (in_fd >= 0) {
        close(in_fd);
    }
    if (out_fd >= 0) {
        if (close(out_fd) < 0) {
            LOG_DEBUG("Error while closing %s: %d", dst, errno);
        }
    }
    umask(old_umask & 0777);
    return ret;
}
