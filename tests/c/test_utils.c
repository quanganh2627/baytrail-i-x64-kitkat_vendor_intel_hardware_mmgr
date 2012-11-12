/* Modem Manager (MMGR) test application - utils source file
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
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <cutils/sockets.h>
#include "at.h"
#include "crash_logger.h"
#include "errors.h"
#include "test_utils.h"
#include "tty.h"

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#define DEV_GSMTTY "/dev/gsmtty1"
#define LEN_FILTER 10

const char *g_mmgr_requests[] = {
#undef X
#define X(a) #a
    MMGR_REQUESTS
};

const char *g_mmgr_events[] = {
#undef X
#define X(a) #a
    MMGR_EVENTS
};

/**
 * compare file content
 *
 * @param [in] path file path
 * @param [in] data content to compare
 * @param [in] len content length
 *
 * @return E_ERR_BAD_PARAMETER if path or data is NULL
 * @return E_ERR_FAILED content not equal
 * @return E_ERR_SUCCESS content equal
 */
int compare_file_content(const char *path, const char *data, int len)
{
    int ret = E_ERR_FAILED;
    int read_size;
    int fd;
    char *tmp;

    CHECK_PARAM(path, ret, out);
    CHECK_PARAM(data, ret, out);

    tmp = malloc(sizeof(char) * len);
    if (tmp == NULL)
        goto out;

    fd = open(path, O_RDONLY);
    if (fd != -1) {
        read_size = read(fd, tmp, len);
        LOG_DEBUG("the file contains: %s", data);
        if (read_size == len) {
            if (strncmp(data, tmp, len) == 0) {
                ret = E_ERR_SUCCESS;
            }
        }
        close(fd);
    }
    free(tmp);
out:
    return ret;
}

/**
 * Look for file
 *
 * @param [in] path file path
 * @param [in] rights file rights
 *
 * @return E_ERR_BAD_PARAMETER if path is NULL
 * @return E_ERR_FAILED file not found
 * @return E_ERR_SUCCESS file found
 */
int is_file_exists(const char *path, unsigned long rights)
{
    struct stat statbuf;
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(path, ret, out);

    if (stat(path, &statbuf) == -1) {
        LOG_DEBUG("Failure with stat on %s (%s)", path, strerror(errno));
        ret = E_ERR_FAILED;
        goto out;
    }

    if (!S_ISREG(statbuf.st_mode)) {
        LOG_DEBUG("not a file");
        ret = E_ERR_FAILED;
    } else if ((statbuf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) !=
               (rights & ~MMGR_UMASK)) {
        LOG_DEBUG("bad file permissions");
        ret = E_ERR_FAILED;
    }
out:
    if (ret == E_ERR_SUCCESS)
        LOG_DEBUG("file %s found", path);
    return ret;
}

/**
 * remove file
 *
 * @param [in] filename file path
 *
 * @return E_ERR_BAD_PARAMETER if filename is NULL
 * @return E_ERR_FAILED remove fails
 * @return E_ERR_SUCCESS if successful
 */
int remove_file(char *filename)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(filename, ret, out);

    if (remove(filename) < 0) {
        LOG_ERROR("failed to remove %s (%s)", filename, strerror(errno));
        ret = E_ERR_FAILED;
    } else {
        LOG_DEBUG("file removed: %s", filename);
    }
out:
    return ret;
}

/**
 * Update modem_state variable
 *
 * @param [in,out] test_data thread handler
 * @param [in] state new modem state
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_SUCCESS if successful
 */
int modem_state_set(test_data_t *test_data, int state)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(test_data, ret, out);

    pthread_mutex_lock(&test_data->mutex);
    test_data->modem_state = state;
    pthread_mutex_unlock(&test_data->mutex);

out:
    return ret;
}

/**
 * Get modem_state variable
 *
 * @param [in,out] test_data thread handler
 * @param [out] state current state
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_SUCCESS if successful
 */
static int modem_state_get(test_data_t *test_data, int *state)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(test_data, ret, out);
    CHECK_PARAM(state, ret, out);

    pthread_mutex_lock(&test_data->mutex);
    *state = test_data->modem_state;
    pthread_mutex_unlock(&test_data->mutex);

out:
    return ret;
}

/**
 * This function will send the command message to DEV_GSMTTY
 *
 * @param [in] command AT request
 * @param [in] command_size AT request size
 *
 * @return E_ERR_SUCCESS command sends and 'OK' received
 * @return E_ERR_AT_CMD_RESEND generic failure. Command to resend
 * @return E_ERR_TTY_POLLHUP POLLHUP detected during read
 * @return E_ERR_TTY_BAD_FD if a bad file descriptor is provided
 * @return E_ERR_BAD_PARAMETER if command is NULL
 */
int send_at_cmd(char *command, int command_size)
{
    int fd_tty;
    int ret = E_ERR_FAILED;

    CHECK_PARAM(command, ret, out);

    open_tty(DEV_GSMTTY, &fd_tty);
    if (fd_tty < 0) {
        LOG_ERROR("Failed to open %s", DEV_GSMTTY);
        goto out;
    }
    ret = send_at_timeout(fd_tty, command, command_size, 10);
    close(fd_tty);
out:
    return ret;
}

/**
 * This function is used by scandir to find crashlog folders
 * where core dump files are stored.
 */
static int filter_folder(const struct dirent *d)
{
    const char *pattern = "crashlog";
    char *found = strstr(d->d_name, pattern);
    return found != NULL;
}

/**
 * This function is used by scandir to find core dump archives
 */
static int filter_archive(const struct dirent *d)
{
    const char *pattern = ".tar.gz";
    char *found = strstr(d->d_name, pattern);
    /* check that the pattern is found at the end of the filename */
    return found != NULL && strlen(found) == strlen(pattern);
}

/**
 * This function is used scandir to compare two elements (files or directory)
 */
static int compare_function(const struct dirent **a, const struct dirent **b)
{
    return strncmp((*a)->d_name, (*b)->d_name, sizeof((*b)->d_name) - 1);
}

/**
 * This function will extract the last core dump archived logged in aplog
 * and check if the archive exist.
 *
 * @param [in] filename core dump file name
 * @param [in] path core dump path
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 * @return E_ERR_BAD_PARAMETER if filename or/and path is/are NULL
 */
int is_core_dump_found(char *filename, const char *path)
{
    struct dirent **folder_list = NULL;
    struct dirent **files_list = NULL;
    int ret = E_ERR_FAILED;
    int folders_number = -1;
    int files_number = -1;
    char folder_name[FILENAME_SIZE];
    int i;
    int j;
    char not[] = "NOT";

    CHECK_PARAM(filename, ret, out);
    CHECK_PARAM(path, ret, out);

    /* looking for all the crashlog subdirs. these folders contain */
    /* the core dump archives */
    folders_number = scandir(path, &folder_list, filter_folder,
                             compare_function);

    for (i = 0; i < folders_number; i++) {
        snprintf(folder_name, sizeof(folder_name), "%s/%s", path,
                 folder_list[i]->d_name);

        /* looking for the core dump archive */
        files_number = scandir(folder_name, &files_list, filter_archive,
                               compare_function);
        for (j = 0; j < files_number; j++) {
            if (strncmp(filename, files_list[j]->d_name, strlen(filename)) == 0) {
                ret = E_ERR_SUCCESS;
                break;
            }
        }
    }

    for (i = 0; i < folders_number; i++) {
        if (folder_list[i] != NULL)
            free(folder_list[i]);
    }
    for (j = 0; j < files_number; j++) {
        if (files_list[j] != NULL)
            free(files_list[j]);
    }
    if (folder_list != NULL)
        free(folder_list);
    if (files_list != NULL)
        free(files_list);

    if (ret == E_ERR_SUCCESS)
        strncpy(not, "", sizeof(not));

    LOG_DEBUG("Core dump file (%s) %s found in (%s)", filename, not, path);
out:
    return ret;
}

/**
 * Erase all files in modemcrash dir
 *
 * @param [in] path path
 *
 * @return E_ERR_BAD_PARAMETER if path is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
int cleanup_modemcrash_dir(const char *path)
{
    DIR *rep;
    struct dirent *ent;
    int ret = E_ERR_SUCCESS;
    char filename[FILENAME_MAX];

    CHECK_PARAM(path, ret, out);

    /* Remove previous modem crash log */
    LOG_DEBUG("open dir: %s", path);
    rep = opendir(path);

    if (rep != NULL) {
        while ((ent = readdir(rep)) != NULL) {
            /* Bypass files started by . (to bypass . and ..) */
            if (strncmp(ent->d_name, ".", 1) == 0)
                continue;
            /* Delete all other files */
            LOG_DEBUG("remove file: %s", ent->d_name);
            snprintf(filename, FILENAME_MAX, "%s/%s", path, ent->d_name);
            if (remove(filename) < 0)
                LOG_ERROR("Not able to remove %s (%s)", filename,
                          strerror(errno));
        }
        closedir(rep);
    } else {
        LOG_ERROR("Can't read %s folder", path);
        ret = E_ERR_FAILED;
    }
out:
    return ret;
}

/**
 * Wait for modem state with timeout
 *
 * @param [in] test_data test_data
 * @param [in] state state to reach
 * @param [in] timeout timeout (in second)
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_MODEM_OUT if modem is OUT
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
int wait_for_state(test_data_t *test_data, int state, int timeout)
{
    int ret = E_ERR_FAILED;
    int err = 0;
    int current_state = 0;
    struct timespec ts;
    struct timeval start;
    struct timeval current;
    int remaining;

    CHECK_PARAM(test_data, ret, out);

    pthread_mutex_lock(&test_data->mutex);
    test_data->waited_state = state;
    pthread_mutex_unlock(&test_data->mutex);

    LOG_DEBUG("waiting for state: %s. (during %ds max)", g_mmgr_events[state],
              timeout);

    gettimeofday(&start, NULL);

    do {
        gettimeofday(&current, NULL);
        ts.tv_sec = current.tv_sec;
        ts.tv_nsec = current.tv_usec * 1000;
        remaining = timeout - (current.tv_sec - start.tv_sec);
        if (remaining > 0)
            ts.tv_sec += 1;

        pthread_mutex_lock(&test_data->cond_mutex);
        err =
            pthread_cond_timedwait(&test_data->cond, &test_data->cond_mutex,
                                   &ts);
        pthread_mutex_unlock(&test_data->cond_mutex);

        modem_state_get(test_data, &current_state);

        /* ack new modem state by releasing the new_state_read mutex */
        pthread_mutex_trylock(&test_data->new_state_read);
        pthread_mutex_unlock(&test_data->new_state_read);

        if (current_state == test_data->waited_state) {
            LOG_DEBUG("state reached");
            ret = E_ERR_SUCCESS;
        } else if ((current_state == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
                   (current_state == E_MMGR_NOTIFY_PLATFORM_REBOOT)) {
            LOG_DEBUG("modem is out of service");
            ret = E_ERR_MODEM_OUT;
        }
    } while ((ret == E_ERR_FAILED) && (remaining > 1));
out:
    return ret;
}

/**
 * update modem state and send signal
 *
 * @param [in] id current event
 * @param [in] test_data test data
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_SUCCESS
 */
static int set_and_notify(e_mmgr_requests_t id, test_data_t *test_data)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(test_data, ret, out);

    /* lock modem state update. the state can only be upgraded
       if read by wait_for_state function */
    pthread_mutex_lock(&test_data->new_state_read);

    pthread_mutex_lock(&test_data->mutex);
    test_data->modem_state = id;
    pthread_mutex_lock(&test_data->cond_mutex);
    pthread_cond_signal(&test_data->cond);
    pthread_mutex_unlock(&test_data->cond_mutex);
    pthread_mutex_unlock(&test_data->mutex);
    if (id < E_MMGR_NUM_REQUESTS)
        LOG_DEBUG("current state: %s", g_mmgr_events[id]);
out:
    return ret;
}

/**
 * callback for modem shutdown event
 *
 * @param [in] ev current info callback data
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_FAILED if failed to send ACK
 * @return E_ERR_SUCCESS
 */
static int event_modem_shutdown(mmgr_cli_event_t *ev)
{
    e_err_mmgr_cli_t err;
    int ret = E_ERR_FAILED;
    test_data_t *test_data = NULL;
    mmgr_cli_requests_t request = {.id = E_MMGR_ACK_MODEM_SHUTDOWN };

    CHECK_PARAM(ev, ret, out);

    test_data = (test_data_t *)ev->context;
    if (test_data == NULL)
        goto out;

    set_and_notify(ev->id, (test_data_t *)ev->context);
    err = mmgr_cli_send_msg(test_data->lib, &request);
    if (err != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("Failed to send E_MMGR_ACK_MODEM_SHUTDOWN");
    } else {
        ret = E_ERR_SUCCESS;
    }

out:
    return ret;
}

/**
 * callback for cold reset modem event
 *
 * @param [in] ev current info callback data
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_FAILED if failed to send ACK
 * @return E_ERR_SUCCESS
 */
static int event_cold_reset(mmgr_cli_event_t *ev)
{
    e_err_mmgr_cli_t err;
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_ACK_MODEM_COLD_RESET };
    test_data_t *test_data = NULL;

    CHECK_PARAM(ev, ret, out);

    test_data = (test_data_t *)ev->context;
    if (test_data == NULL)
        goto out;

    set_and_notify(ev->id, (test_data_t *)ev->context);
    err = mmgr_cli_send_msg(test_data->lib, &request);
    if (err != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("Failed to send E_MMGR_ACK_MODEM_SHUTDOWN");
    } else {
        ret = E_ERR_SUCCESS;
    }

out:
    return ret;
}

/**
 * generic callback event
 *
 * @param [in] ev current info callback data
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_FAILED if failed to send ACK
 * @return E_ERR_SUCCESS
 */
int event_without_ack(mmgr_cli_event_t *ev)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(ev, ret, out);

    ret = set_and_notify(ev->id, (test_data_t *)ev->context);
out:
    return ret;

}

/**
 * cleanup client library
 *
 * @param [in] test_data test data
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_SUCCESS
 */
int cleanup_client_library(test_data_t *test_data)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(test_data, ret, out);

    /* release new_state_read mutex to prevent callback function deadlock */
    pthread_mutex_trylock(&test_data->new_state_read);
    pthread_mutex_unlock(&test_data->new_state_read);

    if (mmgr_cli_disconnect(test_data->lib) != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("failed to disconnect client");
        ret = E_ERR_FAILED;
        goto out;
    }

    if (mmgr_cli_delete_handle(test_data->lib) != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("failed to free library");
        ret = E_ERR_FAILED;
    } else {
        test_data->lib = NULL;
    }
out:
    return ret;
}

/**
 * Handles the modem status
 *
 * @param [in,out] test_data test data
 *
 * @return E_ERR_BAD_PARAMETER if event is NULL
 * @return E_ERR_FAILED if fails
 * @return E_ERR_SUCCESS if successsful
 */
int configure_client_library(test_data_t *test_data)
{
    int ret = E_ERR_FAILED;
    e_err_mmgr_cli_t err;

    CHECK_PARAM(test_data, ret, out);

    err = mmgr_cli_create_handle(&test_data->lib, EXE_NAME, test_data);
    if (err != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("Get client handle failed");
        ret = E_ERR_BAD_PARAMETER;
        goto out;
    }

    if (mmgr_cli_subscribe_event(test_data->lib, event_without_ack,
                                 E_MMGR_EVENT_MODEM_DOWN) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_without_ack,
                                 E_MMGR_EVENT_MODEM_UP) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_without_ack,
                                 E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_without_ack,
                                 E_MMGR_NOTIFY_MODEM_WARM_RESET) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_without_ack,
                                 E_MMGR_NOTIFY_CORE_DUMP) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_cold_reset,
                                 E_MMGR_NOTIFY_MODEM_COLD_RESET) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_modem_shutdown,
                                 E_MMGR_NOTIFY_MODEM_SHUTDOWN) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_without_ack,
                                 E_MMGR_NOTIFY_PLATFORM_REBOOT) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_connect(test_data->lib) == E_ERR_CLI_SUCCEED) {
        LOG_DEBUG("connection to MMGR succeed");
        ret = E_ERR_SUCCESS;
        /* give some time to connect correctly */
        sleep(1);
    }

out:
    if (ret != E_ERR_SUCCESS)
        LOG_ERROR("connection to MMGR failed");
    return ret;
}

/**
 * Update core dump retrieve status
 *
 * @param [in,out] test_data aplog thread data
 * @param [in] state new state
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_SUCCESS if successful
 */
static int update_cd_state(aplog_thread_t *test_data,
                           core_dump_retrieval_t state)
{
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(test_data, ret, out);

    pthread_mutex_lock(&test_data->mutex);
    test_data->state = state;
    pthread_mutex_unlock(&test_data->mutex);
out:
    return ret;
}

/**
 * Clear aplogs
 */
static void clear_logs(void)
{
    char *execv_args[] = { "logcat", "-c", NULL };
    int pid;

    pid = fork();
    if (pid == -1) {
        LOG_ERROR("fork fails: (%s)", strerror(errno));
        exit(1);
    }

    if (pid == 0) {
        execvp(execv_args[0], execv_args);
    } else {
        /* wait for child */
        LOG_DEBUG("done");
        wait(NULL);
    }
}

/**
 * Retrieve core dump filename from aplog
 *
 * @param [in,out] test_data test data
 * @param [in] fd socket fd
 *
 * @return E_ERR_BAD_PARAMETER if data is NULL
 * @return E_ERR_SUCCESS if successful
 */
static int extract_core_dump_name(aplog_thread_t *test_data, int fd)
{
    int epollfd;
    bool running = true;
    char buf[1024];
    char *p_str = NULL;
    const char pattern_found[] = "Modem Core Dump files were saved in:";
    const char pattern_time[] = "retrieve_core_dump - Succeed (in ";
    const char pattern_timeout[] = "retrieve_core_dump - Timeout error";
    const char pattern_error[] = "retrieve_core_dump - Failed with error";
    struct epoll_event ev;
    int ret = E_ERR_SUCCESS;
    int size;

    CHECK_PARAM(test_data, ret, out);

    /* configure epoll */
    ret = initialize_epoll(&epollfd, fd, EPOLLIN);
    if (ret != E_ERR_SUCCESS) {
        goto out;
    }

    do {
        pthread_mutex_lock(&test_data->mutex);
        running = test_data->running;
        pthread_mutex_unlock(&test_data->mutex);

        if (epoll_wait(epollfd, &ev, 1, 1000) < 1) {
            if ((errno == EBADF) || (errno == EINVAL)) {
                LOG_ERROR("bad epoll configuration");
                goto out;
            } else {
                continue;
            }
        }

        if ((size = read(fd, buf, sizeof(buf) - 1)) <= 0)
            continue;
        buf[strnlen(buf, sizeof(buf)) - 1] = '\0';

        if ((p_str = strstr(buf, pattern_found)) != NULL) {
            p_str += strlen(pattern_found) + 1; /* skip space */
            char *end = strstr(p_str, ".tar.gz");
            int size = (end - p_str) + strlen(".tar.gz");;
            if (size > FILENAME_SIZE)
                size = FILENAME_SIZE;
            pthread_mutex_lock(&test_data->mutex);
            strncpy(test_data->filename, p_str, size);
            test_data->filename[size] = '\0';
            LOG_DEBUG("core dump filename found: %s", test_data->filename);
            pthread_mutex_unlock(&test_data->mutex);
        } else if (strstr(buf, pattern_timeout) != NULL) {
            update_cd_state(test_data, E_CD_TIMEOUT);
        } else if (strstr(buf, pattern_error) != NULL) {
            update_cd_state(test_data, E_CD_ERROR);
            goto out;
        } else if ((p_str = strstr(buf, pattern_time)) != NULL) {
            p_str += strlen(pattern_time);
            pthread_mutex_lock(&test_data->mutex);
            sscanf(p_str, "%d", &test_data->duration);
            pthread_mutex_unlock(&test_data->mutex);
            update_cd_state(test_data, E_CD_SUCCEED);
            LOG_DEBUG("time: %ds", test_data->duration);
            goto out;
        }
    } while (running);
out:
    return ret;
}

/**
 * Launch a new process to read aplog with aplog. This function
 * extract the core dump filename.
 *
 * @param [in,out] test_data test data
 */
void listen_aplogs(aplog_thread_t *test_data)
{
    int pid;
    int ret = E_ERR_FAILED;
    char filter[LEN_FILTER];
    if (snprintf(filter, LEN_FILTER, "%s:*", MODULE_NAME) < 0) {
        LOG_DEBUG("setting filter failed");
        strncpy(filter, "", LEN_FILTER);
    }
    char *execv_args[] = { "logcat", filter, "MCDR:*", "*:S", NULL };

    CHECK_PARAM(test_data, ret, out);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, test_data->sockets) < 0) {
        LOG_ERROR("opening stream socket pair");
        goto out;
    }

    clear_logs();
    pid = fork();

    if (pid == -1) {
        LOG_ERROR("fork fails: (%s)", strerror(errno));
        exit(1);
    }

    if (pid == 0) {
        /* This is the child. */
        if (dup2(test_data->sockets[0], STDOUT_FILENO) < 0) {
            LOG_ERROR("dup2 fails: (%s)", strerror(errno));
            exit(1);
        }
        close(test_data->sockets[1]);

        /* launch logcat */
        execvp(execv_args[0], execv_args);
        LOG_ERROR("execvp fails: (%d) on '%s'", errno, execv_args[0]);
    } else {
        /* This is the parent. */
        close(test_data->sockets[0]);

        ret = extract_core_dump_name(test_data, test_data->sockets[1]);

        kill(pid, SIGKILL);
        close(test_data->sockets[1]);
        close(test_data->sockets[0]);
    }
out:
    pthread_exit(&ret);
}

/**
 * perform a modem reset request via a socket request
 *
 * @param [in] data_test test data
 * @param [in] check_file boolean to enable file existance check
 * @param [in] id request to send
 * @param [in] notification expected notification after AT command
 * @param [in] final_state final state expected
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_MODEM_OUT if modem is OUT
 * @return E_ERR_FAILED test fails
 * @return E_ERR_SUCCESS if successful
 */
int reset_by_client_request(test_data_t *data_test, bool check_file,
                            e_mmgr_requests_t id,
                            e_mmgr_events_t notification,
                            e_mmgr_events_t final_state)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = id };

    CHECK_PARAM(data_test, ret, out);

    remove_file(CL_AP_RESET_FILE);

    /* Wait modem up */
    ret = wait_for_state(data_test, E_MMGR_EVENT_MODEM_UP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS) {
        LOG_DEBUG("modem is down");
        goto out;
    }

    if (mmgr_cli_send_msg(data_test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    if (notification != E_MMGR_NUM_EVENTS) {
        ret =
            wait_for_state(data_test, notification,
                           TIMEOUT_MODEM_DOWN_AFTER_CMD);
        if (ret != E_ERR_SUCCESS)
            goto out;
    }

    ret = wait_for_state(data_test, E_MMGR_EVENT_MODEM_DOWN,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    /* Wait modem up during TIMEOUT_MODEM_UP_AFTER_RESET seconds
       to end the test */
    ret = wait_for_state(data_test, final_state, TIMEOUT_MODEM_UP_AFTER_RESET);
    if (ret != E_ERR_SUCCESS)
        goto out;

    if (check_file)
        ret = is_file_exists(CL_AP_RESET_FILE, CL_FILE_PERMISSIONS);
out:
    return ret;
}

/**
 * perform a modem reset request via an AT command
 *
 * @param [in] test test data
 * @param [in] at_cmd AT command to send
 * @param [in] at_len AT command length
 * @param [in] notification expected notification after AT command
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_MODEM_OUT if modem is OUT
 * @return E_ERR_FAILED test fails
 * @return E_ERR_SUCCESS if successful
 */
int reset_by_at_cmd(test_data_t *test, char *at_cmd, size_t at_len,
                    e_mmgr_events_t notification)
{
    int ret = E_ERR_FAILED;
    int err;

    CHECK_PARAM(test, ret, out);
    CHECK_PARAM(at_cmd, ret, out);

    /* Wait modem up */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS) {
        LOG_DEBUG("modem is down");
        goto out;
    }

    /* Send reset command to modem */
    err = send_at_cmd(at_cmd, at_len);
    if ((err != E_ERR_TTY_POLLHUP) && (err != E_ERR_SUCCESS)) {
        ret = E_ERR_FAILED;
        LOG_DEBUG("send of AT commands fails ret=%d", ret);
        goto out;
    }

    if (notification != E_MMGR_NUM_EVENTS) {
        ret = wait_for_state(test, notification, TIMEOUT_MODEM_DOWN_AFTER_CMD);
        if (ret != E_ERR_SUCCESS)
            goto out;
    }

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_DOWN,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    /* Wait modem up during TIMEOUT_MODEM_UP_AFTER_RESET seconds
       to end the test */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
                         TIMEOUT_MODEM_UP_AFTER_RESET);
out:
    return ret;
}
