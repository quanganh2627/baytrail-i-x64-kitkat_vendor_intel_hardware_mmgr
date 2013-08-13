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
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <cutils/sockets.h>
#include "at.h"
#include "client_events.h"
#include "errors.h"
#include "file.h"
#include "property.h"
#include "test_utils.h"
#include "tty.h"

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#define LEN_FILTER 10

#define AT_SELF_RESET "AT+CFUN=15\r"
#define AT_CORE_DUMP "AT+XLOG=4\r"

#define BZ_MSG "\n\n*** YOU SHOULD RAISE A BZ ***\n"
#define WAKE_BUF_SIZE 1024

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
 * Update events variable
 *
 * @param [in,out] test_data thread handler
 * @param [in] state new test state
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_SUCCESS if successful
 */
static e_mmgr_errors_t events_set(test_data_t *test_data, e_events_t state)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(test_data, ret, out);

    pthread_mutex_lock(&test_data->mutex);
    test_data->events |= state;
    pthread_mutex_unlock(&test_data->mutex);

out:
    return ret;
}

/**
 * Get events variable
 *
 * @param [in,out] test_data thread handler
 *
 * @return e_events_t
 */
e_events_t events_get(test_data_t *test_data)
{
    e_events_t ev = E_EVENTS_NONE;

    if (test_data == NULL) {
        ev = E_EVENTS_ERROR_OCCURED;
    } else {
        pthread_mutex_lock(&test_data->mutex);
        ev = test_data->events;
        pthread_mutex_unlock(&test_data->mutex);
    }
    return ev;
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
e_mmgr_errors_t modem_state_set(test_data_t *test_data, e_mmgr_events_t state)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

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
static e_mmgr_errors_t modem_state_get(test_data_t *test_data,
                                       e_mmgr_events_t *state)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(test_data, ret, out);
    CHECK_PARAM(state, ret, out);

    pthread_mutex_lock(&test_data->mutex);
    *state = test_data->modem_state;
    pthread_mutex_unlock(&test_data->mutex);

out:
    return ret;
}

/**
 * This function will send the command message to DLC
 *
 * @param [in] path dlc path to use
 * @param [in] command AT request
 * @param [in] command_size AT request size
 *
 * @return E_ERR_SUCCESS command sends and 'OK' received
 * @return E_ERR_AT_CMD_RESEND generic failure. Command to resend
 * @return E_ERR_TTY_POLLHUP POLLHUP detected during read
 * @return E_ERR_TTY_BAD_FD if a bad file descriptor is provided
 * @return E_ERR_BAD_PARAMETER if command is NULL
 */
e_mmgr_errors_t send_at_cmd(char *path, char *command, int command_size)
{
    int fd_tty = CLOSED_FD;
    e_mmgr_errors_t ret = E_ERR_FAILED;

    CHECK_PARAM(command, ret, out);

    open_tty(path, &fd_tty);
    if (fd_tty < 0) {
        LOG_ERROR("Failed to open %s", path);
        goto out;
    }
    ret = send_at_retry(fd_tty, command, command_size, 4, 2500);
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

bool get_wakelock_state(void)
{
    bool state = false;
    int fd;
    int size = WAKE_BUF_SIZE;
    char data[WAKE_BUF_SIZE];

    while ((fd = open(WAKE_LOCK_SYSFS, O_RDONLY)) < 0) {
        sleep(1);
        LOG_DEBUG("retry to open %s", WAKE_LOCK_SYSFS);
    }

    memset(data, 0, size);
    size = read(fd, data, size);

    if ((size > 0) && (strstr(data, MODULE_NAME) != NULL))
        state = true;
    close(fd);

    return state;
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
e_mmgr_errors_t is_core_dump_found(char *filename, const char *path)
{
    struct dirent **folder_list = NULL;
    struct dirent **files_list = NULL;
    e_mmgr_errors_t ret = E_ERR_FAILED;
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

        for (j = 0; j < files_number; j++) {
            if (files_list[j] != NULL)
                free(files_list[j]);
        }
        if (files_list != NULL)
            free(files_list);
    }

    for (i = 0; i < folders_number; i++) {
        if (folder_list[i] != NULL)
            free(folder_list[i]);
    }
    if (folder_list != NULL)
        free(folder_list);

    if (ret == E_ERR_SUCCESS)
        strncpy(not, "", sizeof(not));

    LOG_DEBUG("Core dump file (%s) %s found in (%s)", filename, not, path);
out:
    return ret;
}

/**
 * Wait for modem state with timeout
 *
 * @param [in] test_data test_data
 * @param [in] state state to reach
 * @param [in] wakelock wakelock state
 * @param [in] timeout timeout (in second)
 *
 * @return E_ERR_BAD_PARAMETER if test_data is NULL
 * @return E_ERR_SUCCESS if state reached
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t wait_for_state(test_data_t *test_data, int state, bool wakelock,
                               int timeout)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    e_mmgr_events_t current_state = E_MMGR_NUM_EVENTS;
    struct timespec ts;
    struct timeval start;
    struct timeval current;
    int remaining = 0;
    char *state_str[] = { "not ", "" };

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
            /*
             * A timeout of 1s is used here to save time in several UCs:
             * - if modem is OOS or plateform is shutdown
             * - if we have already reached the state
             */
            ts.tv_sec += 1;

        pthread_mutex_lock(&test_data->cond_mutex);
        pthread_cond_timedwait(&test_data->cond, &test_data->cond_mutex, &ts);
        pthread_mutex_unlock(&test_data->cond_mutex);

        modem_state_get(test_data, &current_state);

        /* ack new modem state by releasing the new_state_read mutex */
        pthread_mutex_trylock(&test_data->new_state_read);
        pthread_mutex_unlock(&test_data->new_state_read);
        if ((current_state == E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) ||
            (current_state == E_MMGR_NOTIFY_PLATFORM_REBOOT)) {
            LOG_DEBUG("modem state: %s", g_mmgr_events[current_state]);
            events_set(test_data, E_EVENTS_MODEM_OOS);
            break;
        }
    } while ((remaining > 1) && (current_state != test_data->waited_state));

    if (current_state == test_data->waited_state) {
        LOG_DEBUG("state reached (%s)", g_mmgr_events[current_state]);
        bool wake_state = false;
        for (remaining = 0; remaining < 10; remaining++) {
            wake_state = get_wakelock_state();
            if (wake_state != wakelock) {
                usleep(500 * 1000);
            } else {
                LOG_DEBUG("wakelock has reached correct state: %sset",
                          state_str[wake_state]);
                ret = E_ERR_SUCCESS;
                break;
            }
        }
        if (ret != E_ERR_SUCCESS)
            LOG_ERROR("*** wakelock is %sset and should be %sset ***",
                      state_str[wake_state], state_str[wakelock]);
    }

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
static e_mmgr_errors_t set_and_notify(e_mmgr_events_t id,
                                      test_data_t *test_data)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    CHECK_PARAM(test_data, ret, out);

    /* lock modem state update. the state can only be upgraded if read by
     * wait_for_state function */
    pthread_mutex_lock(&test_data->new_state_read);

    modem_state_set(test_data, id);

    pthread_mutex_lock(&test_data->cond_mutex);
    pthread_cond_signal(&test_data->cond);
    pthread_mutex_unlock(&test_data->cond_mutex);

    if (id < E_MMGR_NUM_EVENTS)
        LOG_DEBUG("current state: %s", g_mmgr_events[id]);
out:
    return ret;
}

/**
 * callback for event error
 *
 * @param [in] ev current info callback data
 *
 * @return 0 if successful
 * @return 1 otherwise
 */
static int event_error(mmgr_cli_event_t *ev)
{
    int ret = 1;
    e_mmgr_errors_t err = E_ERR_FAILED;
    test_data_t *data = NULL;
    mmgr_cli_error_t *cli_err = NULL;

    CHECK_PARAM(ev, err, out);

    data = (test_data_t *)ev->context;
    if (data == NULL)
        goto out;

    cli_err = (mmgr_cli_error_t *)ev->data;
    if (cli_err == NULL) {
        LOG_ERROR("empty data");
        goto out;
    }
    LOG_DEBUG("error {id:%d reason:\"%s\" len:%d}", cli_err->id,
              cli_err->reason, cli_err->len);
    if ((cli_err->len == strlen(FAKE_ERROR_REASON))
        && (strncmp(FAKE_ERROR_REASON, cli_err->reason, cli_err->len) == 0))
        events_set(data, E_EVENTS_SUCCEED);

    err = set_and_notify(ev->id, (test_data_t *)ev->context);
    if (err == E_ERR_SUCCESS)
        ret = 0;

out:
    if (ret == 1)
        events_set(data, E_EVENTS_ERROR_OCCURED);
    return ret;
}

/**
 * callback for ap reset
 *
 * @param [in] ev current info callback data
 *
 * @return 0 if successful
 * @return 1 otherwise
 */
static int event_ap_reset(mmgr_cli_event_t *ev)
{
    int ret = 1;
    e_mmgr_errors_t err = E_ERR_FAILED;
    test_data_t *data = NULL;
    mmgr_cli_ap_reset_t *ap = NULL;

    CHECK_PARAM(ev, err, out);

    data = (test_data_t *)ev->context;
    if (data == NULL)
        goto out;

    ap = (mmgr_cli_ap_reset_t *)ev->data;
    if (ap == NULL) {
        LOG_ERROR("empty data");
        goto out;
    }
    LOG_DEBUG("AP reset asked by: %s (len: %d)", ap->name, ap->len);
    if ((ap->len == strlen(EXE_NAME)) &&
        (strncmp(EXE_NAME, ap->name, ap->len) == 0))
        events_set(data, E_EVENTS_SUCCEED);

    err = set_and_notify(ev->id, (test_data_t *)ev->context);
    if (err == E_ERR_SUCCESS)
        ret = 0;

out:
    if (ret == 1)
        events_set(data, E_EVENTS_ERROR_OCCURED);
    return ret;
}

/**
 * callback for core dump
 *
 * @param [in] ev current info callback data
 *
 * @return 0 if successful
 * @return 1 otherwise
 */
static int event_core_dump(mmgr_cli_event_t *ev)
{
    int ret = 1;
    e_mmgr_errors_t err = E_ERR_FAILED;
    test_data_t *data = NULL;
    mmgr_cli_core_dump_t *cd = NULL;
    const char *cd_state[] = {
#undef X
#define X(a) #a
        CORE_DUMP_STATE
    };

    CHECK_PARAM(ev, err, out);

    data = (test_data_t *)ev->context;
    if (data == NULL)
        goto out;

    cd = (mmgr_cli_core_dump_t *)ev->data;
    if ((cd == NULL) || (cd->path == NULL)) {
        LOG_ERROR("empty data");
        goto out;
    }

    LOG_DEBUG("state: %s", cd_state[cd->state]);

    if (cd->state == E_CD_SUCCEED) {
        if ((err = is_file_exists(cd->path, 0)) != E_ERR_SUCCESS) {
            char *base_name = basename(cd->path);
            size_t i;
            char *folders[] = { "/mnt/shell/emulated/0/logs/", "/sdcard/" };
            for (i = 0; i < (sizeof(folders) / sizeof(*folders)); i++) {
                LOG_DEBUG("look at: %s", folders[i]);
                if ((err = is_core_dump_found(base_name,
                                              folders[i])) == E_ERR_SUCCESS)
                    break;
            }
        }

        if (err == E_ERR_SUCCESS) {
            LOG_DEBUG("core dump (%s) found", cd->path);
            ret = 0;
        } else
            LOG_ERROR("core dump (%s) NOT found", cd->path);
    } else
        LOG_ERROR("core dump retrieval has failed with reason: (%s)",
                  cd->reason);

out:
    set_and_notify(ev->id, (test_data_t *)ev->context);
    if (ret == 1)
        events_set(data, E_EVENTS_ERROR_OCCURED);
    else
        events_set(data, E_EVENTS_SUCCEED);
    return ret;
}

/**
 * handle the E_MMGR_RESPONSE_MODEM_FW_RESULT event
 *
 * @param [in] ev current info callback data
 *
 * @return 0 if successful
 * @return 1 otherwise
 */
static int event_fw_status(mmgr_cli_event_t *ev)
{
    int ret = 1;
    e_mmgr_errors_t err = E_ERR_FAILED;
    test_data_t *data = NULL;
    mmgr_cli_fw_update_result_t *fw = NULL;

    CHECK_PARAM(ev, err, out);

    data = (test_data_t *)ev->context;
    if (data == NULL)
        goto out;

    fw = (mmgr_cli_fw_update_result_t *)ev->data;
    if (fw == NULL) {
        LOG_ERROR("empty data");
        goto out;
    }
    LOG_DEBUG("fw id:%d", fw->id);
    err = set_and_notify(ev->id, (test_data_t *)ev->context);
    if (err == E_ERR_SUCCESS)
        ret = 0;

out:
    if (ret == 1)
        events_set(data, E_EVENTS_ERROR_OCCURED);
    return ret;
}

/**
 * generic callback event
 *
 * @param [in] ev current info callback data
 *
 * @return 0 if successful
 * @return 1 otherwise
 */
int generic_mmgr_evt(mmgr_cli_event_t *ev)
{
    int ret = 1;
    e_mmgr_errors_t err;
    test_data_t *test_data = NULL;

    CHECK_PARAM(ev, err, out);

    test_data = (test_data_t *)ev->context;
    if (test_data == NULL)
        goto out;

    err = set_and_notify(ev->id, (test_data_t *)ev->context);
    if (err == E_ERR_SUCCESS)
        ret = 0;

out:
    if (ret == 1)
        events_set(test_data, E_EVENTS_ERROR_OCCURED);
    return ret;
}

/**
 * buggy callback function. This function tries to send a message to MMGR.
 * this is forbidden by the API. The purpose of this test is to check that the
 * library rejects this call
 *
 * @param [in] ev current info callback data
 *
 * @return 0 if successful
 * @return 1 otherwise
 */
int bad_callback(mmgr_cli_event_t *ev)
{
    int ret = 1;
    test_data_t *test_data = NULL;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_FORCE_MODEM_SHUTDOWN };

    if (ev == NULL) {
        LOG_ERROR("ev is NULL");
        goto out;
    }

    test_data = (test_data_t *)ev->context;
    if (test_data == NULL)
        goto out;

    if (mmgr_cli_send_msg(test_data->lib, &request) != E_ERR_CLI_REJECTED)
        events_set(test_data, E_EVENTS_ERROR_OCCURED);
    else {
        ret = 0;
        LOG_DEBUG("request correctly rejected");
    }

out:
    if (ret == 1)
        events_set(test_data, E_EVENTS_ERROR_OCCURED);
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
e_mmgr_errors_t cleanup_client_library(test_data_t *test_data)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

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
e_mmgr_errors_t configure_client_library(test_data_t *test_data)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    e_err_mmgr_cli_t err;

    CHECK_PARAM(test_data, ret, out);

    err = mmgr_cli_create_handle(&test_data->lib, EXE_NAME, test_data);
    if (err != E_ERR_CLI_SUCCEED) {
        LOG_ERROR("Get client handle failed");
        ret = E_ERR_BAD_PARAMETER;
        goto out;
    }

    if (mmgr_cli_subscribe_event(test_data->lib, generic_mmgr_evt,
                                 E_MMGR_EVENT_MODEM_DOWN) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, generic_mmgr_evt,
                                 E_MMGR_EVENT_MODEM_UP) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, generic_mmgr_evt,
                                 E_MMGR_EVENT_MODEM_OUT_OF_SERVICE) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, generic_mmgr_evt,
                                 E_MMGR_NOTIFY_CORE_DUMP) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, generic_mmgr_evt,
                                 E_MMGR_NOTIFY_MODEM_COLD_RESET) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, generic_mmgr_evt,
                                 E_MMGR_NOTIFY_MODEM_SHUTDOWN) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, generic_mmgr_evt,
                                 E_MMGR_NOTIFY_PLATFORM_REBOOT) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_core_dump,
                                 E_MMGR_NOTIFY_CORE_DUMP_COMPLETE) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_ap_reset,
                                 E_MMGR_NOTIFY_AP_RESET) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, generic_mmgr_evt,
                                 E_MMGR_NOTIFY_SELF_RESET) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_error,
                                 E_MMGR_NOTIFY_ERROR) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_fw_status,
                                 E_MMGR_RESPONSE_MODEM_FW_RESULT)
        != E_ERR_CLI_SUCCEED)
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
 * perform a modem reset request via a socket request
 *
 * @param [in] data_test test data
 * @param [in] id request to send
 * @param [in] notification expected notification after AT command
 * @param [in] final_state final state expected
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t reset_by_client_request(test_data_t *data_test,
                                        e_mmgr_requests_t id,
                                        e_mmgr_events_t notification,
                                        e_mmgr_events_t final_state)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = id };

    CHECK_PARAM(data_test, ret, out);

    /* Wait modem up */
    ret = wait_for_state(data_test, E_MMGR_EVENT_MODEM_UP, false,
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
        ret = wait_for_state(data_test, notification, true,
                             TIMEOUT_MODEM_DOWN_AFTER_CMD);
        if (ret != E_ERR_SUCCESS)
            goto out;
    }

    /* Wait modem up during TIMEOUT_MODEM_UP_AFTER_RESET seconds to end the
     * test */
    ret = wait_for_state(data_test, final_state, false,
                         TIMEOUT_MODEM_UP_AFTER_RESET);
    if (ret != E_ERR_SUCCESS)
        goto out;

out:
    return ret;
}

/**
 * Ask for a modem core dump
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t at_core_dump(test_data_t *test)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    int err;

    CHECK_PARAM(test, ret, out);

    /* Wait modem up */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP, false,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS) {
        LOG_DEBUG("modem is down");
        goto out;
    }

    err = send_at_cmd(test->config.shtdwn_dlc, AT_CORE_DUMP,
                      strlen(AT_CORE_DUMP));
    if ((err != E_ERR_TTY_POLLHUP) && (err != E_ERR_SUCCESS)) {
        ret = E_ERR_FAILED;
        LOG_ERROR("send of AT commands fails ret=%d" BZ_MSG, ret);
    }

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_DOWN, true,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = wait_for_state(test, E_MMGR_NOTIFY_CORE_DUMP, true,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = wait_for_state(test, E_MMGR_NOTIFY_CORE_DUMP_COMPLETE, true,
                         TIMEOUT_MODEM_UP_AFTER_RESET);
    if (ret != E_ERR_SUCCESS)
        goto out;

    /* Wait modem up during TIMEOUT_MODEM_UP_AFTER_RESET seconds to end the
     * test */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP, false,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
out:
    return ret;
}

/**
 * perform a modem self-reset request via an AT command
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t at_self_reset(test_data_t *test)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    e_mmgr_errors_t err;

    CHECK_PARAM(test, ret, out);

    /* Wait modem up */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP, false,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS) {
        LOG_DEBUG("modem is down");
        goto out;
    }

    /* Send reset command to modem */
    err = send_at_cmd(test->config.shtdwn_dlc, AT_SELF_RESET,
                      strlen(AT_SELF_RESET));
    if ((err != E_ERR_TTY_POLLHUP) && (err != E_ERR_SUCCESS)) {
        ret = E_ERR_FAILED;
        LOG_ERROR("send of AT commands fails ret=%d" BZ_MSG, ret);
    }

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_DOWN, true,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = wait_for_state(test, E_MMGR_NOTIFY_SELF_RESET, true,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    /* Wait modem up during TIMEOUT_MODEM_UP_AFTER_RESET seconds to end the
     * test */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP, false,
                         TIMEOUT_MODEM_UP_AFTER_RESET);
out:
    return ret;
}

static bool is_fake_events_allowed(void)
{
    char build_type[PROPERTY_VALUE_MAX];
    bool answer = false;

    property_get_string(PROPERTY_BUILD_TYPE, build_type);
    if (strncmp(build_type, FAKE_EVENTS_BUILD_TYPE, PROPERTY_VALUE_MAX) == 0)
        answer = true;

    return answer;
}

e_mmgr_errors_t request_fake_ev(test_data_t *test, e_mmgr_requests_t id,
                                e_mmgr_events_t answer, bool check_result)
{
    e_mmgr_errors_t ret = E_ERR_FAILED;
    e_err_mmgr_cli_t err = E_ERR_CLI_FAILED;
    mmgr_cli_requests_t request = {.id = id };

    CHECK_PARAM(test, ret, out);

    err = mmgr_cli_send_msg(test->lib, &request);

    if (!is_fake_events_allowed()) {
        if (err == E_ERR_CLI_SUCCEED) {
            LOG_ERROR("fake request APPROVED in production");
        } else {
            LOG_DEBUG("fake request REJECTED in production");
            ret = E_ERR_SUCCESS;
        }
    } else {
        if (err == E_ERR_CLI_SUCCEED) {
            ret = wait_for_state(test, answer, false,
                                 TIMEOUT_MODEM_DOWN_AFTER_CMD);

            if (check_result && (events_get(test) != E_EVENTS_SUCCEED))
                ret = E_ERR_FAILED;
        }

    }
out:
    return ret;
}
