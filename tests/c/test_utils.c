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
#include "errors.h"
#include "file.h"
#include "test_utils.h"
#include "tty.h"

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#define DEV_GSMTTY "/dev/gsmtty1"
#define LEN_FILTER 10

#define AT_SELF_RESET "AT+CFUN=15\r"
#define AT_CORE_DUMP "AT+XLOG=4\r"

#define BZ_MSG "\n\n*** YOU SHOULD RAISE A BZ ***\n"

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
        pthread_cond_timedwait(&test_data->cond, &test_data->cond_mutex, &ts);
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

static int event_ap_reset(mmgr_cli_event_t *ev)
{
    int ret = E_ERR_FAILED;
    test_data_t *data = NULL;
    mmgr_cli_ap_reset_t *ap = NULL;

    CHECK_PARAM(ev, ret, out);
    data = (test_data_t *)ev->context;
    if (data == NULL)
        goto out;

    data->test_succeed = false;

    ap = (mmgr_cli_ap_reset_t *)ev->data;
    if (ap == NULL) {
        LOG_ERROR("empty data");
        goto out;
    }
    LOG_DEBUG("AP reset asked by: %s (len: %d)", ap->name, ap->len);
    if ((ap->len == strlen(EXE_NAME)) &&
        (strncmp(EXE_NAME, ap->name, ap->len) == 0))
        data->test_succeed = true;

    ret = set_and_notify(ev->id, (test_data_t *)ev->context);
out:
    return ret;
}

static int event_core_dump(mmgr_cli_event_t *ev)
{
    int ret = E_ERR_FAILED;
    test_data_t *data = NULL;
    mmgr_cli_core_dump_t *cd = NULL;
    char *base_name = NULL;

    CHECK_PARAM(ev, ret, out);
    data = (test_data_t *)ev->context;
    if (data == NULL)
        goto out;

    data->test_succeed = false;

    cd = (mmgr_cli_core_dump_t *)ev->data;
    if (cd == NULL) {
        LOG_ERROR("empty data");
        goto out;
    }

    switch (cd->state) {
    case E_CD_FAILED:
        LOG_ERROR("core dump not retrived");
        goto out;
        break;
    case E_CD_SUCCEED_WITHOUT_PANIC_ID:
        LOG_DEBUG("No panid id");
        break;
    case E_CD_SUCCEED:
        LOG_DEBUG("panic id: %d", cd->panic_id);
        break;
    }
    LOG_DEBUG("core dump path: %s", cd->path);

    base_name = basename(cd->path);
    if ((is_file_exists(cd->path, 0) == E_ERR_SUCCESS)
        || (is_core_dump_found(base_name, "/sdcard/") == E_ERR_SUCCESS)) {
        LOG_DEBUG("core dump found");
        data->test_succeed = true;
    }

    ret = set_and_notify(ev->id, (test_data_t *)ev->context);
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

    if (mmgr_cli_subscribe_event(test_data->lib, event_core_dump,
                                 E_MMGR_NOTIFY_CORE_DUMP_COMPLETE) !=
        E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_ap_reset,
                                 E_MMGR_NOTIFY_AP_RESET) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_without_ack,
                                 E_MMGR_NOTIFY_SELF_RESET) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test_data->lib, event_without_ack,
                                 E_MMGR_NOTIFY_ERROR) != E_ERR_CLI_SUCCEED)
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
 * @return E_ERR_MODEM_OUT if modem is OUT
 * @return E_ERR_FAILED test fails
 * @return E_ERR_SUCCESS if successful
 */
int reset_by_client_request(test_data_t *data_test,
                            e_mmgr_requests_t id,
                            e_mmgr_events_t notification,
                            e_mmgr_events_t final_state)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = id };

    CHECK_PARAM(data_test, ret, out);

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

    ret = wait_for_state(data_test, E_MMGR_EVENT_MODEM_DOWN,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    if (notification != E_MMGR_NUM_EVENTS) {
        ret = wait_for_state(data_test, notification,
                             TIMEOUT_MODEM_DOWN_AFTER_CMD);
        if (ret != E_ERR_SUCCESS)
            goto out;
    }

    /* Wait modem up during TIMEOUT_MODEM_UP_AFTER_RESET seconds
       to end the test */
    ret = wait_for_state(data_test, final_state, TIMEOUT_MODEM_UP_AFTER_RESET);
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
 * @return E_ERR_MODEM_OUT if modem is OUT
 * @return E_ERR_FAILED test fails
 * @return E_ERR_SUCCESS if successful
 */
int at_core_dump(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    int err;

    CHECK_PARAM(test, ret, out);

    /* Wait modem up */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS) {
        LOG_DEBUG("modem is down");
        goto out;
    }

    err = send_at_cmd(AT_CORE_DUMP, strlen(AT_CORE_DUMP));
    if ((err != E_ERR_TTY_POLLHUP) && (err != E_ERR_SUCCESS)) {
        ret = E_ERR_FAILED;
        LOG_ERROR("send of AT commands fails ret=%d" BZ_MSG, ret);
    }

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_DOWN,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = wait_for_state(test, E_MMGR_NOTIFY_CORE_DUMP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = wait_for_state(test, E_MMGR_NOTIFY_CORE_DUMP_COMPLETE,
                         TIMEOUT_MODEM_UP_AFTER_RESET);
    if (ret != E_ERR_SUCCESS)
        goto out;

    /* Wait modem up during TIMEOUT_MODEM_UP_AFTER_RESET seconds
       to end the test */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
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
 * @return E_ERR_MODEM_OUT if modem is OUT
 * @return E_ERR_FAILED test fails
 * @return E_ERR_SUCCESS if successful
 */
int at_self_reset(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    int err;

    CHECK_PARAM(test, ret, out);

    /* Wait modem up */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS) {
        LOG_DEBUG("modem is down");
        goto out;
    }

    /* Send reset command to modem */
    err = send_at_cmd(AT_SELF_RESET, strlen(AT_SELF_RESET));
    if ((err != E_ERR_TTY_POLLHUP) && (err != E_ERR_SUCCESS)) {
        ret = E_ERR_FAILED;
        LOG_ERROR("send of AT commands fails ret=%d" BZ_MSG, ret);
    }

    ret = wait_for_state(test, E_MMGR_NOTIFY_SELF_RESET,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

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
