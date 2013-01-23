/* Modem Manager (MMGR) test application - tests definition source file
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
#include <stdio.h>
#include <unistd.h>
#include "crash_logger.h"
#include "errors.h"
#include "mmgr.h"
#include "property.h"
#include "test_cases.h"

#define RESET_CMD_NO_CORE_DUMP "AT+CFUN=15\r"
#define RESET_CMD_CORE_DUMP "AT+XLOG=4\r"

#define MAX_MOVING_FILE_SLEEP 20
#define RIL_PROPERTY "persist.ril-daemon.disable"

/**
 * Test modem reset without core dump
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int modem_self_reset(test_data_t *test)
{
    int ret = E_ERR_FAILED;

    CHECK_PARAM(test, ret, out);

    remove_file(CL_MODEM_SELF_RESET_FILE);

    ret = reset_by_at_cmd(test, RESET_CMD_NO_CORE_DUMP,
                          strlen(RESET_CMD_NO_CORE_DUMP), E_MMGR_NUM_EVENTS);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = is_file_exists(CL_MODEM_SELF_RESET_FILE, CL_FILE_PERMISSIONS);
out:
    return ret;
}

/**
 * Test modem reset with core dump
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int reset_with_cd(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    const char *core_dump_dir[] = { "/sdcard/" LOGS_FOLDER, LOGS_FOLDER };
    char filename[FILENAME_SIZE + 1] = "";
    aplog_thread_t aplog_data;
    int err;
    int i;

    aplog_data.thread_id = -1;
    aplog_data.running = true;
    aplog_data.state = E_CD_NO_PATTERN;
    pthread_mutex_init(&aplog_data.mutex, NULL);

    err = pthread_create(&aplog_data.thread_id, NULL,
                         (void *)listen_aplogs, (void *)&aplog_data);
    if (err < 0) {
        LOG_ERROR("Failed to create listen aplogs thread: [%s]",
                  strerror(errno));
        goto out;
    }

    cleanup_modemcrash_dir(MODEM_LOGS_FOLDER);

    ret = reset_by_at_cmd(test, RESET_CMD_CORE_DUMP,
                          strlen(RESET_CMD_CORE_DUMP), E_MMGR_NOTIFY_CORE_DUMP);
    if (ret != E_ERR_SUCCESS)
        goto out;

    pthread_mutex_lock(&aplog_data.mutex);
    if (aplog_data.state == E_CD_SUCCEED) {
        strncpy(filename, aplog_data.filename, FILENAME_SIZE);
        LOG_DEBUG("core dump %s successfuly generated in %ds", filename,
                  aplog_data.duration);
    } else {
        LOG_ERROR("core dump retrieve failed. Reason=%d", aplog_data.state);
    }
    pthread_mutex_unlock(&aplog_data.mutex);

    /* looking for core dump files */
    ret = E_ERR_FAILED;
    for (i = 0; i < MAX_MOVING_FILE_SLEEP; i++) {
        if ((is_core_dump_found(filename, core_dump_dir[0]) == E_ERR_SUCCESS)
            || (is_core_dump_found(filename, core_dump_dir[1])
                == E_ERR_SUCCESS)) {
            ret = E_ERR_SUCCESS;
            break;
        } else
            sleep(1);
    }
    /* Check if modem crash log is present */
    if ((ret == E_ERR_SUCCESS) &&
        (is_file_exists(CL_CORE_DUMP_FILE, CL_FILE_PERMISSIONS)
         == E_ERR_SUCCESS) &&
        (compare_file_content(CL_CORE_DUMP_FILE, UNKNOWN_PANIC_ID_STR,
                              strlen(UNKNOWN_PANIC_ID_STR))))
        ret = E_ERR_SUCCESS;
    else
        ret = E_ERR_FAILED;

out:
    if (aplog_data.thread_id != -1) {
        LOG_DEBUG("stopping aplog thread");
        pthread_mutex_lock(&aplog_data.mutex);
        aplog_data.running = false;
        pthread_mutex_unlock(&aplog_data.mutex);
        LOG_DEBUG("wait for join");
        pthread_join(aplog_data.thread_id, NULL);
    }
    return ret;
}

/**
 * Test modem reset with E_MMGR_REQUEST_MODEM_RECOVERY request
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int modem_recovery(test_data_t *test)
{
    return reset_by_client_request(test, true, E_MMGR_REQUEST_MODEM_RECOVERY,
                                   E_MMGR_NUM_EVENTS, E_MMGR_EVENT_MODEM_UP);
}

/**
 * Test modem reset with E_MMGR_REQUEST_MODEM_RESTART request
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int modem_restart(test_data_t *test)
{
    return reset_by_client_request(test, true, E_MMGR_REQUEST_MODEM_RESTART,
                                   E_MMGR_NOTIFY_MODEM_COLD_RESET,
                                   E_MMGR_EVENT_MODEM_UP);
}

/**
 * Test a complete reset escalation recovery
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int full_recovery(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    int i;
    int reboot;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_MODEM_RECOVERY };

    CHECK_PARAM(test, ret, out);

    puts("\n*************************************************************\n"
         "To perform this test, you should have just boot your phone\n"
         "and performed no test. If a reset escalation has already been\n"
         "performed, the test will be declared FAILED\n"
         "*************************************************************\n\n");

    for (i = 1; i <= test->config.nb_warm_reset; i++) {
        printf("\nCheck #%d WARM reset\n", i);
        ret = reset_by_client_request(test, true,
                                      E_MMGR_REQUEST_MODEM_RECOVERY,
                                      E_MMGR_NOTIFY_MODEM_WARM_RESET,
                                      E_MMGR_EVENT_MODEM_UP);
        if (ret != E_ERR_SUCCESS)
            goto out;
    }
    if (test->config.modem_cold_reset_enable) {

        for (i = 1; i <= test->config.nb_cold_reset; i++) {
            printf("\nCheck #%d COLD reset\n", i);
            ret = reset_by_client_request(test, true,
                                          E_MMGR_REQUEST_MODEM_RECOVERY,
                                          E_MMGR_NOTIFY_MODEM_COLD_RESET,
                                          E_MMGR_EVENT_MODEM_UP);
            if (ret != E_ERR_SUCCESS)
                goto out;
        }
    }

    if (test->config.platform_reboot_enable) {
        printf("\nCheck Reboot mechanism\n");
        get_property(PLATFORM_REBOOT_KEY, &reboot);
        if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
            ret = E_ERR_FAILED;
            goto out;
        }

        if (reboot >= test->config.nb_platform_reboot) {
            ret = wait_for_state(test, E_MMGR_EVENT_MODEM_OUT_OF_SERVICE,
                                 TIMEOUT_MODEM_DOWN_AFTER_CMD);
            if (ret == E_ERR_MODEM_OUT)
                ret = E_ERR_SUCCESS;
        } else {
            ret = wait_for_state(test, E_MMGR_NOTIFY_PLATFORM_REBOOT,
                                 TIMEOUT_MODEM_DOWN_AFTER_CMD);
            if (ret == E_ERR_MODEM_OUT)
                ret = E_ERR_SUCCESS;
            ret &= is_file_exists(CL_REBOOT_FILE, CL_FILE_PERMISSIONS);
        }
    }

out:
    return ret;
}

/**
 * Test reset counter mechanism. Reboot counter shall be set to 0
 * and a warm modem reset shall be performed
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int reset_counter(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    int counter;

    CHECK_PARAM(test, ret, out);

    set_property(PLATFORM_REBOOT_KEY, 123);
    LOG_DEBUG("waiting during %ds. Please, do not use your phone",
              test->config.min_time_issue + 1);
    sleep(test->config.min_time_issue + 1);

    ret = reset_by_client_request(test, true, E_MMGR_REQUEST_MODEM_RECOVERY,
                                  E_MMGR_NOTIFY_MODEM_WARM_RESET,
                                  E_MMGR_EVENT_MODEM_UP);
    if (ret != E_ERR_SUCCESS)
        goto out;

    get_property(PLATFORM_REBOOT_KEY, &counter);
    if (counter != 0) {
        LOG_DEBUG("reset escalation not reseted");
        ret = E_ERR_FAILED;
    }

out:
    return ret;
}

/**
 * Turn off the modem
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int turn_off_modem(test_data_t *test)
{
    int ret = E_ERR_FAILED;

    CHECK_PARAM(test, ret, out);

    ret = reset_by_client_request(test, false,
                                  E_MMGR_REQUEST_FORCE_MODEM_SHUTDOWN,
                                  E_MMGR_NOTIFY_MODEM_SHUTDOWN,
                                  E_MMGR_EVENT_MODEM_DOWN);
    if (ret != E_ERR_SUCCESS)
        goto out;

    LOG_DEBUG("stopping the RIL");
    ret = set_property(RIL_PROPERTY, 1);

out:
    return ret;
}

/**
 * Turn on the modem
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int turn_on_modem(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_RESOURCE_ACQUIRE };

    CHECK_PARAM(test, ret, out);

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_DOWN,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS) {
        LOG_DEBUG("modem is up");
        goto out;
    }

    LOG_DEBUG("starting the RIL");
    ret = set_property(RIL_PROPERTY, 0);

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
    } else {
        ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
                             TIMEOUT_MODEM_UP_AFTER_RESET);
    }

out:
    return ret;
}

/**
 * Test socket banned client mechanism
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int client_banned(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    int i;
    int err = E_ERR_SUCCESS;
    mmgr_cli_requests_t request = {.id = E_MMGR_RESOURCE_ACQUIRE };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_disconnect(test->lib) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test->lib, event_without_ack,
                                 E_MMGR_ACK) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_subscribe_event(test->lib, event_without_ack,
                                 E_MMGR_NACK) != E_ERR_CLI_SUCCEED)
        goto out;

    if (mmgr_cli_connect(test->lib) != E_ERR_CLI_SUCCEED)
        goto out;

    /* Wait modem up */
    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = E_ERR_FAILED;
    for (i = 0;
         i < (test->config.max_requests_banned + 1) && err != E_ERR_FAILED;
         i++) {
        printf("\nsending message #%d\n", i + 1);
        if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED)
            err = E_ERR_FAILED;
        if (wait_for_state(test, E_MMGR_ACK, 5) != E_ERR_SUCCESS)
            err = E_ERR_FAILED;
        /* force modem state to be sure that ACK is received next time */
        modem_state_set(test, E_MMGR_NACK);
    }
    LOG_DEBUG("i=%d err=%d", i, err);
    if ((i == test->config.max_requests_banned) && (err == E_ERR_FAILED)
        && (mmgr_cli_connect(test->lib) == E_ERR_CLI_SUCCEED))
        ret = E_ERR_SUCCESS;

out:
    return ret;
}

/**
 * This test checks the resource des/allocation mechanism
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED if test fails
 * @return E_ERR_SUCCESS if test succes
 */
int resource_check(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_RESOURCE_ACQUIRE };

    CHECK_PARAM(test, ret, out);

    puts("\n*************************************************************\n"
         "This test is only possible if no clients have acquire the \n"
         "resource...\n"
         "*************************************************************\n");

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);
    if (ret != E_ERR_SUCCESS)
        goto out;

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    sleep(1);

    request.id = E_MMGR_RESOURCE_RELEASE;
    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_NOTIFY_MODEM_SHUTDOWN, 5);
    if (ret != E_ERR_SUCCESS)
        goto out;

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_DOWN,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

    request.id = E_MMGR_RESOURCE_ACQUIRE;
    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

out:
    return ret;
}

/**
 * lib mmgr client API stress test
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED if test fails
 * @return E_ERR_SUCCESS if test succes
 */
int test_libmmgrcli_api(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    int line = -1;

    CHECK_PARAM(test, ret, out);
    mmgr_cli_requests_t request = {.id = E_MMGR_NUM_REQUESTS };
    mmgr_cli_handle_t *hdle;

    if (mmgr_cli_create_handle(NULL, EXE_NAME, NULL) != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_create_handle(&hdle, EXE_NAME, NULL) != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    hdle = NULL;
    if (mmgr_cli_create_handle(&hdle, NULL, NULL) != E_ERR_CLI_FAILED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_create_handle(&hdle, EXE_NAME, NULL) != E_ERR_CLI_SUCCEED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_delete_handle(NULL) != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    mmgr_cli_connect(hdle);

    if (mmgr_cli_delete_handle(hdle) != E_ERR_CLI_FAILED) {
        line = __LINE__;
        goto out;
    }

    mmgr_cli_disconnect(hdle);

    if (mmgr_cli_delete_handle(hdle) != E_ERR_CLI_SUCCEED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_subscribe_event(test->lib, event_without_ack,
                                 E_MMGR_ACK) != E_ERR_CLI_FAILED) {

        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_disconnect(test->lib) != E_ERR_CLI_SUCCEED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_disconnect(NULL) != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_subscribe_event(test->lib, NULL, E_MMGR_ACK)
        != E_ERR_CLI_FAILED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_subscribe_event(test->lib, event_without_ack,
                                 E_MMGR_NUM_EVENTS) != E_ERR_CLI_FAILED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_subscribe_event(NULL, event_without_ack, E_MMGR_ACK)
        != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_subscribe_event(test->lib, event_without_ack,
                                 E_MMGR_ACK) != E_ERR_CLI_SUCCEED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_unsubscribe_event(test->lib, E_MMGR_NACK) != E_ERR_CLI_SUCCEED) {
        line = __LINE__;
        goto out;
    }
    if (mmgr_cli_unsubscribe_event(test->lib, E_MMGR_NACK) != E_ERR_CLI_SUCCEED) {
        line = __LINE__;
        goto out;
    }
    if (mmgr_cli_unsubscribe_event(test->lib, E_MMGR_NUM_EVENTS)
        != E_ERR_CLI_FAILED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_unsubscribe_event(NULL, E_MMGR_ACK) != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_lock(test->lib) != E_ERR_CLI_FAILED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_unlock(test->lib) != E_ERR_CLI_FAILED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_connect(test->lib) != E_ERR_CLI_SUCCEED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_connect(NULL) != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_lock(test->lib) != E_ERR_CLI_SUCCEED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_lock(test->lib) != E_ERR_CLI_ALREADY_LOCK) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_unlock(test->lib) != E_ERR_CLI_SUCCEED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_unlock(test->lib) != E_ERR_CLI_ALREADY_UNLOCK) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_send_msg(test->lib, NULL) != E_ERR_CLI_FAILED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_FAILED) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_send_msg(NULL, &request) != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_unlock(NULL) != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    if (mmgr_cli_lock(NULL) != E_ERR_CLI_BAD_HANDLE) {
        line = __LINE__;
        goto out;
    }

    ret = E_ERR_SUCCESS;

out:
    if (ret != E_ERR_SUCCESS)
        LOG_ERROR("test failed at line %d", line);
    return ret;
}
