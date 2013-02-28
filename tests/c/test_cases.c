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
#include "errors.h"
#include "file.h"
#include "mmgr.h"
#include "property.h"
#include "test_cases.h"

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

    ret = at_self_reset(test);

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

    CHECK_PARAM(test, ret, out);

    ret = at_core_dump(test);
    if (!test->test_succeed)
        ret = E_ERR_FAILED;

out:
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
    int ret = E_ERR_FAILED;

    CHECK_PARAM(test, ret, out);

    ret = reset_by_client_request(test, E_MMGR_REQUEST_MODEM_RECOVERY,
                                  E_MMGR_NUM_EVENTS, E_MMGR_EVENT_MODEM_UP);

    if (!test->test_succeed)
        ret = E_ERR_FAILED;

out:
    return ret;
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
    int ret = E_ERR_FAILED;

    CHECK_PARAM(test, ret, out);

    ret = reset_by_client_request(test, E_MMGR_REQUEST_MODEM_RESTART,
                                  E_MMGR_NOTIFY_MODEM_COLD_RESET,
                                  E_MMGR_EVENT_MODEM_UP);
    if (!test->test_succeed)
        ret = E_ERR_FAILED;

out:
    return ret;
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
        test->test_succeed = false;
        ret = reset_by_client_request(test,
                                      E_MMGR_REQUEST_MODEM_RECOVERY,
                                      E_MMGR_NOTIFY_MODEM_WARM_RESET,
                                      E_MMGR_EVENT_MODEM_UP);
        if ((ret != E_ERR_SUCCESS) && (!test->test_succeed))
            goto out;
    }
    if (test->config.nb_cold_reset > 0) {

        for (i = 1; i <= test->config.nb_cold_reset; i++) {
            printf("\nCheck #%d COLD reset\n", i);
            test->test_succeed = false;
            ret = reset_by_client_request(test,
                                          E_MMGR_REQUEST_MODEM_RECOVERY,
                                          E_MMGR_NOTIFY_MODEM_COLD_RESET,
                                          E_MMGR_EVENT_MODEM_UP);
            if ((ret != E_ERR_SUCCESS) && (!test->test_succeed))
                goto out;
        }
    }

    if (test->config.nb_platform_reboot > 0) {
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
        }
    }

out:
    return ret;
}

/**
 * Resource acquire test
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int resource_acquire(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_RESOURCE_ACQUIRE };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_send_msg(test->lib, &request) == E_ERR_CLI_SUCCEED)
        ret = E_ERR_SUCCESS;
out:
    return ret;
}

/**
 * Resource release test
 *
 * @param [in] test test data
 *
 * @return E_ERR_BAD_PARAMETER if test is NULL
 * @return E_ERR_FAILED test fails
 * @return E_ERR_OUT_OF_SERVICE test fails because MODEM is OUT
 * @return E_ERR_SUCCESS if successful
 */
int resource_release(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_RESOURCE_RELEASE };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_send_msg(test->lib, &request) == E_ERR_CLI_SUCCEED)
        ret = E_ERR_SUCCESS;
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

    ret = reset_by_client_request(test, E_MMGR_REQUEST_MODEM_RECOVERY,
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

    ret = reset_by_client_request(test,
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

int fake_modem_down(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_FAKE_DOWN };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_DOWN,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

out:
    return ret;
}

int fake_modem_up(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_FAKE_UP };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_UP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

out:
    return ret;
}

int fake_modem_shtdwn(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_FAKE_MODEM_SHUTDOWN };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_NOTIFY_MODEM_SHUTDOWN,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

out:
    return ret;
}

int fake_modem_hs(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id =
            E_MMGR_REQUEST_FAKE_MODEM_OUT_OF_SERVICE
    };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_EVENT_MODEM_OUT_OF_SERVICE,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

out:
    return ret;
}

int fake_cd(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_FAKE_CORE_DUMP };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_NOTIFY_CORE_DUMP,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

out:
    return ret;
}

int fake_cd_complete(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request =
        {.id = E_MMGR_REQUEST_FAKE_CORE_DUMP_COMPLETE };

    CHECK_PARAM(test, ret, out);

    test->test_succeed = false;

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_NOTIFY_CORE_DUMP_COMPLETE,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

    if (!test->test_succeed)
        ret = E_ERR_FAILED;
out:
    return ret;
}

int fake_error(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_FAKE_ERROR };

    CHECK_PARAM(test, ret, out);

    test->test_succeed = false;

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_NOTIFY_ERROR,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

    if (!test->test_succeed)
        ret = E_ERR_FAILED;
out:
    return ret;
}

int fake_ap_reset(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_FAKE_AP_RESET };

    CHECK_PARAM(test, ret, out);

    test->test_succeed = false;

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_NOTIFY_AP_RESET,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

    if (!test->test_succeed)
        ret = E_ERR_FAILED;
out:
    return ret;
}

int fake_self_reset(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_FAKE_SELF_RESET };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_NOTIFY_SELF_RESET,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

out:
    return ret;
}

int fake_reboot(test_data_t *test)
{
    int ret = E_ERR_FAILED;
    mmgr_cli_requests_t request = {.id = E_MMGR_REQUEST_FAKE_PLATFORM_REBOOT
    };

    CHECK_PARAM(test, ret, out);

    if (mmgr_cli_send_msg(test->lib, &request) != E_ERR_CLI_SUCCEED) {
        ret = E_ERR_FAILED;
        goto out;
    }

    ret = wait_for_state(test, E_MMGR_NOTIFY_PLATFORM_REBOOT,
                         TIMEOUT_MODEM_DOWN_AFTER_CMD);

out:
    return ret;
}
