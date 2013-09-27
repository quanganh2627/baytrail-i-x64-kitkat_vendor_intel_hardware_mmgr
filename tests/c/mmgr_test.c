/* Modem Manager (MMGR) test application
**
** Copyright (C) Intel 2010
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

#include <cutils/sockets.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "errors.h"
#include "test_cases.h"
#include "mmgr.h"

#define MIN_MMGR_VERSION  "3.2.1"
#define CAUTION_MESSAGE   "\n\n" \
    "***********************************************************************\n" \
    "CAUTION: This is the "MODULE_NAME " test application. It's designed for \n" \
    "engineering tests purpose only. You should be aware of "MODULE_NAME "\n" \
    "mechanism before using it. According to your platform configuration,\n" \
    "your modem can be declared OUT OF SERVICE or your platform can\n" \
    "REBOOT.\n" \
    "Please, don't forget to disable crashtool report to avoid useless reports.\n" \
    "NB: Reboot your phone to recover if your modem is out.\n\n" \
    "Use it with CAUTION.\n" \
    "***********************************************************************\n" \
    "Are you sure you wish to continue? (Y/N): "

#define USAGE "\n" \
    "--------------------------------------------------\n" \
    "Usage: "EXE_NAME " [-h] [-f] [-t <test number>]\n" \
    "optional arguments:\n" \
    " -h or --help      show this help message and exit\n" \
    " -f                skip CAUTION message\n" \
    " -v                display "EXE_NAME " version and "MODULE_NAME \
    " minimal version\n" \
    " -t <test number>  launch the specified test\n\n" \
    "long option name:\n"

#define PRINT_TEST \
    "\n******************************************\n" \
    "Name: %s\n" \
    "State: %s\n" \
    "********************************************\n\n"

#define INVALID_CHOICE \
    "\n***********************************\n" \
    "**     Invalid test choice       **\n" \
    "***********************************\n"

#define DESCRIPTION_LEN 70
#define INVALID_TEST    -2

#define TEST_RESULT \
    X(SUCCEED), \
    X(FAILED), \
    X(INCONCLUSIVE)

typedef struct test_case {
    char desc[DESCRIPTION_LEN];
    e_mmgr_errors_t (*func)(test_data_t *data);
    char name[DESCRIPTION_LEN];
} test_case_t;

enum {
#undef X
#define X(a) E_TEST_ ## a
    TEST_RESULT
};

/**
 * Run selected test
 *
 * @param [in,out] test test data
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED if test failed
 * @return E_ERR_OUT_OF_SERVICE if modem is out of service
 * @return E_ERR_BAD_PARAMETER if at least one bad parameter is given
 */
e_mmgr_errors_t run_test(test_case_t *test)
{
    test_data_t test_data;
    e_mmgr_errors_t ret = E_ERR_FAILED;
    int result = E_TEST_FAILED;;
    e_events_t ev = E_EVENTS_NONE;
    char *state[] = {
#undef X
#define X(a) #a
        TEST_RESULT
    };

    CHECK_PARAM(test, ret, out);

    test_data.lib = NULL;
    test_data.waited_state = E_MMGR_NUM_EVENTS;
    test_data.modem_state = E_MMGR_NUM_EVENTS;
    test_data.events = E_EVENTS_NONE;
    pthread_mutex_init(&test_data.new_state_read, NULL);
    pthread_mutex_init(&test_data.mutex, NULL);
    pthread_mutex_init(&test_data.cond_mutex, NULL);
    pthread_cond_init(&test_data.cond, NULL);

    if ((ret = mmgr_configure(&test_data.config, DEFAULT_MMGR_CONFIG_FILE))
        == E_ERR_BAD_PARAMETER) {
        LOG_ERROR("initialization failed");
        goto out;
    }

    ret = configure_client_library(&test_data);
    if (ret != E_ERR_SUCCESS) {
        LOG_ERROR("Failed to configure mmgr_cli library");
        goto out;
    }

    printf(PRINT_TEST, test->desc, "started");

    ret = test->func(&test_data);
    ev = events_get(&test_data);
    if (ev & E_EVENTS_ERROR_OCCURED) {
        LOG_DEBUG("An error occured during the test");
        result = E_TEST_FAILED;
    } else {
        switch (ret) {
        case E_ERR_SUCCESS:
            result = E_TEST_SUCCEED;
            break;
        case E_ERR_FAILED:
            if (ev & E_EVENTS_MODEM_OOS)
                result = E_TEST_INCONCLUSIVE;
            else
                result = E_TEST_FAILED;
            break;
        case E_ERR_BAD_PARAMETER:
            result = E_TEST_FAILED;
            LOG_DEBUG("bad parameter");
            break;
        default:
            result = E_TEST_FAILED;
            LOG_ERROR("bad returned value");
            break;
        }
    }
    printf(PRINT_TEST, test->desc, state[result]);

    ret = cleanup_client_library(&test_data);
    if (ret != E_ERR_SUCCESS)
        LOG_ERROR("failed to disconnect properly the client");

out:
    LOG_DEBUG("end");
    return ret;
}

/**
 * Display user menu to choose the test
 *
 * @param [in] tests tests descriptions
 * @param [in] nb_test number of tests
 * @param [out] choice test selected
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_BAD_PARAMETER if tests or/and choice is/are NULL
 */
int choose_test(test_case_t *tests, int nb_test, int *choice)
{
    char data[64];
    char *end_ptr = NULL;
    int i;
    int ret = E_ERR_SUCCESS;

    CHECK_PARAM(tests, ret, out);
    CHECK_PARAM(choice, ret, out);

    for (;; ) {
        printf("\n"
               "***********************************\n"
               "***   %s - TEST APPLICATION   ***\n"
               "***********************************\n", MODULE_NAME);
        for (i = 0; i < nb_test; i++)
            printf("%-2d - %s\n", i + 1, tests[i].desc);

        printf("0 - Quit the test application.\n\n"
               "Please select the test to run: ");
        fgets(data, 6, stdin);
        *choice = strtol(data, &end_ptr, 10);
        if ((data == end_ptr) || (strlen(data) > 3))
            continue;
        if ((*choice >= 0) && (*choice <= nb_test))
            break;
        else
            puts(INVALID_CHOICE);
    }
    (*choice)--;
out:
    return ret;
}

/**
 * Display caution message
 *
 * @return true if user agree with caution message
 * @return false otherwise
 */
bool agree_caution(void)
{
    char choice[64];
    bool accept = false;

    do {
        puts(CAUTION_MESSAGE);
        fgets(choice, 64, stdin);
    } while ((*choice != 'Y') && (*choice != 'N'));

    if (*choice == 'Y')
        accept = true;
    return accept;
}

void usage(test_case_t *test, int nb)
{
    int i;

    puts(USAGE);
    for (i = 0; i < nb; i++)
        printf("--%-16s %s\n", test[i].name, test[i].desc);
}

/**
 * mmgr-test main
 *
 * @param [in] argc number of arguments
 * @param [in] argv list of arguments
 *
 * @return EXIT_FAILURE if failed
 * @return EXIT_SUCCESS if successful
 */
int main(int argc, char *argv[])
{
    e_mmgr_errors_t err = E_ERR_FAILED;
    int choice;
    int ret = EXIT_SUCCESS;
    int test_id = INVALID_TEST;
    bool display_caution = true;
    char *end_ptr = NULL;
    struct option *long_opts = NULL;
    int nb_tests = 0;
    int index = 0;
    int i;

    /* *INDENT-OFF* */
    test_case_t tests[] = {
        { "Modem self-reset", modem_self_reset, "self-reset" },
        { "Modem recovery request", modem_recovery, "recovery" },
        { "Modem restart request (by-pass reset escalation)", modem_restart,
          "restart" },
        { "Modem reset with core dump", reset_with_cd, "cd" },
        { "Force modem OFF and RIL", turn_off_modem, "off" },
        { "Turn on modem and RIL", turn_on_modem, "on" },
        { "Full reset escalation", full_recovery, "full" },
        { "Reset escalation counter", reset_counter, "timer" },
        { "Resource management (works only if no client is connected)",
          resource_check, "resource" },
        { "lib mmgr API check", test_libmmgrcli_api, "cli" },
        { "resource acquire", resource_acquire, "acquire" },
        { "resource release", resource_release, "release" },
        { "FAKE REQUEST: modem up", fake_modem_up, "fake_up" },
        { "FAKE REQUEST: modem down", fake_modem_down, "fake_down" },
        { "FAKE REQUEST: core dump", fake_cd, "fake_cd" },
        { "FAKE REQUEST: core dump complete", fake_cd_complete, "fake_cd_end" },
        { "FAKE REQUEST: ap reset", fake_ap_reset, "fake_ap_reset" },
        { "FAKE REQUEST: self-reset", fake_self_reset, "fake_self_reset" },
        { "FAKE REQUEST: modem shutdown", fake_modem_shtdwn, "fake_shutdown" },
        { "FAKE REQUEST: platform reboot", fake_reboot, "fake_reboot" },
        { "FAKE REQUEST: modem out of service", fake_modem_hs, "fake_oos" },
        { "FAKE REQUEST: error", fake_error, "fake_error" },
        { "ENDLESS TEST: start the modem and keep it alive", start_modem,
          "start_modem" }
    };
    /* *INDENT-ON* */

    nb_tests = sizeof(tests) / sizeof(*tests);
    long_opts = calloc(sizeof(struct option), (nb_tests + 1));
    if (long_opts == NULL) {
        LOG_ERROR("memory allocation failed");
        goto out;
    }

    for (i = 0; i < nb_tests; i++) {
        long_opts[i].name = tests[i].name;
        long_opts[i].has_arg = 0;
        long_opts[i].flag = NULL;
        long_opts[i].val = i;
    }

    while ((choice =
                getopt_long(argc, argv, "vhft:", long_opts, &index)) != -1) {
        if (index != 0) {
            test_id = long_opts[index].val;
        } else {
            switch (choice) {
            case 'f':
                display_caution = false;
                break;
            case 't':
                test_id = strtol(optarg, &end_ptr, 10) - 1;
                if (optarg == end_ptr)
                    test_id = INVALID_TEST;
                break;
            case 'v':
                printf("\n%s (Build: %s:%s).\n"
                       "Needs at least %s version: %s\n\n", EXE_NAME,
                       __DATE__, __TIME__, MODULE_NAME, MIN_MMGR_VERSION);
                goto out;
                break;
            case 'h':
            default:
                usage(tests, nb_tests);
                goto out;
                break;
            }
        }
    }

    if (display_caution)
        if (!agree_caution())
            goto out;
    if (test_id == INVALID_TEST)
        choose_test(tests, sizeof(tests) / sizeof(*tests), &test_id);
    if ((test_id >= 0) && (test_id < nb_tests))
        err = run_test(&tests[test_id]);
    else
    if (test_id != -1)
        puts(INVALID_CHOICE);

out:
    if (long_opts != NULL)
        free(long_opts);

    LOG_DEBUG("end");
    if (err != E_ERR_SUCCESS)
        ret = EXIT_FAILURE;
    return ret;
}
