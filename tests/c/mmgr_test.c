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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "errors.h"
#include "test_cases.h"
#include "mmgr.h"

#define MIN_MMGR_VERSION  "3.2.1"
#define CAUTION_MESSAGE   "\n\n" \
"***********************************************************************\n"\
"CAUTION: This is the "MODULE_NAME" test application. It's designed for \n"\
"engineering tests purpose only. You should be aware of "MODULE_NAME"\n" \
"mechanism before using it. According to your platform configuration,\n" \
"your modem can be declared OUT OF SERVICE or your platform can\n" \
"REBOOT.\n" \
"Please, don't forget to disable crashtool report to avoid useless reports.\n" \
"NB: Reboot your phone to recover if your modem is out.\n\n" \
"Use it with CAUTION.\n" \
"***********************************************************************\n"\
"Are you sure you wish to continue? (Y/N): "

#define USAGE "\n" \
    "--------------------------------------------------\n" \
"Usage: "EXE_NAME" [-h] [-f] [-t <test number>]\n" \
"optional arguments:\n" \
" -h                show this help message and exit\n" \
" -f                skip CAUTION message\n" \
" -v                display "EXE_NAME" version and "MODULE_NAME \
                    " minimal version\n" \
" -t <test number>  launch the specified test\n"

#define PRINT_TEST \
"\n*************** Test %s ***************\n" \
"(Name: %s) %s\n" \
"********************************************\n\n"

#define INVALID_CHOICE \
"\n***********************************\n" \
"**     Invalid test choice       **\n" \
"***********************************\n"

#define DESCRIPTION_LEN 70
#define INVALID_TEST    -2

typedef struct test_case {
    char desc[DESCRIPTION_LEN];
    int (*func) (test_data_t *data);
} test_case_t;

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
int run_test(test_case_t *test)
{
    test_data_t test_data;
    int ret = E_ERR_FAILED;
    int result = 1;
    char *state[] = { "SUCCEED", "FAILED",
        "SUCCEED but modem is OUT due to correct reset escalation behavior"
    };

    CHECK_PARAM(test, ret, out);

    test_data.lib = NULL;
    test_data.waited_state = -1;
    test_data.modem_state = -1;
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

    printf(PRINT_TEST, "started", test->desc, "");

    ret = test->func(&test_data);
    switch (ret) {
    case E_ERR_SUCCESS:
        result = 0;
        break;
    case E_ERR_FAILED:
        result = 1;
        break;
    case E_ERR_MODEM_OUT:
        result = 2;
        break;
    case E_ERR_BAD_PARAMETER:
        LOG_DEBUG("bad param");
        break;
    }
    printf(PRINT_TEST, "result has", test->desc, state[result]);

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

    for (;;) {
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
        if ((*choice >= 0) && (*choice <= nb_test)) {
            break;
        } else {
            puts(INVALID_CHOICE);
        }
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
    int err;
    int ret = EXIT_SUCCESS;
    int test_id = INVALID_TEST;
    bool display_caution = true;
    char *end_ptr = NULL;

    test_case_t tests[] = {
        {.desc = "Modem self-reset",.func = modem_self_reset},
        {.desc = "Modem recovery request",.func = modem_recovery},
        {
         .desc = "Modem restart request (by-pass reset escalation)",
         .func = modem_restart},
        {.desc = "Modem reset with core dump",.func = reset_with_cd},
        {.desc = "Force modem OFF and RIL",.func = turn_off_modem},
        {.desc = "Turn on modem and RIL",.func = turn_on_modem},
        {.desc = "Client banned",.func = client_banned},
        {.desc = "Full reset escalation",.func = full_recovery},
        {.desc = "Reset escalation counter",.func = reset_counter},
        {.desc = "Resource management (works only if no client is connected)",
         .func = resource_check},
        {.desc = "lib mmgr API check",.func = test_libmmgrcli_api},
    };

    while ((err = getopt(argc, argv, "vhft:")) != -1) {
        switch (err) {
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
            puts(USAGE);
            goto out;
            break;
        }
    }

    if (display_caution) {
        if (!agree_caution())
            goto out;
    }
    if (test_id == INVALID_TEST) {
        choose_test(tests, sizeof(tests) / sizeof(*tests), &test_id);
    }
    if ((test_id >= 0) && (test_id < (int)(sizeof(tests) / sizeof(*tests)))) {
        err = run_test(&tests[test_id]);
    } else {
        if (test_id != -1)
            puts(INVALID_CHOICE);
    }

out:
    LOG_DEBUG("end");
    if (err != E_ERR_SUCCESS)
        ret = EXIT_FAILURE;
    return ret;
}
