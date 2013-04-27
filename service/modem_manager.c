/* Modem Manager - main source file
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "errors.h"
#include "logs.h"
#include "config.h"
#include "file.h"
#include "events_manager.h"

#define USAGE \
"Start "MODULE_NAME" Daemon.\n" \
"Usage: "MODULE_NAME" [OPTION]...\n" \
"-h\t\t: Show help options\n" \
"-c <filename>\t: Use <filename> as configuration file\n"

#define GCOV_FOLDER "/data/gcov"

/* global values used to cleanup */
mmgr_data_t *g_mmgr = NULL;

/**
 * Clean MMGR before exit
 */
static void cleanup(void)
{
    events_cleanup(g_mmgr);
    LOG_VERBOSE("Exiting");
}

/**
 * Handle catched signals
 *
 * @param [in] sig signal handler id
 */
static void sig_handler(int sig)
{
    switch (sig) {
    case SIGUSR1:
        pthread_exit(NULL);
        break;
    case SIGHUP:
    case SIGTERM:
        /* nothing to do as cleanup will be called by exit */
        break;
    }
    exit(0);
}

/**
 * Set the handler needed to exit a thread
 *
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED if failed
 */
static e_mmgr_errors_t set_signal_handler(void)
{
    struct sigaction sigact;
    int err = E_ERR_FAILED;

    memset(&sigact, 0, sizeof(struct sigaction));
    /* Signal handler */
    if (sigemptyset(&sigact.sa_mask) == -1) {
        goto end_set_signal_handler;
    }
    sigact.sa_flags = 0;
    sigact.sa_handler = sig_handler;

    if (sigaction(SIGUSR1, &sigact, NULL) == -1) {
        goto end_set_signal_handler;
    }
    if (sigaction(SIGHUP, &sigact, NULL) == -1) {
        goto end_set_signal_handler;
    }
    if (sigaction(SIGTERM, &sigact, NULL) == -1) {
        goto end_set_signal_handler;
    }

    /* configuration successful */
    err = E_ERR_SUCCESS;

end_set_signal_handler:
    return err;
}

/**
 * Modem Manager main function
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
    e_mmgr_errors_t ret = EXIT_SUCCESS;
    char *conf_file = DEFAULT_MMGR_CONFIG_FILE;
    mmgr_data_t mmgr;

    g_mmgr = &mmgr;

    while (-1 != (err = getopt(argc, argv, "hc:v"))) {
        switch (err) {
        case 'c':
            conf_file = optarg;
            break;

        case 'h':
            puts(USAGE);
            goto out;
            break;

        case 'v':
            fprintf(stdout, "%s (last commit: \"%s\")\n", argv[0],
                    GIT_COMMIT_ID);
            goto out;
            break;

        default:
            puts(USAGE);
            goto out;
        }
    }
    LOG_DEBUG("Boot. last commit: \"%s\"", GIT_COMMIT_ID);

#ifdef GOCV_MMGR
    setenv("GCOV_PREFIX", GCOV_FOLDER, 1);
    mkdir(GCOV_FOLDER, 0777);
#else
    /* set default umask to have 664 as default value to new files */
    umask(MMGR_UMASK);
#endif

    if (set_signal_handler() == E_ERR_FAILED) {
        LOG_ERROR("Error during sigaction initialization. Exit");
        ret = EXIT_FAILURE;
        goto out;
    }

    if (atexit(cleanup) != 0) {
        LOG_ERROR("Exit configuration failed. Exit");
        ret = EXIT_FAILURE;
        goto out;
    }

    if ((err = mmgr_configure(&mmgr.config, conf_file))
        == E_ERR_BAD_PARAMETER) {
        LOG_ERROR("Initialization failed (reason=%d). Exit", err);
        ret = EXIT_FAILURE;
        goto out;
    }

    err = recov_init(&mmgr.config, &mmgr.reset);
    if (err != E_ERR_SUCCESS) {
        LOG_ERROR("Reset escalation init failed (reason=%d). Exit", err);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (events_init(&mmgr) != E_ERR_SUCCESS) {
        LOG_ERROR("Events configuration failed. Exit");
        ret = EXIT_FAILURE;
        goto out;
    }
    events_manager(&mmgr);
out:
    /* @TODO: REMOVE EXIT. bogus? If returns is used, atexit function callback
     * is called but mmgr is deallocated... */
    exit(ret);
    return ret;
}
