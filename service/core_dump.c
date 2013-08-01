/* Modem Manager - core dump source file
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
#include <dlfcn.h>
#include <pthread.h>
#include "core_dump.h"
#include "errors.h"
#include "logs.h"

typedef struct core_dump_thread {
    pthread_t thread_id;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    mcdr_lib_t *mcdr;
} core_dump_thread_t;

/* Core dump reader configuration filename */
#define MCDR_CONFIG_FILE "/system/etc/telephony/mcdr.conf"
/* the recovery time must not exceed */
#define CORE_DUMP_RECOVERY_MAX_TIME 600
#define MCDR_LIBRARY_NAME "libmcdr.so"

#define MCDR_GET_CORE_DUMP "mcdr_get_core_dump"
#define MCDR_CLEANUP "mcdr_cleanup"
#define MCDR_GET_STATE "mcdr_get_state"

/**
 * initialize core dump. If the libmcdr is available, mcdr will be enabled
 * disabled if not.
 *
 * @param [in] config mmgr config
 * @param [in,out] mcdr mcdr config
 *
 * @return E_ERR_BAD_PARAMETER if mcdr is NULL
 * @return E_ERR_FAILED initialization fails
 * @return E_ERR_SUCCESS if successful
 */
e_mmgr_errors_t core_dump_init(const mmgr_configuration_t *config,
                               mcdr_lib_t *mcdr)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    char *p = NULL;
    const char *str_protocol[] = { "LCDP", "YMODEM" };

    CHECK_PARAM(mcdr, ret, out);

    if (!config->modem_core_dump_enable) {
        mcdr->enabled = false;
        LOG_VERBOSE("failed to load library");
    } else {
        mcdr->lib = dlopen(MCDR_LIBRARY_NAME, RTLD_LAZY);
        if (mcdr->lib == NULL) {
            mcdr->enabled = false;
            dlerror();
        } else {
            mcdr->enabled = true;
            mcdr->data.baudrate = config->mcdr_baudrate;
            strncpy(mcdr->data.path, config->mcdr_path, MAX_SIZE_CONF_VAL - 1);
            strncpy(mcdr->data.port, config->mcdr_device,
                    MAX_SIZE_CONF_VAL - 1);
            mcdr->read = dlsym(mcdr->lib, MCDR_GET_CORE_DUMP);
            mcdr->cleanup = dlsym(mcdr->lib, MCDR_CLEANUP);
            mcdr->get_state = dlsym(mcdr->lib, MCDR_GET_STATE);

            p = (char *)dlerror();
            if (p != NULL) {
                LOG_ERROR("An error ocurred during symbol resolution");
                dlclose(mcdr->lib);
                mcdr->lib = NULL;
                ret = E_ERR_FAILED;
            }

            if (strncmp(config->mcdr_protocol, "LCDP", MAX_SIZE_CONF_VAL) == 0)
                mcdr->data.protocol = LCDP;
            else
                mcdr->data.protocol = YMODEM;

            LOG_DEBUG("MCDR protocol: %s", str_protocol[mcdr->data.protocol]);
        }
    }
out:
    return ret;
}

/**
 * function calling the mcdr lib. This function will send a signal once the
 * the operation is ended
 *
 * @param [in,out] cd_reader core dump thread struct
 */
static void thread_core_dump(core_dump_thread_t *cd_reader)
{
    cd_reader->mcdr->read(&cd_reader->mcdr->data);
    /* the thread is finished. send the conditional signal waited by
     * pthread_cond_timedwait */
    pthread_mutex_lock(&cd_reader->mutex);
    pthread_cond_signal(&cd_reader->cond);
    pthread_mutex_unlock(&cd_reader->mutex);
    return;
}

/**
 * Start core dump reader program.
 *
 * @param [in] mcdr mcdr config
 *
 * @return E_ERR_BAD_PARAMETER if mcdr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t retrieve_core_dump(mcdr_lib_t *mcdr)
{
    int err;
    e_mmgr_errors_t ret = E_ERR_FAILED;
    struct timespec ts;
    struct timeval tp;
    struct timeval tp_end;
    core_dump_thread_t cd_reader;
    mcdr_status_t status;

    CHECK_PARAM(mcdr, ret, out);

    /* initialize thread structure */
    mcdr->state = E_CD_FAILED;
    pthread_mutex_init(&cd_reader.mutex, NULL);
    pthread_cond_init(&cd_reader.cond, NULL);
    cd_reader.mcdr = mcdr;
    cd_reader.thread_id = -1;

    /* Start core dump reader */
    LOG_DEBUG("launch core dump reader");
    err = pthread_create(&cd_reader.thread_id, NULL, (void *)thread_core_dump,
                         (void *)&cd_reader);
    if (err != 0) {
        LOG_ERROR("Start core dump reader FAILED");
        return E_ERR_FAILED;
    }

    /* The core dump read operation can't exceed two minutes. The thread will
     * be interrupted with pthread_cond_timedwait */

    /* Get the current time and add CORE_DUMP_RECOVERY_MAX_TIME. */
    gettimeofday(&tp, NULL);
    ts.tv_sec = tp.tv_sec;
    ts.tv_nsec = tp.tv_usec * 1000;
    ts.tv_sec += CORE_DUMP_RECOVERY_MAX_TIME;

    /* launch time condition The mutex must be locked before calling
     * pthread_cond_timedwait. */
    pthread_mutex_lock(&cd_reader.mutex);
    err = pthread_cond_timedwait(&cd_reader.cond, &cd_reader.mutex, &ts);
    pthread_mutex_unlock(&cd_reader.mutex);

    if (err == ETIMEDOUT) {
        status = mcdr->get_state();
        LOG_ERROR("Timeout. mcdr_status = %d", status);
        if (status == MCDR_ARCHIVE_IN_PROGRESS) {
            LOG_DEBUG("Archiving still on-going");
            /* @TODO: perhaps a timeout can be usefull to prevent infinite
             * archiving process */
        } else {
            LOG_ERROR("Core dump retrieval takes too much time. Aborting");
            mcdr->cleanup();
        }
    }

    if (cd_reader.thread_id != -1) {
        /* The thread exit normally. Join it */
        err = pthread_join(cd_reader.thread_id, NULL);
        if (err != 0) {
            LOG_DEBUG("ERROR during thread_join");
        } else {
            if (mcdr->data.state == MCDR_SUCCEED) {
                gettimeofday(&tp_end, NULL);
                LOG_VERBOSE("Succeed (in %lus.) name:%s", tp_end.tv_sec -
                            tp.tv_sec, mcdr->data.coredump_file);
                ret = E_ERR_SUCCESS;
                mcdr->state = E_CD_SUCCEED_WITHOUT_PANIC_ID;
            } else {
                LOG_ERROR("Failed with error %d", mcdr->data.state);
            }
        }
    }
out:
    return ret;
}
