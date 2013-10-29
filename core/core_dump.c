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

typedef struct mcdr_lib {
    bool enabled;
    void *lib;
    mcdr_data_t data;
    void (*read)(mcdr_data_t *);
    void (*cleanup)(void);
    mcdr_status_t (*get_state)(void);
    char *(*get_reason)(void);
} mcdr_lib_t;

typedef struct core_dump_thread {
    pthread_t thread_id;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    mcdr_lib_t *mcdr;
} core_dump_thread_t;

/* the recovery time must not exceed */
#define CORE_DUMP_RECOVERY_MAX_TIME 1200

#ifdef GOCV_MMGR
#define MCDR_LIBRARY_NAME "libmcdr-gcov.so"
#else
#define MCDR_LIBRARY_NAME "libmcdr.so"
#endif

#define MCDR_GET_CORE_DUMP "mcdr_get_core_dump"
#define MCDR_CLEANUP "mcdr_cleanup"
#define MCDR_GET_STATE "mcdr_get_state"
#define MCDR_GET_REASON "mcdr_get_reason"

/**
 * initialize core dump. If the libmcdr is available, mcdr will be enabled
 * disabled if not.
 *
 * @param [in] cfg
 *
 * @return a valid mcdr_handle_t pointer
 * @return NULL otherwise
 */
mcdr_handle_t *mcdr_init(const mcdr_info_t *cfg)
{
    char *p = NULL;
    mcdr_lib_t *mcdr = NULL;

    if (!cfg) {
        LOG_ERROR("cfg is NULL");
        goto err;
    }

    mcdr = calloc(1, sizeof(mcdr_lib_t));
    if (!mcdr) {
        LOG_ERROR("memory allocation failed");
        goto err;
    }

    if (!cfg->gnl.enable) {
        mcdr->enabled = false;
        LOG_VERBOSE("failed to load library");
    } else {
        mcdr->lib = dlopen(MCDR_LIBRARY_NAME, RTLD_LAZY);
        if (mcdr->lib == NULL) {
            mcdr->enabled = false;
            dlerror();
        } else {
            mcdr->enabled = true;
            mcdr->data.mcdr_info = *cfg;

            mcdr->read = dlsym(mcdr->lib, MCDR_GET_CORE_DUMP);
            mcdr->cleanup = dlsym(mcdr->lib, MCDR_CLEANUP);
            mcdr->get_state = dlsym(mcdr->lib, MCDR_GET_STATE);
            mcdr->get_reason = dlsym(mcdr->lib, MCDR_GET_REASON);

            p = (char *)dlerror();
            if (p != NULL) {
                LOG_ERROR("An error ocurred during symbol resolution");
                goto err;
            }
        }
    }

    return (mcdr_handle_t *)mcdr;

err:
    mcdr_dispose((mcdr_handle_t *)mcdr);
    return NULL;
}

/**
 * @brief mcdr_dispose
 *
 * @param h module handle
 *
 * @return E_ERR_SUCCESS if succeed
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t mcdr_dispose(mcdr_handle_t *h)
{
    mcdr_lib_t *mcdr = (mcdr_lib_t *)h;
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    if (h) {
        dlclose(mcdr->lib);
        free(mcdr);
    } else {
        ret = E_ERR_FAILED;
    }

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
 * @param [in] h module handle
 * @param [out] state
 *
 * @return E_ERR_BAD_PARAMETER if mcdr is NULL
 * @return E_ERR_SUCCESS if successful
 * @return E_ERR_FAILED otherwise
 */
e_mmgr_errors_t mcdr_read(mcdr_handle_t *h, e_core_dump_state_t *state)
{
    int err = 0;
    e_mmgr_errors_t ret = E_ERR_FAILED;
    struct timespec ts;
    struct timeval tp;
    struct timeval tp_end;
    core_dump_thread_t cd_reader;
    mcdr_lib_t *mcdr = (mcdr_lib_t *)h;

    CHECK_PARAM(mcdr, ret, out);
    CHECK_PARAM(state, ret, out);

    /* initialize thread structure */
    pthread_mutex_init(&cd_reader.mutex, NULL);
    pthread_cond_init(&cd_reader.cond, NULL);
    cd_reader.mcdr = mcdr;
    cd_reader.thread_id = -1;
    *state = E_CD_OTHER;

    /* Start core dump reader */
    LOG_DEBUG("starting MCDR");
    err = pthread_create(&cd_reader.thread_id, NULL, (void *)thread_core_dump,
                         (void *)&cd_reader);
    if (err != 0) {
        LOG_ERROR("Failed to launch MCDR");
        goto out;
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
        if (MCDR_ARCHIVE_IN_PROGRESS == mcdr->get_state()) {
            LOG_DEBUG("Archiving still on-going");
            /* @TODO: perhaps a timeout can be usefull to prevent infinite
             * archiving process */
        } else {
            LOG_ERROR("Core dump retrieval takes too much time. Aborting");
            mcdr->cleanup();
            *state = E_CD_TIMEOUT;
        }
    }

    if (cd_reader.thread_id != -1) {
        /* The thread exit normally. Join it */
        if (pthread_join(cd_reader.thread_id, NULL) != 0)
            LOG_ERROR("failed to join the thread");
    }

    if (*state != E_CD_TIMEOUT) {
        switch (mcdr->get_state()) {
        case MCDR_SUCCEED:
            gettimeofday(&tp_end, NULL);
            LOG_VERBOSE("Succeed (in %lus.) name:%s", tp_end.tv_sec -
                        tp.tv_sec, mcdr->data.coredump_file);
            *state = E_CD_SUCCEED;
            ret = E_ERR_SUCCESS;
            break;

        case MCDR_FS_ERROR:
        case MCDR_INIT_ERROR:
        case MCDR_IO_ERROR:
            *state = E_CD_LINK_ERROR;
            break;

        case MCDR_START_PROT_ERR:
        case MCDR_PROT_ERROR:
            *state = E_CD_PROTOCOL_ERROR;
            break;

        default:
            /* nothing to do */
            break;
        }
    }

out:
    return ret;
}

/**
 * Returns the path where core dump is stored
 * The returned value must not be freed
 *
 * @param [in] h module handle
 *
 * @return path
 * @return NULL if h is NULL
 */
const char *mcdr_get_path(mcdr_handle_t *h)
{
    mcdr_lib_t *mcdr = (mcdr_lib_t *)h;
    char *path = NULL;

    if (h)
        path = mcdr->data.mcdr_info.gnl.path;

    return path;
}

/**
 * Returns the filename where core dump is stored
 * The returned value must not be freed
 *
 * @param [in] h module handle
 *
 * @return filename
 * @return NULL if h is NULL
 */
const char *mcdr_get_filename(mcdr_handle_t *h)
{
    mcdr_lib_t *mcdr = (mcdr_lib_t *)h;
    char *filename = NULL;

    if (h)
        filename = mcdr->data.coredump_file;

    return filename;
}

/**
 * Returns the error reason
 * The returned value must not be freed
 *
 * @param [in] h module handle
 *
 * @return error reason
 * @return NULL if h is NULL
 */
const char *mcdr_get_error_reason(mcdr_handle_t *h)
{
    mcdr_lib_t *mcdr = (mcdr_lib_t *)h;
    char *reason = NULL;

    if (h)
        reason = mcdr->get_reason();

    return reason;
}

/**
 * Returns if core dump feature is enabled
 *
 * @param [in] h module handle
 *
 * @return false by default
 * @return valid state otherwise
 */
bool mcdr_is_enabled(mcdr_handle_t *h)
{
    bool enable = false;
    mcdr_lib_t *mcdr = (mcdr_lib_t *)h;

    if (h)
        enable = mcdr->enabled;

    return enable;
}
