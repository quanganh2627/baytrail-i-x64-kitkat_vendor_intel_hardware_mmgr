/* Modem Manager - modem upgrade source file
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

#include <libgen.h>
#include <sys/stat.h>

#include "common.h"
#include "errors.h"
#include "file.h"
#include "logs.h"
#include "mdm_upgrade.h"
#include "zip.h"
#include "property.h"
#include "client_cnx.h"

#define DSDA_PROVISIONING "service.mmgr.dsda_provisioning"
#define MODEM_ZIP_PATH "/system/etc/firmware/modem/modem.zip"

/* This is a magic path, but it's also hardcoded in POS/ROS */
#define PROVISIONING_FOLDER "/config/telephony/provisioning"

#define FILE_PERMISSION (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
#define FILTER_SIZE 128

typedef struct tlv_updates {
    char filter[FILTER_SIZE];
    char file[MY_PATH_MAX];
} tlv_updates_t;

typedef struct mdm_update {
    char fls_filter[FILTER_SIZE];
    char *fls_file;
    char *run_folder;
    tlv_updates_t *tlvs;
    size_t nb_tlv;
    int upgrade_err;
    bool dsda;
    int inst_id;
} mdm_upgrade_t;

typedef enum err_type {
    ERR_FLS,
    ERR_TLV,
} err_type_t;

static inline bool flag_is_set(void)
{
    int value = 0;

    property_get_int(DSDA_PROVISIONING, &value);

    return value == 1;
}

static inline void flag_set(void)
{
    property_set_int(DSDA_PROVISIONING, 1);
}

static inline void flag_unset(void)
{
    property_set_int(DSDA_PROVISIONING, 0);
}

/**
 * Replace tlv extension by a regexp used by sscanf
 *
 * @param [out] filter
 * @param [in] file name of tlv file
 *
 * @return E_ERR_SUCCESS
 * @return E_ERR_FAILED
 */
static e_mmgr_errors_t get_tlv_filter(char *filter, const char *file)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    ASSERT(filter != NULL);
    ASSERT(file != NULL);

    strncpy(filter, file, FILTER_SIZE);
    filter[FILTER_SIZE - 1] = '\0';
    char *find = strstr(filter, ".tlv");
    if (find) {
        static const char *const regexp = "%*1[.]%*1[t]%*1[l]%1[v]";
        snprintf(find, FILTER_SIZE - (find - filter), "%s", regexp);
    } else {
        LOG_DEBUG("wrong file extension");
        ret = E_ERR_FAILED;
    }

    return ret;
}

static void mdm_upgrade_set_error(mdm_upgrade_t *upgrade, err_type_t type)
{
    ASSERT(upgrade != NULL);

    switch (type) {
    case ERR_FLS:
        upgrade->upgrade_err |= MDM_UPGRADE_FLS_ERROR;
        break;
    case ERR_TLV:
        upgrade->upgrade_err |= MDM_UPGRADE_TLV_ERROR;
        break;
    default:
        break;
    }
}

int mdm_upgrade_get_error(mdm_upgrade_hdle_t *hdle)
{
    mdm_upgrade_t *upgrade = (mdm_upgrade_t *)hdle;

    ASSERT(upgrade != NULL);

    return upgrade->upgrade_err;
}

/**
 * Create fls filter used to extract fls in zip file
 *
 * @param [out] filter
 * @param [in] mdm_name
 * @param [in] hw_revision
 * @param [in] sw_revision
 *
 * @return E_ERR_SUCCESS
 * @return E_ERR_FAILED
 */
static void get_fls_filter(char *filter, const char *mdm_name,
                           const char *hw_revision, const char *sw_revision)
{
    ASSERT(mdm_name != NULL);
    ASSERT(hw_revision != NULL);
    ASSERT(sw_revision != NULL);

    if (!strncmp(mdm_name, "6360", 4)) {
        /* This is a 6360 modem. This modem has a different convention naming */
        snprintf(filter, FILTER_SIZE, "XMM_%s%%1[_]", mdm_name);
    } else {
        bool has_hw_rev = strncmp(hw_revision, "NA", 2);
        bool has_sw_rev = strncmp(sw_revision, "NA", 2);

        snprintf(filter, FILTER_SIZE, "XMM_%s_REV", mdm_name);

        if (has_hw_rev)
            strncat(filter, hw_revision, FILTER_SIZE - strlen(filter));
        else
            strncat(filter, "%*2[0-9]", FILTER_SIZE - strlen(filter));

        strncat(filter, "_%*4[0-9].%*2[0-9]_V", FILTER_SIZE - strlen(filter));

        if (has_sw_rev)
            strncat(filter, sw_revision, FILTER_SIZE - strlen(filter));
        else
            strncat(filter, "%*1[0-9].%*1[0-9]", FILTER_SIZE - strlen(filter));

        strncat(filter, "_%*[^.]%*1[.]%*1[f]%*1[l]%1[s]", FILTER_SIZE -
                strlen(filter));
    }
}

/**
 * Extract TLV files from zip archive
 *
 * @param [out] update
 * @param [in] file
 *
 * @return E_ERR_SUCCESS
 * @return E_ERR_FAILED
 */
static inline e_mmgr_errors_t extract_tlv_files(mdm_upgrade_t *update,
                                                const char *file)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;

    LOG_INFO("Extracting TLV files from: %s", file);
    for (size_t i = 0; i < update->nb_tlv; i++) {
        if (E_ERR_SUCCESS !=
            zip_extract_entry(file, update->tlvs[i].filter,
                              update->tlvs[i].file,
                              FILE_PERMISSION)) {
            mdm_upgrade_set_error(update, ERR_TLV);
            LOG_ERROR("TLV extraction has failed");
            ret = E_ERR_FAILED;
            break;
        }
    }

    return ret;
}

static e_mmgr_errors_t prepare_update(mdm_upgrade_t *update, const char *file)
{
    ASSERT(update != NULL);
    bool fw_update = false;
    bool tlv_update = false;

    if (update->dsda && (update->inst_id == DEFAULT_INST_ID)
        && flag_is_set()) {
        LOG_DEBUG("fw already extracted. Nothing to do");
        goto out;
    }

    if (strstr(file, ".fls")) {
        if (rename(file, update->fls_file))
            mdm_upgrade_set_error(update, ERR_FLS);
        else
            fw_update = true;
    } else if (strstr(file, ".tlv")) {
        char dst[MY_PATH_MAX];
        snprintf(dst, MY_PATH_MAX, "%s/%s", update->run_folder, basename(file));
        if (rename(file, dst))
            mdm_upgrade_set_error(update, ERR_TLV);
        else
            tlv_update = true;
    } else if (zip_is_valid(file)) {
        if (E_ERR_SUCCESS == extract_tlv_files(update, file))
            tlv_update = true;
        if (E_ERR_SUCCESS == zip_extract_entry(file, update->fls_filter,
                                               update->fls_file,
                                               FILE_PERMISSION))
            fw_update = true;
        else
            mdm_upgrade_set_error(update, ERR_FLS);
        if (!update->dsda) {
            unlink(file);
        } else {
            if (update->inst_id == DEFAULT_INST_ID) {
                flag_set();
            } else if (flag_is_set()) {
                unlink(file);
                flag_unset();
            }
        }
    } else if (strstr(file, "package")) {
        /* This is not a zip file and the file is called package. It might be a
         * fls file */
        LOG_DEBUG("Update detected with no extension. "
                  "Let's assume this is a fls file");
        if (rename(file, update->fls_file))
            mdm_upgrade_set_error(update, ERR_FLS);
        else
            fw_update = true;
    } else {
        LOG_ERROR("unknown file type: %s", file);
        unlink(file);
    }

    if (fw_update)
        LOG_DEBUG("Modem firmware update has been installed");
    if (tlv_update)
        LOG_DEBUG("TLV patch has been installed");

    if (fw_update && !tlv_update)
        if (file_exist(MODEM_ZIP_PATH, 0) == true)
            extract_tlv_files(update, MODEM_ZIP_PATH);
out:
    return E_ERR_SUCCESS;
}

mdm_upgrade_hdle_t *mdm_upgrade_init(tlvs_info_t *tlvs, int inst_id, bool dsda,
                                     mdm_info_t *mdm,
                                     const char *fls_file,
                                     const char *run_folder)
{
    ASSERT(tlvs != NULL);
    ASSERT(mdm != NULL);
    ASSERT(fls_file != NULL);
    ASSERT(run_folder != NULL);

    mdm_upgrade_t *update = calloc(1, sizeof(mdm_upgrade_t));
    ASSERT(update != NULL);

    update->tlvs = calloc(tlvs->nb, sizeof(tlv_updates_t));
    ASSERT((update->tlvs != NULL) || (tlvs->nb == 0));

    update->nb_tlv = tlvs->nb;
    for (size_t i = 0; i < tlvs->nb; i++) {
        get_tlv_filter(update->tlvs[i].filter, tlvs->tlv[i].filename);
        snprintf(update->tlvs[i].file, sizeof(update->tlvs[i].file), "%s/%s",
                 run_folder, tlvs->tlv[i].filename);
    }

    get_fls_filter(update->fls_filter, mdm->core.name,
                   mdm->core.hw_revision, mdm->core.sw_revision);

    update->fls_file = strdup(fls_file);
    update->run_folder = strdup(run_folder);

    update->dsda = dsda;
    update->inst_id = inst_id;

    return (mdm_upgrade_hdle_t *)update;
}

void mdm_upgrade_dispose(mdm_upgrade_hdle_t *hdle)
{
    mdm_upgrade_t *update = (mdm_upgrade_t *)hdle;

    ASSERT(update != NULL);

    free(update->fls_file);
    free(update->run_folder);
    free(update->tlvs);
    free(update);
}

/**
 * Checks for modem upgrade. If an update is found, it moves the files in the
 * right place
 *
 * @param [in] hdle
 *
 * @return E_ERR_SUCCESS
 * @return E_ERR_FAILED
 */
e_mmgr_errors_t mdm_upgrade(mdm_upgrade_hdle_t *hdle)
{
    e_mmgr_errors_t ret = E_ERR_SUCCESS;
    mdm_upgrade_t *update = (mdm_upgrade_t *)hdle;

    ASSERT(update != NULL);

    /* reset modem upgrade error flag */
    update->upgrade_err = 0;

    char *files[10];
    int found = file_find(PROVISIONING_FOLDER, "", files, ARRAY_SIZE(files));
    if (found > 2) {
        ret = E_ERR_FAILED;
        LOG_ERROR("more than two files have been detected. Update rejected");
        for (int i = 0; i < found; i++) {
            unlink(files[i]);
            free(files[i]);
        }
    } else {
        for (int i = 0; i < found; i++) {
            LOG_DEBUG("file found: %s", files[i]);
            prepare_update(update, files[i]);
            free(files[i]);
        }
    }

    return ret;
}

char *mdm_upgrade_get_tlv_path(mdm_upgrade_hdle_t *hdle)
{
    char *path = NULL;
    mdm_upgrade_t *update = (mdm_upgrade_t *)hdle;

    if (update)
        path = update->run_folder;

    return path;
}

/**
 * Extract TLV files from modem.zip
 *
 * @param [in] hdle
 *
 * @return E_ERR_SUCCESS
 * @return E_ERR_FAILED
 */
e_mmgr_errors_t mdm_upgrade_extract_tlv_files(mdm_upgrade_hdle_t *hdle)
{
    mdm_upgrade_t *update = (mdm_upgrade_t *)hdle;
    e_mmgr_errors_t ret = E_ERR_FAILED;

    ASSERT(update != NULL);

    if (zip_is_valid(MODEM_ZIP_PATH))
        ret = extract_tlv_files(update, MODEM_ZIP_PATH);

    return ret;
}
