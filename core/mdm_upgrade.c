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

#define FILE_PERMISSION (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
#define FILTER_SIZE 128

typedef struct mdm_update {
    char tlv_filter[FILTER_SIZE];
    char fls_filter[FILTER_SIZE];
    char provisioning[MY_PATH_MAX];
    char *fls_file;
    char tlv_file[MY_PATH_MAX];
} mdm_upgrade_t;

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

static e_mmgr_errors_t prepare_update(mdm_upgrade_t *update, const char *file)
{
    ASSERT(update != NULL);
    bool fw_update = false;
    bool tlv_update = false;

    if (strstr(file, ".fls")) {
        fw_update = true;
        rename(file, update->fls_file);
    } else if (strstr(file, ".tlv")) {
        tlv_update = true;
        rename(file, update->tlv_file);
    } else if (zip_is_valid(file)) {
        if (E_ERR_SUCCESS == zip_extract_entry(file, update->tlv_filter,
                                               update->tlv_file,
                                               FILE_PERMISSION))
            tlv_update = true;
        if (E_ERR_SUCCESS == zip_extract_entry(file, update->fls_filter,
                                               update->fls_file,
                                               FILE_PERMISSION))
            fw_update = true;
        unlink(file);
    } else if (strstr(file, "package")) {
        /* This is not a zip file and the file is called package. It might be a
         * fls file */
        LOG_DEBUG("Update detected with no extension. "
                  "Let's assume this is a fls file");
        fw_update = true;
        rename(file, update->fls_file);
    } else {
        LOG_ERROR("unknown file type: %s", file);
        unlink(file);
    }

    if (fw_update)
        LOG_DEBUG("Modem firmware update has been installed");
    if (tlv_update)
        LOG_DEBUG("TLV patch has been installed");

    return E_ERR_SUCCESS;
}

mdm_upgrade_hdle_t *mdm_upgrade_init(tlv_info_t *tlv, mdm_info_t *mdm_info,
                                     const char *fls_file)
{
    ASSERT(tlv != NULL);
    ASSERT(mdm_info != NULL);
    ASSERT(fls_file != NULL);

    mdm_upgrade_t *update = calloc(1, sizeof(mdm_upgrade_t));
    ASSERT(update != NULL);

    get_tlv_filter(update->tlv_filter, tlv->filename);
    get_fls_filter(update->fls_filter, mdm_info->name, mdm_info->hw_revision,
                   mdm_info->sw_revision);
    snprintf(update->provisioning, sizeof(update->provisioning),
             "%s/provisioning", tlv->folder);

    snprintf(update->tlv_file, sizeof(update->tlv_file), "%s/%s", tlv->folder,
             tlv->filename);
    update->fls_file = strdup(fls_file);
    return (mdm_upgrade_hdle_t *)update;
}

void mdm_upgrade_dispose(mdm_upgrade_hdle_t *hdle)
{
    mdm_upgrade_t *update = (mdm_upgrade_t *)hdle;

    ASSERT(update != NULL);

    free(update->fls_file);
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

    char *files[10];
    int found = file_find(update->provisioning, "", files, ARRAY_SIZE(files));
    if (found > 2) {
        ret = E_ERR_FAILED;
        LOG_ERROR("more than two files have been detected. Update rejected");
        int i;
        for (i = 0; i < found; i++) {
            unlink(files[i]);
            free(files[i]);
        }
    } else {
        int i;
        for (i = 0; i < found; i++) {
            LOG_DEBUG("file found: %s", files[i]);
            prepare_update(update, files[i]);
            free(files[i]);
        }
    }

    return ret;
}
