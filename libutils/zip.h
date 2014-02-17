/* Modem Manager - zip header file
**
** Copyright (C) Intel 2014
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

#ifndef __MMGR_ZIP_HEADER__
#define __MMGR_ZIP_HEADER__

/**
 * Inflates a zip file entry to a specified location.
 *
 * @param [in] zip_filename Zip file
 * @param [in] filter filter matching the filename in the archive
 * @param [in] dest_path location of extracted file
 * @param [in] dst_mode The mode to give to inflated entry.
 *
 * @return E_ERR_FAILED
 * @return E_ERR_SUCCESS
 */
e_mmgr_errors_t zip_extract_entry(const char *zip_filename, const char *filter,
                                  const char *dest_path, mode_t dst_mode);


bool zip_is_valid(const char *file);
#endif /* __MMGR_ZIP_HEADER__ */
