# Modem Manager (MMGR) - indent MMGR script
#
# Copyright (C) Intel 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/bin/bash

# Please, before uploading a new patch, run this script to indent
# properly the MMGR code.

INDENT_RULES="-linux -nut -cdw -il0 -i4"

# All typdefs declared in source files (instead of header) or indent unknown
# typedefs must be declared here
TYPEDEFS_SRC=(bool GKeyFile core_dump_thread_t size_t test_case_t mmgr_cli_handle_t fd_set)

function indent_c_mmgr
{
    local dir=$1
    # C typedefs management
    local src_types=" "
    for (( i=0; i<${#TYPEDEFS_SRC[@]}; i++ )); do
        src_types+="-T ${TYPEDEFS_SRC[$i]} "
    done

    # extract header and source file list
    local src_list=$(find $dir -type f -name "*.[ch]")

    # extract typedefs declared in header files
    local hdr_types=$(sed -n 's:^ *}\ *\([^;]*_t\);.*:-T \1 :p' $src_list | \
        tr -d '\n')

    # code indenatation: extract specific typdefs from headers files to help
    # indent.
    indent $INDENT_RULES $src_types $hdr_types $src_list
}

# LET's do the job:
if [ ! $(command -v indent) ]; then
    echo "You need to install indent first"
    exit
fi

if [ $# -ne 1 ]; then
    echo "Usage: $0 <dir>"
    exit
fi

indent_c_mmgr $1

# Remove backup files
find $1 -name "*~" -exec rm {} \;
