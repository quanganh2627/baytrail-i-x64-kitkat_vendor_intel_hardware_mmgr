LOCAL_PATH:= $(call my-dir)

#############################################
# General rules:
#############################################
MY_MODULE := mmgr-test
MY_MODULE_TAGS := optional tests

MY_INCLUDES := \
    $(LOCAL_PATH)/../../inc \

MY_SRC_FILES := $(call all-c-files-under, .)
MY_C_FLAGS := -Wall -Werror -Wvla -DSTDIO_LOGS -DMODULE_NAME=\"MMGR-TEST\"

MY_SHARED_LIBS := libcutils libc
MY_LOCAL_IMPORT := libtcs libmmgr_utils libmmgrcli libmmgr_cnx
MY_LD_LIBS := -lpthread

#############################################
# MODEM MANAGER C application test
#############################################
include $(CLEAR_VARS)
LOCAL_MODULE := $(MY_MODULE)
LOCAL_MODULE_TAGS := $(MY_MODULE_TAGS)

LOCAL_C_INCLUDES := $(MY_INCLUDES)
LOCAL_SRC_FILES := $(MY_SRC_FILES)
LOCAL_CFLAGS += $(MY_C_FLAGS)

# libmcdr is not linked. Only import the header
LOCAL_IMPORT_C_INCLUDE_DIRS_FROM_SHARED_LIBRARIES := $(MY_LOCAL_IMPORT) libmcdr
LOCAL_LDLIBS += $(MY_LD_LIBS)
LOCAL_SHARED_LIBRARIES := $(MY_SHARED_LIBS) $(MY_LOCAL_IMPORT)
include $(BUILD_EXECUTABLE)

#############################################
# MODEM MANAGER C application test - GCOV
#############################################
ifeq ($(mmgr_gcov), true)

include $(CLEAR_VARS)
LOCAL_MODULE := $(addsuffix -gcov, $(MY_MODULE))
LOCAL_MODULE_TAGS := $(MY_MODULE_TAGS)

LOCAL_C_INCLUDES := $(MY_INCLUDES)
LOCAL_SRC_FILES := $(MY_SRC_FILES)
LOCAL_CFLAGS += $(MY_C_FLAGS) -fprofile-arcs -ftest-coverage

MY_LOCAL_GCOV_IMPORT := $(foreach file,$(MY_LOCAL_IMPORT), $(addsuffix -gcov, $(file)))
# libmcdr is not linked. Only import the header
LOCAL_IMPORT_C_INCLUDE_DIRS_FROM_SHARED_LIBRARIES := $(MY_LOCAL_GCOV_IMPORT) libmcdr
LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
LOCAL_LDLIBS += $(MY_LD_LIBS)
LOCAL_SHARED_LIBRARIES := $(MY_SHARED_LIBS) $(MY_LOCAL_GCOV_IMPORT)
include $(BUILD_EXECUTABLE)

endif
