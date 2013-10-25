LOCAL_PATH:= $(call my-dir)

MY_INCLUDES := \
    $(LOCAL_PATH)/../../service \
    $(TARGET_OUT_HEADERS)/IFX-modem

MY_SRC_FILES := \
    $(call all-c-files-under, .) \
    ../../service/client_cnx.c \
    ../../service/data_to_msg.c \
    ../../service/msg_to_data.c \
    ../../service/tty.c

MY_C_FLAGS := -Wall -Werror -Wvla -DMODULE_NAME=\"MMGR_CLI\"
MY_SHARED_LIBS := libcutils libc

#############################################
# MODEM MANAGER C client library
#############################################
include $(CLEAR_VARS)
LOCAL_MODULE := libmmgrcli
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := $(MY_INCLUDES)
LOCAL_SRC_FILES := $(MY_SRC_FILES)
LOCAL_CFLAGS += $(MY_C_FLAGS)

LOCAL_SYSTEM_SHARED_LIBRARIES := $(MY_SHARED_LIBS)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/../../inc
include $(BUILD_SHARED_LIBRARY)

#############################################
# MODEM MANAGER C client library - GCOV
#############################################
ifeq ($(mmgr_gcov), true)

include $(CLEAR_VARS)
LOCAL_MODULE := libmmgrcli-gcov
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := $(MY_INCLUDES)
LOCAL_SRC_FILES := $(MY_SRC_FILES)
LOCAL_CFLAGS += $(MY_C_FLAGS) -fprofile-arcs -ftest-coverage
LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov

LOCAL_SYSTEM_SHARED_LIBRARIES := $(MY_SHARED_LIBS)
include $(BUILD_SHARED_LIBRARY)

endif
