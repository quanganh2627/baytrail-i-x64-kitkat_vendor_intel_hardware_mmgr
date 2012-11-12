#############################################
# MODEM MANGER C client library
#############################################
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libmmgrcli
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/../../service \
    $(TARGET_OUT_HEADERS)/IFX-modem
LOCAL_SRC_FILES := \
    mmgr_cli.c
LOCAL_SYSTEM_SHARED_LIBRARIES := libcutils libc
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS += -Wall -Wvla -DDEBUG_MMGR_CLI
#uncomment this to enable gcov
#LOCAL_CFLAGS += -fprofile-arcs -ftest-coverage
#LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
include $(BUILD_SHARED_LIBRARY)

