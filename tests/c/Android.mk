#############################################
# MODEM MANAGER C appliation test
#############################################
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := mmgr-test
LOCAL_CFLAGS += -Wall -DSTDIO_LOGS -Wvla
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/../../service \
    $(TARGET_OUT_HEADERS)/IFX-modem \
    $(TARGET_OUT_HEADERS) \
    vendor/intel/external/glib/ \
    vendor/intel/external/glib/android/ \
    vendor/intel/external/glib/glib/ \
    ../inc

LOCAL_SRC_FILES:= \
    ../../service/at.c \
    ../../service/config.c \
    ../../service/file.c \
    ../../service/property.c \
    ../../service/tty.c \
    mmgr_test.c \
    test_cases.c \
    test_utils.c
LOCAL_MODULE_TAGS := optional tests
LOCAL_SHARED_LIBRARIES := libcutils libc libglib-2.0 libmmgrcli
LOCAL_LDLIBS += -lpthread
#uncomment this to enable gcov
#LOCAL_CFLAGS += -fprofile-arcs -ftest-coverage
#LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
include $(BUILD_EXECUTABLE)

