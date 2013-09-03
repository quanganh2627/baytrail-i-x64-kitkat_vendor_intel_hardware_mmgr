LOCAL_PATH:= $(call my-dir)

MY_INCLUDES := \
    $(LOCAL_PATH)/../../service \
    $(LOCAL_PATH)/../../service/link \
    $(TARGET_OUT_HEADERS)/IFX-modem \
    $(TARGET_OUT_HEADERS) \
    ../inc \
    $(call include-path-for, libtcs) \

MY_SRC_FILES := \
    $(call all-c-files-under, .) \
    ../../service/at.c \
    ../../service/file.c \
    ../../service/property.c \
    ../../service/tty.c

MY_C_FLAGS := -Wall -Werror -Wvla -DSTDIO_LOGS
MY_SHARED_LIBS := libcutils libc libmmgrcli libtcs
MY_LD_LIBS := -lpthread

#############################################
# MODEM MANAGER C appliation test
#############################################
include $(CLEAR_VARS)
LOCAL_MODULE := mmgr-test
LOCAL_MODULE_TAGS := optional tests

LOCAL_C_INCLUDES := $(MY_INCLUDES)
LOCAL_SRC_FILES := $(MY_SRC_FILES)
LOCAL_CFLAGS += $(MY_C_FLAGS)
LOCAL_LDLIBS += $(MY_LD_LIBS)

LOCAL_SHARED_LIBRARIES := $(MY_SHARED_LIBS)
include $(BUILD_EXECUTABLE)

#############################################
# MODEM MANAGER C appliation test - GCOV
#############################################
ifeq ($(mmgr_gcov), true)

include $(CLEAR_VARS)
LOCAL_MODULE := mmgr-test-gcov
LOCAL_MODULE_TAGS := optional tests

LOCAL_C_INCLUDES := $(MY_INCLUDES)
LOCAL_SRC_FILES := $(MY_SRC_FILES)
LOCAL_CFLAGS += $(MY_C_FLAGS) -fprofile-arcs -ftest-coverage
LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
LOCAL_LDLIBS += $(MY_LD_LIBS)

LOCAL_SHARED_LIBRARIES := $(MY_SHARED_LIBS)
include $(BUILD_EXECUTABLE)

endif
