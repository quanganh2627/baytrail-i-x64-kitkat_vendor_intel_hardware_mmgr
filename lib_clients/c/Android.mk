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
    interface.c \
    utils.c \
    ../../service/client_cnx.c \
    ../../service/data_to_msg.c \
    ../../service/msg_to_data.c
LOCAL_SYSTEM_SHARED_LIBRARIES := libcutils libc
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS += -Wall -Wvla -DDEBUG_MMGR_CLI
#uncomment this to enable gcov
#LOCAL_CFLAGS += -fprofile-arcs -ftest-coverage
#LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libmmgrcli_static
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/../../service \
    $(TARGET_OUT_HEADERS)/IFX-modem
LOCAL_SRC_FILES := \
    interface.c \
    utils.c \
    ../../service/client_cnx.c \
    ../../service/data_to_msg.c \
    ../../service/msg_to_data.c
LOCAL_SYSTEM_SHARED_LIBRARIES := libc
LOCAL_SYSTEM_STATIC_LIBRARIES := libcutils
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS += -Wall -Wvla -DDEBUG_MMGR_CLI
#uncomment this to enable gcov
#LOCAL_CFLAGS += -fprofile-arcs -ftest-coverage
#LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
include $(BUILD_STATIC_LIBRARY)

