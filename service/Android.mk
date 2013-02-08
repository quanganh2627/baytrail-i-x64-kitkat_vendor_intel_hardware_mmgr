#############################################
# MODEM MANAGER daemon
#############################################
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := mmgr
LOCAL_CFLAGS += -Wall -Wvla
LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/IFX-modem \
    $(TARGET_OUT_HEADERS) \
    ../inc \
    hardware/intel/glib/ \
    hardware/intel/glib/android

LOCAL_SRC_FILES:= \
    at.c \
    client.c \
    client_events.c \
    config.c \
    core_dump.c \
    crash_logger.c \
    events_manager.c \
    file.c \
    java_intent.c \
    modem_events.c \
    modem_info.c \
    modem_manager.c  \
    modem_specific.c \
    mux.c \
    property.c \
    tty.c \
    timer_events.c \
    reset_escalation.c \
    socket.c
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := libcutils libc
LOCAL_SHARED_LIBRARIES := libglib-2.0 liblog libcutils libdl
LOCAL_LDLIBS += -lpthread
#############################################
# module depedency rules
#############################################
LOCAL_REQUIRED_MODULES := \
    libmmgrcli \
    com.intel.internal.telephony.MmgrClient.xml \
    com.intel.internal.telephony.MmgrClient
ifneq (, $(findstring "$(TARGET_BUILD_VARIANT)", "eng" "userdebug"))
LOCAL_REQUIRED_MODULES += \
    libmcdr \
    mmgr-test \
    MMGR_test
endif
#uncomment this to enable gcov
#LOCAL_CFLAGS += -fprofile-arcs -ftest-coverage -DGOCV_MMGR
#LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
include $(BUILD_EXECUTABLE)

