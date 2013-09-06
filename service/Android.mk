#############################################
# MODEM MANAGER daemon
#############################################
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := mmgr
LOCAL_CFLAGS += -Wall -Wvla -DLIBUSBHOST

# Extract commit id
COMMIT_ID := $(shell git --git-dir=$(LOCAL_PATH)/../.git \
        --work-tree=$(LOCAL_PATH) log --oneline -n1 \
        | sed 's:\s\{1,\}:\\ :g')

LOCAL_CFLAGS += -DGIT_COMMIT_ID=\"$(COMMIT_ID)\"

LOCAL_C_INCLUDES += \
    $(TARGET_OUT_HEADERS)/IFX-modem \
    $(TARGET_OUT_HEADERS) \
    ../inc \
    vendor/intel/external/glib \
    vendor/intel/external/glib/android \
    vendor/intel/external/glib/glib \
    $(call include-path-for, libusb)

LOCAL_SRC_FILES:= \
    at.c \
    client.c \
    client_events.c \
    client_cnx.c \
    config.c \
    core_dump.c \
    data_to_msg.c \
    events_manager.c \
    file.c \
    java_intent.c \
    msg_to_data.c \
    modem_events.c \
    modem_info.c \
    modem_manager.c  \
    modem_specific.c \
    bus_events.c \
    link_pm.c \
    mux.c \
    property.c \
    security.c \
    tty.c \
    timer_events.c \
    reset_escalation.c

LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libglib-2.0 liblog libcutils libdl libusbhost libc
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
    MMGR_test \
    nvm_client
endif
#uncomment this to enable gcov
#LOCAL_CFLAGS += -fprofile-arcs -ftest-coverage -DGOCV_MMGR
#LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
include $(BUILD_EXECUTABLE)

