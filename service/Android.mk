LOCAL_PATH:= $(call my-dir)

MY_INCLUDES := \
    $(TARGET_OUT_HEADERS)/IFX-modem \
    $(TARGET_OUT_HEADERS) \
    ../inc \
    $(LOCAL_PATH)/link \
    $(call include-path-for, libusb) \
    $(call include-path-for, libtcs) \

MY_SRC_FILES := $(call all-c-files-under, .)

# Extract commit id
COMMIT_ID := $(shell git --git-dir=$(LOCAL_PATH)/../.git \
        --work-tree=$(LOCAL_PATH) log --oneline -n1 \
        | sed -e 's:\s\{1,\}:\\ :g' -e 's:["&{}]::g' \
        -e "s:'::g")

MY_C_FLAGS := -Wall -Werror -Wvla -DLIBUSBHOST \
    -DGIT_COMMIT_ID=\"$(COMMIT_ID)\" -DMODULE_NAME=\"MMGR\"

MY_SHARED_LIBS := libc libcutils libdl libusbhost liblog libtcs
MY_LDLIBS := -lpthread

#############################################
# MODEM MANAGER daemon
#############################################
include $(CLEAR_VARS)
LOCAL_MODULE := mmgr
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := $(MY_INCLUDES)
LOCAL_SRC_FILES :=  $(MY_SRC_FILES)
LOCAL_CFLAGS += $(MY_C_FLAGS)

LOCAL_SHARED_LIBRARIES := $(MY_SHARED_LIBS)
LOCAL_LDLIBS += $(MY_LDLIBS)
#-------------------------------------------
# module depedency rules
#-------------------------------------------
LOCAL_REQUIRED_MODULES := \
    libmmgrcli \
    com.intel.internal.telephony.MmgrClient.xml \
    com.intel.internal.telephony.MmgrClient \
    mmgr_$(TARGET_BOARD_PLATFORM)_xml \

ifneq (, $(findstring "$(TARGET_BUILD_VARIANT)", "eng" "userdebug"))
LOCAL_REQUIRED_MODULES += \
    libmcdr \
    mmgr-test \
    MMGR_test \
    nvm_client \

endif
include $(BUILD_EXECUTABLE)

#############################################
# MODEM MANAGER daemon - GCOV
#############################################
ifeq ($(mmgr_gcov), true)

include $(CLEAR_VARS)
LOCAL_MODULE := mmgr-gcov
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := $(MY_INCLUDES)
LOCAL_SRC_FILES :=  $(MY_SRC_FILES)
LOCAL_CFLAGS += $(MY_C_FLAGS) -fprofile-arcs -ftest-coverage -DGOCV_MMGR

LOCAL_LDLIBS += $(MY_LDLIBS)
LOCAL_LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
LOCAL_SHARED_LIBRARIES := $(MY_SHARED_LIBS)
include $(BUILD_EXECUTABLE)

endif
