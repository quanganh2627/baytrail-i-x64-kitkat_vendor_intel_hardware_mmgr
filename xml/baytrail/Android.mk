LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := mmgr_baytrail.xml
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/telephony
LOCAL_SRC_FILES := $(LOCAL_MODULE)
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := mmgr_baytrail_xml
LOCAL_MODULE_TAGS := optional
LOCAL_REQUIRED_MODULES :=\
    mmgr_baytrail.xml\

include $(BUILD_PHONY_PACKAGE)

