#############################################
# MMGR interface file copy
#############################################
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_COPY_HEADERS := mmgr_cli.h
LOCAL_COPY_HEADERS += mmgr.h
LOCAL_COPY_HEADERS_TO := IFX-modem
include $(BUILD_COPY_HEADERS)

