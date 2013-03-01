#############################################
# MMGR interface file copy
#############################################
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_COPY_HEADERS := \
    mmgr_cli.h \
    mmgr_fw_cli.h \
    mmgr.h \
    modem_update.h

LOCAL_COPY_HEADERS := mmgr_cli.h
LOCAL_COPY_HEADERS += mmgr.h
LOCAL_COPY_HEADERS += mmgr_fw_cli.h
LOCAL_COPY_HEADERS += modem_update.h
LOCAL_COPY_HEADERS_TO := IFX-modem
include $(BUILD_COPY_HEADERS)

