
#ifndef __MMGR_MUP_HEADER__
#define __MMGR_MUP_HEADER__

#include <stddef.h>
#include "mmgr.h"

typedef enum e_mup_err {
    E_MUP_BAD_PARAMETER,
    E_MUP_FAILED,
    E_MUP_SUCCEED
} e_mup_err_t;

#ifdef __cplusplus
extern "C" {
#endif

    typedef void (*mup_ap_log_callback_t) (const char *msg, size_t msg_len);

    typedef struct mup_interface {
        void *context;
        int last_error;
        mup_ap_log_callback_t ap_log_callback;
    } mup_interface_t;

    typedef struct mup_fw_update_params {
        mup_interface_t *handle;
        char *fw_file_path;
        size_t fw_file_path_len;
        int erase_all;
    } mup_fw_update_params_t;

    typedef struct mup_rndcert_read_params {
        mup_interface_t *handle;
        char *dest_file_name;
        size_t dest_file_name_len;
    } mup_rndcert_read_params_t;

    typedef struct mup_rndcert_erase_params {
        mup_interface_t *handle;
    } mup_rndcert_erase_params_t;

    typedef struct mup_rndcert_update_params {
        mup_interface_t *handle;
        char *src_file_path;
        size_t src_file_path_len;
    } mup_rndcert_update_params_t;

    typedef struct mup_fuse_get_params {
        mup_interface_t *handle;
        char *dest_buffer;
        size_t dest_buffer_size;
    } mup_fuse_get_params_t;

    typedef struct mup_hw_id_get_params {
        mup_interface_t *handle;
        char *dest_buffer;
        size_t dest_buffer_size;
    } mup_hw_id_get_params_t;

    typedef struct mup_nvm_update_params {
        mup_interface_t *handle;
        char *nvm_file_path;
        size_t nvm_file_path_len;
    } mup_nvm_update_params_t;

    typedef struct mup_nvm_read_id_params {
        mup_interface_t *handle;
        char *dest_buffer;
        size_t dest_buffer_size;
    } mup_nvm_read_id_params_t;

    int mup_get_last_error(mup_interface_t *handle);
    void mup_chk_invoke_log_cb(mup_interface_t *handle, const char *msg,
                               size_t msg_len);

    e_mup_err_t mup_initialize(mup_interface_t **handle,
                               mup_ap_log_callback_t ap_log_callback);
    e_mup_err_t mup_update_fw(mup_fw_update_params_t *params);
    e_mup_err_t mup_update_rnd(mup_rndcert_update_params_t *params);
    e_mup_err_t mup_read_rnd(mup_rndcert_read_params_t *params);
    e_mup_err_t mup_erase_rnd(mup_rndcert_erase_params_t *params);
    e_mup_err_t mup_get_fuse(mup_fuse_get_params_t *params);
    e_mup_err_t mup_get_hw_id(mup_hw_id_get_params_t *params);
    e_mup_err_t mup_update_nvm(mup_nvm_update_params_t *params);
    e_mup_err_t mup_get_nvm_id(mup_nvm_read_id_params_t *params);
    e_mup_err_t mup_dispose(mup_interface_t *handle);

#ifdef __cplusplus
}
#endif
#endif                          /* __MMGR_MUP_HEADER__ */