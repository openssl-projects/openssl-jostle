//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "mac.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include <string.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"


static int32_t init_mac_ctx(mac_ctx *mctx) {
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    if (mctx == NULL || mctx->ctx == NULL) {
        return JO_UNEXPECTED_STATE;
    }

    mctx->initialized = 0;

    if (OPS_ALTERNATE_1 0 == strncmp(mctx->mac_name, "CMAC", sizeof("CMAC"))) {
        // CMAC

        if (mctx->function_name == NULL ||
            0 != strncmp(mctx->function_name, "aes-cbc", sizeof("aes-cbc"))) {
            return JO_UNEXPECTED_STATE; // we control this
        }

        switch (mctx->key_len) {
            case 16:
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "aes-128-cbc", 0);
                break;
            case 24:
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "aes-192-cbc", 0);
                break;
            case 32:
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "aes-256-cbc", 0);
                break;
            default:
                return JO_UNKNOWN_KEY_LEN;
        }
    } else if (OPS_ALTERNATE_2 0 == strncmp(mctx->mac_name, "HMAC", sizeof("HMAC"))) {
        // HMAC
        if (mctx->function_name == NULL) {
            return JO_UNEXPECTED_STATE; // we control this
        }
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, mctx->function_name, 0);
    } else {
        return JO_UNEXPECTED_STATE;
    }


    ERR_clear_error();
    if (OPS_OPENSSL_ERROR_2 EVP_MAC_init(mctx->ctx, mctx->key, mctx->key_len, params) != 1) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1000);
    }

    mctx->initialized = 1;
    return JO_SUCCESS;
}

mac_ctx *allocate_mac(const char *mac_name, const char *function, int32_t *err) {
    mac_ctx *mctx = NULL;


    jo_assert(err != NULL);
    jo_assert(mac_name != NULL);
    jo_assert(function != NULL);


    mctx = OPENSSL_zalloc(sizeof(*mctx));
    jo_assert(mctx != NULL);

    size_t len = strlen(mac_name) + 1;
    mctx->mac_name = OPENSSL_malloc(len);
    jo_assert(mctx->mac_name != NULL);
    memcpy(mctx->mac_name, mac_name, len);


    len = strlen(function) + 1;
    mctx->function_name = OPENSSL_malloc(len);
    jo_assert(mctx->function_name != NULL);
    memcpy(mctx->function_name, function, len);


    ERR_clear_error();
    mctx->mac = EVP_MAC_fetch(get_global_jostle_ossl_lib_ctx(), mctx->mac_name, NULL);
    if (OPS_OPENSSL_ERROR_1 mctx->mac == NULL) {
        *err = JO_OPENSSL_ERROR;
        goto exit;
    }

    mctx->ctx = EVP_MAC_CTX_new(mctx->mac);
    if (OPS_OPENSSL_ERROR_2 mctx->ctx == NULL) {
        *err = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1000);
        goto exit;
    }

    *err = JO_SUCCESS;
    return mctx;

exit:

    if (mctx->ctx != NULL) {
        EVP_MAC_CTX_free(mctx->ctx);
    }
    if (mctx->mac != NULL) {
        EVP_MAC_free(mctx->mac);
    }
    if (mctx->function_name != NULL) {
        OPENSSL_free(mctx->function_name);
    }
    if (mctx->mac_name != NULL) {
        OPENSSL_free(mctx->mac_name);
    }
    OPENSSL_free(mctx);


    return NULL;
}

int32_t mac_init(mac_ctx *mctx, const uint8_t *key, size_t key_len) {
    uint8_t *new_key;
    int32_t ret;


    jo_assert(mctx != NULL);
    jo_assert(key != NULL);

    // non-NULL even for empty key: EVP_MAC_init treats NULL as "reuse previous"
    new_key = OPENSSL_malloc(key_len == 0 ? 1 : key_len);
    jo_assert(new_key != NULL);

    if (key_len > 0) {
        memcpy(new_key, key, key_len);
    }

    if (mctx->key != NULL) {
        OPENSSL_clear_free(mctx->key, mctx->key_len);
    }

    mctx->key = new_key;
    mctx->key_len = key_len;

    ret = init_mac_ctx(mctx);
    if (ret < 0) {
        OPENSSL_clear_free(mctx->key, mctx->key_len);
        mctx->key = NULL;
        mctx->key_len = 0;
        return ret;
    }

    return JO_SUCCESS;
}

int32_t mac_update(mac_ctx *mctx, const uint8_t *in, int32_t off, int32_t len) {
    jo_assert(mctx != NULL);
    jo_assert(off >= 0);
    jo_assert(len >= 0);

    if (len == 0) {
        return JO_SUCCESS;
    }

    jo_assert(in != NULL);
    jo_assert(mctx->initialized != 0);

    ERR_clear_error();
    if (OPS_OPENSSL_ERROR_1 EVP_MAC_update(mctx->ctx, in + off, (size_t) len) != 1) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1000);
    }

    return JO_SUCCESS;
}

int32_t mac_final(mac_ctx *mctx, uint8_t *out, int32_t off, int32_t out_len) {
    size_t written = 0;

    jo_assert(mctx != NULL);
    jo_assert(out != NULL);
    jo_assert(off >= 0);
    jo_assert(out_len >= 0);
    jo_assert(off <= out_len);
    jo_assert(mctx->initialized != 0);


    ERR_clear_error();
    if (OPS_OPENSSL_ERROR_2 EVP_MAC_final(
            mctx->ctx,
            out + off,
            &written, (size_t) (out_len - off)) != 1) {
        return JO_OPENSSL_ERROR;
    }

    if (written > (size_t) INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t mac_len(mac_ctx *mctx) {
    jo_assert(mctx != NULL);
    jo_assert(mctx->initialized != 0);

    ERR_clear_error();
    size_t ret = EVP_MAC_CTX_get_mac_size(mctx->ctx);
    if (OPS_OPENSSL_ERROR_1 ret == 0) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1000);
    }

    if (OPS_INT32_OVERFLOW_1 ret > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) ret;
}

int32_t mac_reset(mac_ctx *mctx) {
   jo_assert(mctx != NULL);

    if (mctx->key == NULL) {
        return JO_NOT_INITIALIZED;
    }

    return init_mac_ctx(mctx);
}

void mac_free(mac_ctx *mctx) {
    if (mctx == NULL) {
        return;
    }

    if (mctx->ctx != NULL) {
        EVP_MAC_CTX_free(mctx->ctx);
    }
    if (mctx->mac != NULL) {
        EVP_MAC_free(mctx->mac);
    }
    if (mctx->function_name != NULL) {
        OPENSSL_free(mctx->function_name);
    }
    if (mctx->mac_name != NULL) {
        OPENSSL_free(mctx->mac_name);
    }
    if (mctx->key != NULL) {
        OPENSSL_clear_free(mctx->key, mctx->key_len);
    }
    OPENSSL_free(mctx);
}
