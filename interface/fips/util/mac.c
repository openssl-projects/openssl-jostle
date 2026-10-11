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

// Frees a context without counting it: the create failure paths release what
// they built and never reached the ledger.
static void mac_release(mac_ctx *mctx);

/*
 * Largest KMAC output a context is sized for, in bytes. Ours to choose, below OpenSSL's own limit; it sizes caller
 * allocations.
 */
#define MAC_MAX_KMAC_OUTPUT_BYTES (1024 * 1024)

// KMAC-128 and KMAC-256 differ only in what OpenSSL derives from the fetched name.
static int is_kmac(const char *mac_name) {
    return 0 == strncmp(mac_name, "KMAC-128", sizeof("KMAC-128"))
           || 0 == strncmp(mac_name, "KMAC-256", sizeof("KMAC-256"));
}

// GMAC gives one tag per init: finalize and reset spend it, and a re-init may not repeat the key and nonce.
static int is_gmac(const char *mac_name) {
    return 0 == strncmp(mac_name, "GMAC", sizeof("GMAC"));
}

static int32_t init_mac_ctx(mac_ctx *mctx) {
    // Three slots: the arms that set the most are GMAC (cipher + iv) and KMAC
    // (custom + size).
    OSSL_PARAM params[3] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

    if (mctx == NULL || mctx->ctx == NULL) {
        return JO_UNEXPECTED_STATE;
    }

    mctx->initialized = 0;

    // A value no arm reads would be dropped silently, so a MAC that takes none refuses it.
    if (!is_kmac(mctx->mac_name)) {
        if (mctx->custom != NULL) {
            return JO_MAC_TAKES_NO_CUSTOM;
        }
        if (mctx->out_len != 0) {
            return JO_MAC_TAKES_NO_OUTPUT_LEN;
        }
    }

    if (mctx->iv != NULL && 0 != strncmp(mctx->mac_name, "GMAC", sizeof("GMAC"))) {
        return JO_MODE_TAKES_NO_IV;
    }

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
    } else if (OPS_ALTERNATE_3 0 == strncmp(mctx->mac_name, "POLY1305", sizeof("POLY1305"))) {
        // Poly1305: a 32-byte one-time key, no params; function_name is a placeholder.
        if (mctx->key_len != 32) {
            return JO_UNKNOWN_KEY_LEN;
        }
    } else if (OPS_ALTERNATE_4 0 == strncmp(mctx->mac_name, "GMAC", sizeof("GMAC"))) {
        // GMAC: the cipher follows the key length and a nonce is required; OpenSSL decides the nonce length.
        if (mctx->function_name == NULL ||
            0 != strncmp(mctx->function_name, "aes-gcm", sizeof("aes-gcm"))) {
            return JO_UNEXPECTED_STATE; // we control this
        }

        if (mctx->iv == NULL) {
            return JO_IV_IS_NULL;
        }

        switch (mctx->key_len) {
            case 16:
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "aes-128-gcm", 0);
                break;
            case 24:
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "aes-192-gcm", 0);
                break;
            case 32:
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "aes-256-gcm", 0);
                break;
            default:
                return JO_UNKNOWN_KEY_LEN;
        }

        params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV, mctx->iv, mctx->iv_len);
    } else if (OPS_ALTERNATE_5 is_kmac(mctx->mac_name)) {
        // KMAC: function_name is a placeholder. The key and output floors move with the module's config, so
        // OpenSSL decides them; the output ceiling is ours, since it sizes caller allocations.
        int n = 0;

        if (mctx->out_len > MAC_MAX_KMAC_OUTPUT_BYTES) {
            return JO_MAC_OUTPUT_LEN_INVALID;
        }

        if (mctx->custom != NULL) {
            params[n++] = OSSL_PARAM_construct_octet_string(
                    OSSL_MAC_PARAM_CUSTOM, mctx->custom, mctx->custom_len);
        }

        // 0 means unspecified: forwarded, OpenSSL would produce no output.
        if (mctx->out_len != 0) {
            params[n++] = OSSL_PARAM_construct_size_t(
                    OSSL_MAC_PARAM_SIZE, &mctx->out_len);
        }
    } else {
        return JO_UNEXPECTED_STATE;
    }


    ERR_clear_error();
    if (OPS_FAILED_INIT_1 EVP_MAC_init(mctx->ctx, mctx->key, mctx->key_len, params) != 1) {
        return JO_OPENSSL_ERROR OPS_OFFSET_FAILED_INIT_1(1001);
    }

    mctx->initialized = 1;
    return JO_SUCCESS;
}

// Drops the held key, nonce, customisation string and length after a failed init, so nothing outlives it.
static void mac_drop_held(mac_ctx *mctx) {
    OPENSSL_clear_free(mctx->key, mctx->key_len);
    mctx->key = NULL;
    mctx->key_len = 0;
    OPENSSL_free(mctx->iv);
    mctx->iv = NULL;
    mctx->iv_len = 0;
    OPENSSL_free(mctx->custom);
    mctx->custom = NULL;
    mctx->custom_len = 0;
    mctx->out_len = 0;
}

mac_ctx *allocate_mac(const char *mac_name, const char *function, int32_t *err) {
    mac_ctx *mctx = NULL;


    jo_assert(err != NULL);
    jo_assert(mac_name != NULL);
    jo_assert(function != NULL);


    mctx = OPENSSL_zalloc(sizeof(*mctx));
    jo_assert(mctx != NULL);
    mctx->kind = MAC_CTX_KIND;

    size_t len = strlen(mac_name) + 1;
    mctx->mac_name = OPENSSL_malloc(len);
    jo_assert(mctx->mac_name != NULL);
    memcpy(mctx->mac_name, mac_name, len);


    len = strlen(function) + 1;
    mctx->function_name = OPENSSL_malloc(len);
    jo_assert(mctx->function_name != NULL);
    memcpy(mctx->function_name, function, len);


    ERR_clear_error();
    mctx->mac = EVP_MAC_fetch(get_global_jostle_fips_ossl_lib_ctx(), mctx->mac_name, NULL);
    if (OPS_FAILED_CREATE_1 mctx->mac == NULL) {
        *err = JO_NAME_NOT_FOUND;
        goto exit;
    }

    mctx->ctx = EVP_MAC_CTX_new(mctx->mac);
    if (OPS_FAILED_CREATE_2 mctx->ctx == NULL) {
        *err = JO_OPENSSL_ERROR OPS_OFFSET_FAILED_CREATE_2(1000);
        goto exit;
    }

    *err = JO_SUCCESS;
    JO_LEDGER_CREATED(JO_LEDGER_MAC_CTX);
    return mctx;

exit:
    mac_release(mctx);
    return NULL;
}

/*
 * Deep copy, absorbed state included, for Mac.clone(). The copy owns its own EVP_MAC reference, names and held
 * parameters, since mac_free releases each.
 */
mac_ctx *mac_copy(const mac_ctx *src, int32_t *err) {
    jo_assert(err != NULL);
    int32_t check_rc = mac_ctx_check(src);
    if (UNSUCCESSFUL(check_rc)) {
        *err = check_rc;
        return NULL;
    }
    jo_assert(src->ctx != NULL);
    jo_assert(src->mac != NULL);
    jo_assert(src->mac_name != NULL);
    jo_assert(src->function_name != NULL);

    ERR_clear_error();

    mac_ctx *mctx = OPENSSL_zalloc(sizeof(*mctx));
    jo_assert(mctx != NULL);
    mctx->kind = MAC_CTX_KIND;

    size_t len = strlen(src->mac_name) + 1;
    mctx->mac_name = OPENSSL_malloc(len);
    jo_assert(mctx->mac_name != NULL);
    memcpy(mctx->mac_name, src->mac_name, len);

    len = strlen(src->function_name) + 1;
    mctx->function_name = OPENSSL_malloc(len);
    jo_assert(mctx->function_name != NULL);
    memcpy(mctx->function_name, src->function_name, len);

    // up_ref changes only the reference count.
    if (OPS_OPENSSL_ERROR_8 1 != EVP_MAC_up_ref((EVP_MAC *) src->mac)) {
        *err = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(1015);
        goto exit;
    }
    mctx->mac = src->mac;

    mctx->ctx = EVP_MAC_CTX_dup(src->ctx);
    if (OPS_OPENSSL_ERROR_9 mctx->ctx == NULL) {
        *err = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(1016);
        goto exit;
    }

    // The held parameters travel so the clone's mac_reset re-inits as the same MAC.
    if (src->key != NULL) {
        mctx->key = OPENSSL_malloc(src->key_len == 0 ? 1 : src->key_len);
        jo_assert(mctx->key != NULL);
        if (src->key_len > 0) {
            memcpy(mctx->key, src->key, src->key_len);
        }
        mctx->key_len = src->key_len;
    }

    if (src->iv != NULL) {
        mctx->iv = OPENSSL_malloc(src->iv_len == 0 ? 1 : src->iv_len);
        jo_assert(mctx->iv != NULL);
        if (src->iv_len > 0) {
            memcpy(mctx->iv, src->iv, src->iv_len);
        }
        mctx->iv_len = src->iv_len;
    }

    if (src->custom != NULL) {
        mctx->custom = OPENSSL_malloc(src->custom_len == 0 ? 1 : src->custom_len);
        jo_assert(mctx->custom != NULL);
        if (src->custom_len > 0) {
            memcpy(mctx->custom, src->custom, src->custom_len);
        }
        mctx->custom_len = src->custom_len;
    }
    mctx->out_len = src->out_len;
    mctx->initialized = src->initialized;

    *err = JO_SUCCESS;
    JO_LEDGER_CREATED(JO_LEDGER_MAC_CTX);
    return mctx;

exit:
    mac_release(mctx);
    return NULL;
}


int32_t mac_init(mac_ctx *mctx, const uint8_t *key, size_t key_len,
                 const uint8_t *iv, size_t iv_len,
                 const uint8_t *custom, size_t custom_len, size_t out_len) {
    uint8_t *new_key;
    uint8_t *new_iv = NULL;
    uint8_t *new_custom = NULL;
    int32_t ret;


    int32_t check_rc = mac_ctx_check(mctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }
    jo_assert(key != NULL);

    // Same key and nonce as the held ones: refused, and the ctx left as it was. Constant time over the bytes.
    if (is_gmac(mctx->mac_name) && mctx->key != NULL && mctx->iv != NULL && iv != NULL
        && key_len == mctx->key_len && iv_len == mctx->iv_len) {
        int key_diff = CRYPTO_memcmp(key, mctx->key, key_len);
        int iv_diff = CRYPTO_memcmp(iv, mctx->iv, iv_len);
        if ((key_diff | iv_diff) == 0) {
            return JO_MAC_NONCE_REUSED;
        }
    }

    // Non-NULL even for an empty key: EVP_MAC_init reads NULL as "reuse the previous key".
    new_key = OPENSSL_malloc(key_len == 0 ? 1 : key_len);
    jo_assert(new_key != NULL);

    if (key_len > 0) {
        memcpy(new_key, key, key_len);
    }

    if (iv != NULL) {
        new_iv = OPENSSL_malloc(iv_len == 0 ? 1 : iv_len);
        jo_assert(new_iv != NULL);
        if (iv_len > 0) {
            memcpy(new_iv, iv, iv_len);
        }
    }

    if (custom != NULL) {
        new_custom = OPENSSL_malloc(custom_len == 0 ? 1 : custom_len);
        jo_assert(new_custom != NULL);
        if (custom_len > 0) {
            memcpy(new_custom, custom, custom_len);
        }
    }

    if (mctx->key != NULL) {
        OPENSSL_clear_free(mctx->key, mctx->key_len);
    }
    if (mctx->iv != NULL) {
        OPENSSL_free(mctx->iv);
    }
    if (mctx->custom != NULL) {
        OPENSSL_free(mctx->custom);
    }

    mctx->key = new_key;
    mctx->key_len = key_len;
    mctx->iv = new_iv;
    mctx->iv_len = iv != NULL ? iv_len : 0;
    mctx->custom = new_custom;
    mctx->custom_len = custom != NULL ? custom_len : 0;
    mctx->out_len = out_len;

    ret = init_mac_ctx(mctx);
    if (ret < 0) {
        mac_drop_held(mctx);
        return ret;
    }

    return JO_SUCCESS;
}

int32_t mac_update(mac_ctx *mctx, const uint8_t *in, int32_t off, int32_t len) {
    int32_t check_rc = mac_ctx_check(mctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }
    jo_assert(off >= 0);
    jo_assert(len >= 0);

    if (len == 0) {
        return JO_SUCCESS;
    }

    jo_assert(in != NULL);
    jo_assert(mctx->initialized != 0);

    ERR_clear_error();
    if (OPS_OPENSSL_ERROR_1 EVP_MAC_update(mctx->ctx, in + off, (size_t) len) != 1) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1002);
    }

    return JO_SUCCESS;
}

int32_t mac_final(mac_ctx *mctx, uint8_t *out, int32_t off, int32_t out_len) {
    size_t written = 0;

    int32_t check_rc = mac_ctx_check(mctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }
    jo_assert(out != NULL);
    jo_assert(off >= 0);
    jo_assert(out_len >= 0);
    jo_assert(off <= out_len);
    jo_assert(mctx->initialized != 0);


    int32_t ret = JO_SUCCESS;
    ERR_clear_error();
    if (OPS_OPENSSL_ERROR_2 EVP_MAC_final(
            mctx->ctx,
            out + off,
            &written, (size_t) (out_len - off)) != 1) {
        ret = JO_OPENSSL_ERROR;
    }
    if (is_gmac(mctx->mac_name)) {
        mctx->initialized = 0;
    }
    if (UNSUCCESSFUL(ret)) {
        return ret;
    }

    if (written > (size_t) INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t mac_len(mac_ctx *mctx) {
    int32_t check_rc = mac_ctx_check(mctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }
    jo_assert(mctx->initialized != 0);

    ERR_clear_error();
    size_t ret = EVP_MAC_CTX_get_mac_size(mctx->ctx);
    if (OPS_OPENSSL_ERROR_12 ret == 0) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_12(1003);
    }

    if (OPS_INT32_OVERFLOW_1 ret > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) ret;
}

int32_t mac_len_for(mac_ctx *mctx) {
    int32_t check_rc = mac_ctx_check(mctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }
    jo_assert(mctx->mac_name != NULL);
    jo_assert(mctx->function_name != NULL);

    OSSL_LIB_CTX *libctx = get_global_jostle_fips_ossl_lib_ctx();
    EVP_MD *md = NULL;
    EVP_CIPHER *cipher = NULL;
    // Function scope so the cleanup label frees it on every path.
    EVP_MAC_CTX *fresh = NULL;
    int32_t ret;

    ERR_clear_error();

    // HMAC: the digest's output size.
    if (0 == strncmp(mctx->mac_name, "HMAC", sizeof("HMAC"))) {
        md = EVP_MD_fetch(libctx, mctx->function_name, NULL);
        if (OPS_OPENSSL_ERROR_3 md == NULL) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(1010);
            goto exit;
        }
        int size = EVP_MD_get_size(md);
        if (OPS_OPENSSL_ERROR_5 size <= 0) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(1012);
            goto exit;
        }
        ret = (int32_t) size;
        goto exit;
    }

    // CMAC: the cipher's block size, the same for every AES key length.
    if (0 == strncmp(mctx->mac_name, "CMAC", sizeof("CMAC"))) {
        if (0 != strncmp(mctx->function_name, "aes-cbc", sizeof("aes-cbc"))) {
            ret = JO_UNEXPECTED_STATE;
            goto exit;
        }
        cipher = EVP_CIPHER_fetch(libctx, "aes-128-cbc", NULL);
        if (OPS_OPENSSL_ERROR_4 cipher == NULL) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(1011);
            goto exit;
        }
        int block = EVP_CIPHER_get_block_size(cipher);
        if (OPS_OPENSSL_ERROR_6 block <= 0) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(1013);
            goto exit;
        }
        ret = (int32_t) block;
        goto exit;
    }

    // Poly1305 and GMAC: the unkeyed ctx reports the fixed tag length.
    if (0 == strncmp(mctx->mac_name, "POLY1305", sizeof("POLY1305")) ||
        0 == strncmp(mctx->mac_name, "GMAC", sizeof("GMAC"))) {
        size_t size = EVP_MAC_CTX_get_mac_size(mctx->ctx);
        if (OPS_OPENSSL_ERROR_7 size == 0) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(1014);
            goto exit;
        }
        if (size > (size_t) INT32_MAX) {
            ret = JO_OUTPUT_SIZE_INT_OVERFLOW;
            goto exit;
        }
        ret = (int32_t) size;
        goto exit;
    }

    // KMAC: the default length, asked of a fresh ctx; mctx->ctx follows a requested length, and Java caches this
    // per algorithm.
    if (is_kmac(mctx->mac_name)) {
        size_t size;

        fresh = EVP_MAC_CTX_new(mctx->mac);
        if (OPS_OPENSSL_ERROR_10 fresh == NULL) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(1017);
            goto exit;
        }
        size = EVP_MAC_CTX_get_mac_size(fresh);
        if (OPS_OPENSSL_ERROR_11 size == 0) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_11(1018);
            goto exit;
        }
        if (size > (size_t) INT32_MAX) {
            ret = JO_OUTPUT_SIZE_INT_OVERFLOW;
            goto exit;
        }
        ret = (int32_t) size;
        goto exit;
    }

    ret = JO_UNEXPECTED_STATE;

exit:
    EVP_MD_free(md);
    EVP_CIPHER_free(cipher);
    EVP_MAC_CTX_free(fresh);
    return ret;
}

int32_t mac_ctx_check(const mac_ctx *ctx) {
    if (ctx == NULL) {
        return JO_MAC_CTX_IS_NULL;
    }
    if (ctx->kind != MAC_CTX_KIND) {
        return JO_MAC_CTX_WRONG_KIND;
    }
    return JO_SUCCESS;
}

int32_t mac_reset(mac_ctx *mctx) {
    int32_t check_rc = mac_ctx_check(mctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    // A GMAC ctx is spent, not restored; it needs only a held key.
    if (is_gmac(mctx->mac_name)) {
        if (mctx->key == NULL) {
            return JO_NOT_INITIALIZED;
        }
        mctx->initialized = 0;
        return JO_SUCCESS;
    }

    if (mctx->initialized == 0) {
        return JO_NOT_INITIALIZED;
    }

    int32_t ret = init_mac_ctx(mctx);
    if (ret < 0) {
        mac_drop_held(mctx);
    }
    return ret;
}

static void mac_release(mac_ctx *mctx) {
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
    // Neither the nonce nor the customisation string is secret.
    if (mctx->iv != NULL) {
        OPENSSL_free(mctx->iv);
    }
    if (mctx->custom != NULL) {
        OPENSSL_free(mctx->custom);
    }
    mctx->kind = MAC_CTX_NONE;
    OPENSSL_clear_free(mctx, sizeof(*mctx));
}

void mac_free(mac_ctx *mctx) {
    // Frees nothing on a wrong kind: freeing another object as a mac_ctx corrupts it.
    if (mac_ctx_check(mctx) != JO_SUCCESS) {
        return;
    }
    JO_LEDGER_DESTROYED(JO_LEDGER_MAC_CTX);
    mac_release(mctx);
}
