//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "kdf.h"
#include "openssl/kdf.h"


#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/types.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"

int32_t scrypt(
    uint8_t *password, size_t password_len,
    uint8_t *salt, size_t salt_len,
    uint64_t n,
    uint32_t r,
    uint32_t p,
    uint8_t *out,
    size_t out_len
) {
    jo_assert(password != NULL);
    jo_assert(salt != NULL);
    jo_assert(out != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "SCRYPT", NULL);
    if (OPS_OPENSSL_ERROR_1  kdf == NULL) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);


    if (OPS_OPENSSL_ERROR_2 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1000);
        goto exit;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password, password_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p),
        OSSL_PARAM_END
    };

    if (OPS_OPENSSL_ERROR_3 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(1001);
        goto exit;
    }

    ret = JO_SUCCESS;

exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);

    return ret;
}


int32_t pbkdf2(
    uint8_t *password, size_t password_len,
    uint8_t *salt, size_t salt_len,
    uint32_t iter,
    uint8_t *digest,
    size_t digest_len,
    uint8_t *out,
    size_t out_len
) {
    jo_assert(password != NULL);
    jo_assert(salt != NULL);
    jo_assert(digest != NULL);
    jo_assert(out != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "PBKDF2", NULL);
    if (OPS_OPENSSL_ERROR_1 kdf == NULL) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);


    if (OPS_OPENSSL_ERROR_2 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(2000);
        goto exit;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password, password_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len),
        OSSL_PARAM_END
    };

    if (OPS_OPENSSL_ERROR_3 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(2001);
        goto exit;
    }

    ret = JO_SUCCESS;
exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}


int32_t kdf_hkdf(
    uint8_t *ikm, size_t ikm_len,
    uint8_t *salt, size_t salt_len,
    uint8_t *info, size_t info_len,
    uint8_t *digest, size_t digest_len,
    uint8_t *out, size_t out_len
) {
    // IKM, digest and out are mandatory and validated by the bridge.
    // salt and info are optional: a NULL salt means "use HashLen zeros"
    // (RFC 5869), a NULL/empty info means "no context info".
    jo_assert(ikm != NULL);
    jo_assert(digest != NULL);
    jo_assert(out != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "HKDF", NULL);
    if (OPS_OPENSSL_ERROR_1 kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3002);
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);

    if (OPS_OPENSSL_ERROR_2 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(3000);
        goto exit;
    }

    // Hard-code the HKDF mode to RFC 5869 extract-and-expand. This is the
    // EVP_KDF "HKDF" default, but set it explicitly so the one-shot semantics
    // the consumers rely on survive a default change or a custom provider.
    // DO NOT change this value.
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

    OSSL_PARAM params[6];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len);
    // Uniform guards: a zero-length salt/info is deliberately treated the same
    // as an absent one. For the salt the two forms are RFC-equivalent anyway —
    // an empty HMAC key is padded to HashLen zeros, which is exactly the
    // RFC 5869 default-salt behaviour the omitted param produces.
    if (salt != NULL && salt_len > 0) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    }
    if (info != NULL && info_len > 0) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_len);
    }
    params[idx++] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_3 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(3001);
        goto exit;
    }

    ret = JO_SUCCESS;
exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

