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
        ret = JO_OPENSSL_ERROR OPS_OFFSET(1000);
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
        ret = JO_OPENSSL_ERROR OPS_OFFSET(1001);
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
        ret = JO_OPENSSL_ERROR OPS_OFFSET(2000);
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
        ret = JO_OPENSSL_ERROR OPS_OFFSET(2001);
        goto exit;
    }

    ret = JO_SUCCESS;
exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

