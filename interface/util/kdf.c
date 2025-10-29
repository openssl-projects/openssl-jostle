//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "kdf.h"
#include "openssl/kdf.h"

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/types.h>

#include "bc_err_codes.h"

int32_t scrypt(
    uint8_t *password, size_t password_len,
    uint8_t *salt, size_t salt_len,
    uint64_t n,
    uint32_t r,
    uint32_t p,
    uint8_t *out,
    size_t out_len
) {
    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    OSSL_PARAM params[6] = {0};

    kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
    if (kdf == NULL) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (!kctx) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                  password, password_len);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    params[2] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n);
    params[3] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r);
    params[4] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p);
    params[5] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR;
    }

exit:
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
    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    OSSL_PARAM params[6] = {0};

    kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (kdf == NULL) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (!kctx) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }


    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                  password, password_len);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    params[2] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    params[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

exit:
    EVP_KDF_CTX_free(kctx);
    return ret;
}

int32_t pkcs12(
    uint8_t *password, size_t password_len,
    uint8_t *salt, size_t salt_len,
    uint32_t iter,
    uint8_t *digest,
    size_t digest_len,
    uint8_t *out,
    size_t out_len
) {
    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    OSSL_PARAM params[6] = {0};

    kdf = EVP_KDF_fetch(NULL, "PKCS12KDF", NULL);
    if (kdf == NULL) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (!kctx) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }


    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                  password, password_len);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    params[2] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    params[3] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

exit:
    EVP_KDF_CTX_free(kctx);
    return ret;
}
