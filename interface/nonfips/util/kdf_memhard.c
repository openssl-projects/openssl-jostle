//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// Memory-hard password KDFs: scrypt (RFC 7914) and Argon2 (RFC 9106).
//
// Nonfips tree only: the FIPS provider serves neither, so the FIPS interface library carries no bridge and exports
// no symbol for them, and the tree-parity audit sanctions the missing fips twin. kdf.c holds the five one-shot KDFs
// both providers serve (PBKDF2, HKDF, KBKDF, SSKDF, SSHKDF).
//

#include "kdf_memhard.h"
#include "openssl/kdf.h"


#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/types.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"

int32_t jo_scrypt(
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
    uint64_t maxmem = JO_SCRYPT_MAX_MEMORY_BYTES;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "SCRYPT", NULL);
    if (OPS_OPENSSL_ERROR_1  kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1002);
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
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem),
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

/*
 * Argon2 (RFC 9106). The KDF name follows the caller's type, which the bridge restricts to {0,1,2}. The version is
 * set from the caller so the output depends on stated inputs alone. Threads are pinned to 1: the output depends on
 * lanes, not threads, and no process-wide max-threads setting is touched.
 */
int32_t jo_argon2(
    int32_t type,
    uint32_t version,
    uint8_t *password, size_t password_len,
    uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint32_t memory_kib,
    uint32_t lanes,
    uint8_t *out,
    size_t out_len
) {
    jo_assert(password != NULL);
    jo_assert(salt != NULL);
    jo_assert(out != NULL);
    jo_assert(type >= 0 && type <= 2);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    const char *kdf_name;
    uint32_t threads = 1;

    switch (type) {
        case 0:
            kdf_name = "ARGON2D";
            break;
        case 1:
            kdf_name = "ARGON2I";
            break;
        default:
            kdf_name = "ARGON2ID";
            break;
    }

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), kdf_name, NULL);
    if (OPS_OPENSSL_ERROR_1 kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(4002);
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);

    if (OPS_OPENSSL_ERROR_2 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(4000);
        goto exit;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password, password_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory_kib),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_END
    };

    if (OPS_OPENSSL_ERROR_3 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(4001);
        goto exit;
    }

    ret = JO_SUCCESS;

exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);

    return ret;
}
