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

/*
 * Non-NULL stub passed to OSSL_PARAM_construct_octet_string for
 * optional parameters (HKDF salt / info, X9.63 KDF shared-info)
 * when the caller didn't supply one. OpenSSL accepts a zero-length
 * value and treats the parameter as absent, but the pointer argument
 * to the param-construction macro must be non-NULL. Declared
 * non-const because OSSL_PARAM_construct_octet_string takes
 * {@code void *} (OpenSSL only reads from it in this read-side
 * usage; never holds anything sensitive).
 */
static uint8_t kdf_empty_stub[1] = {0};

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


/**
 * HKDF (RFC 5869) — extract-then-expand mode (the standard HKDF flow).
 * Maps onto OpenSSL's "HKDF" {@code EVP_KDF} in its default
 * EXTRACT_AND_EXPAND mode.
 *
 * <p>IKM (input keying material) is mandatory and non-empty; salt and
 * info may legitimately be NULL/zero-length (RFC 5869 §2.2 allows the
 * caller to omit either). The bridge layer null-checks the byte
 * arrays, leaves zero-length values intact, and asserts IKM is
 * non-NULL here.
 */
int32_t hkdf(
    uint8_t *ikm, size_t ikm_len,
    uint8_t *salt, size_t salt_len,
    uint8_t *info, size_t info_len,
    uint8_t *digest, size_t digest_len,
    uint8_t *out, size_t out_len
) {
    jo_assert(ikm != NULL);
    // salt and info may be NULL (RFC 5869 allows zero-length values
    // and we represent those as NULL + len 0 across the bridge).
    jo_assert(digest != NULL);
    jo_assert(out != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "HKDF", NULL);
    if (OPS_OPENSSL_ERROR_4 kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(3000);
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (OPS_OPENSSL_ERROR_5 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(3001);
        goto exit;
    }

    // Empty salt / info: OSSL_PARAM_construct_octet_string with len==0
    // is accepted by OpenSSL's HKDF and treated as "absent" per RFC.
    // Pass the file-static kdf_empty_stub for zero-length params so
    // the buffer pointer is always non-NULL (macro requirement).
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
            (salt == NULL || salt_len == 0) ? kdf_empty_stub : salt,
            salt_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
            (info == NULL || info_len == 0) ? kdf_empty_stub : info,
            info_len),
        OSSL_PARAM_END
    };

    if (OPS_OPENSSL_ERROR_6 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(3002);
        goto exit;
    }

    ret = JO_SUCCESS;
exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}


/**
 * ANSI X9.63 KDF (and the SP 800-56A "concatenation KDF" alias the X9.63
 * KDF is widely substituted for). Maps onto OpenSSL's "X963KDF"
 * {@code EVP_KDF}. Inputs are the secret (Z, typically the raw ECDH
 * shared secret), an optional shared-info (UKM in JCE terms), and a
 * digest name driving the iterated hash.
 *
 * <p>Shared-info / UKM is optional per X9.63 §3.6 — pass NULL/0 for
 * "absent". The bridge layer handles the NULL → empty-octet-string
 * translation.
 *
 * <p>OPS offsets 4000/4001/4002 (flags OPS_OPENSSL_ERROR_7..._9).
 * The 4000 numeric block is also used by xec.c with disjoint flags
 * (OPS_OPENSSL_ERROR_1..._4); see xec.c header for rationale.
 */
int32_t x963kdf(
    uint8_t *z, size_t z_len,
    uint8_t *shared_info, size_t shared_info_len,
    uint8_t *digest, size_t digest_len,
    uint8_t *out, size_t out_len
) {
    jo_assert(z != NULL);
    jo_assert(digest != NULL);
    jo_assert(out != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "X963KDF", NULL);
    if (OPS_OPENSSL_ERROR_7 kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(4000);
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (OPS_OPENSSL_ERROR_8 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(4001);
        goto exit;
    }

    // See HKDF above for the kdf_empty_stub rationale.
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, z, z_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
            (shared_info == NULL || shared_info_len == 0) ? kdf_empty_stub : shared_info,
            shared_info_len),
        OSSL_PARAM_END
    };

    if (OPS_OPENSSL_ERROR_9 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(4002);
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

