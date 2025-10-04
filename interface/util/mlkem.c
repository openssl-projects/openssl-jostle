//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "mlkem.h"

#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "bc_err_codes.h"
#include "key_spec.h"
#include "ops.h"


int32_t mlkem_generate_key_pair(key_spec *spec, int32_t type, uint8_t *seed, size_t seed_len) {
    assert(spec != NULL);
    // spec->type = type;

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;


    OSSL_PARAM params[] = {
        OSSL_PARAM_END,
        OSSL_PARAM_END
    };

    if (seed != NULL) {
        if (seed_len != MLKEM_SEED_LEN) {
            // slh_n not negative by this point
            ret_code = JO_INVALID_SEED_LEN;
            goto exit;
        }
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed, seed_len);
    }

    switch (type) {
        case KS_ML_KEM_512:
            ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-512",NULL);
            break;
        case KS_ML_KEM_768:
            ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768",NULL);
            break;
        case KS_ML_KEM_1024:
            ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024",NULL);
            break;
        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
    }


    if (ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (!EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (!EVP_PKEY_CTX_set_params(ctx, params)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (!EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }


#ifdef JOSTLE_OPS
    if (OPS_OPENSSL_ERROR_1 0) {
        EVP_PKEY_free(spec->key);
        spec->key = NULL;
    }
#endif


    if (spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;


exit:
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}

int32_t mlkem_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }


    size_t min_len;

    // Get minimum len
    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
                                                                 &min_len)) {
        return JO_OPENSSL_ERROR;
    }

    // Return the length
    if (out == NULL) {
        return (int32_t) min_len;
    }


    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out, min_len,
                                                                 &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET(1000);
    }

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t mlkem_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    size_t min_len;

    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0,
                                                                 &min_len)) {
        return JO_OPENSSL_ERROR;
    }


    if (out == NULL) {
        return (int32_t) min_len;
    }

    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;


    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, out, min_len,
                                                                 &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET(1000);
    }

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t mlkem_get_private_seed(key_spec *key_spec, uint8_t *out, size_t out_len) {
    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    const size_t min_len = MLKEM_SEED_LEN;

    if (out == NULL) {
        return (int32_t) min_len;
    }


    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;

    if (OPS_OPENSSL_ERROR_1
        1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ML_KEM_SEED, out, min_len, &written)) {
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t mlkem_decode_private_key(key_spec *key_spec, int32_t typeId,  uint8_t *src, size_t src_len) {
    int32_t ret_code = JO_FAIL;
    const char *type;

    assert(key_spec != NULL);

    size_t min_len;


    switch (typeId) {
        case KS_ML_KEM_512:
            min_len = 1632;
            type = "ML-KEM-512";
            break;
        case KS_ML_KEM_768:
            min_len = 2400;
            type = "ML-KEM-768";
            break;
        case KS_ML_KEM_1024:
            type = "ML-KEM-1024";
            min_len = 3168;
            break;
        default:
            return JO_INVALID_KEY_TYPE;
    }


    if (src_len < min_len) {
        ret_code = JO_ENCODED_PRIVATE_KEY_LEN;
        goto exit;
    }


    key_spec->key = EVP_PKEY_new_raw_private_key_ex(NULL, type,NULL, src, src_len);

#ifdef JOSTLE_OPS
    if (OPS_OPENSSL_ERROR_1 0) {
        EVP_PKEY_free(key_spec->key);
        key_spec->key = NULL;
        // trigger the openssl error pathway below
    }
#endif

    if (key_spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    return ret_code;
}

int32_t mlkem_decode_public_key(key_spec *key_spec, int32_t typeId,  uint8_t *src, size_t src_len) {
    int32_t ret_code = JO_FAIL;
    const char *type;

    assert(key_spec != NULL);

    size_t min_len;
    switch (typeId) {
        case KS_ML_KEM_512:
            min_len = 800;
            type = "ML-KEM-512";
            break;
        case KS_ML_KEM_768:
            min_len = 1184;
            type = "ML-KEM-768";
            break;
        case KS_ML_KEM_1024:
            type = "ML-KEM-1024";
            min_len = 1568;
            break;
        default:
            return JO_INVALID_KEY_TYPE;
    }

    if (min_len != src_len) {
        ret_code = JO_ENCODED_PUBLIC_KEY_LEN;
        goto exit;
    }


    key_spec->key = EVP_PKEY_new_raw_public_key_ex(NULL, type,NULL, src, src_len);

#ifdef JOSTLE_OPS
    if (OPS_OPENSSL_ERROR_1 0) {
        EVP_PKEY_free(key_spec->key);
        key_spec->key = NULL;
        // trigger the openssl error pathway below
    }
#endif

    if (key_spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    return ret_code;
}
