//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "mlxkem.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include "bc_err_codes.h"
#include "key_spec.h"
#include "ops.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"

/*
 * The OpenSSL name for a hybrid key-spec type, or NULL if the type is not one.
 * Spelled exactly as IANA and OpenSSL do - these are TLS group names, not
 * something we get to normalise.
 */
static const char *mlxkem_name(int32_t type) {
    switch (type) {
        case KS_X25519_MLKEM768:
            return "X25519MLKEM768";
        case KS_X448_MLKEM1024:
            return "X448MLKEM1024";
        case KS_SECP256R1_MLKEM768:
            return "SecP256r1MLKEM768";
        case KS_SECP384R1_MLKEM1024:
            return "SecP384r1MLKEM1024";
        default:
            return NULL;
    }
}

/*
 * Is this EVP_PKEY one of the four hybrids? Asked of the key rather than
 * trusted from the caller, so a key of another family reaching a hybrid getter
 * is a typed rejection rather than a wrong answer.
 */
static int mlxkem_is_hybrid(EVP_PKEY *pkey) {
    const char *algo = EVP_PKEY_get0_type_name(pkey);

    if (algo == NULL) {
        return 0;
    }
    return strcmp(algo, "X25519MLKEM768") == 0
           || strcmp(algo, "X448MLKEM1024") == 0
           || strcmp(algo, "SecP256r1MLKEM768") == 0
           || strcmp(algo, "SecP384r1MLKEM1024") == 0;
}

int32_t mlxkem_generate_key_pair(key_spec *spec, int32_t type, void *rnd_src) {
    jo_assert(spec != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    const char *name = mlxkem_name(type);
    if (name == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), name, NULL);

    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1400);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 EVP_PKEY_keygen_init(ctx) <= 0) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1401);
        goto exit;
    }

    // Free any pre-existing key so EVP_PKEY_keygen doesn't leak it.
    if (spec->key != NULL) {
        EVP_PKEY_free(spec->key);
        spec->key = NULL;
    }

    if (OPS_OPENSSL_ERROR_3 EVP_PKEY_keygen(ctx, &(spec->key)) <= 0) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(1402);
        goto exit;
    }

#ifdef JOSTLE_OPS
    if (OPS_OPENSSL_ERROR_4 0) {
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
    rand_clear_java_srand_call();
    return ret_code;
}

/*
 * Shared body for the two getters. `param` is the OSSL_PKEY_PARAM_* to read and
 * `unsupported` the code to return when the fetch refuses without raising.
 *
 * The two-call shape matters here in a way it does not for other families: on
 * the SecP variants the SIZE query succeeds and the FETCH then fails, so a
 * getter that trusted the size query would report a length it cannot deliver.
 */
static int32_t mlxkem_get_param(key_spec *spec, const char *param, int32_t unsupported,
                                uint8_t *out, size_t out_len) {
    jo_assert(spec != NULL);
    EVP_PKEY *pkey = spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    if (!mlxkem_is_hybrid(pkey)) {
        return JO_INCORRECT_KEY_TYPE;
    }

    ERR_clear_error();

    size_t min_len = 0;

    if (OPS_OPENSSL_ERROR_5 EVP_PKEY_get_octet_string_param(pkey, param, NULL, 0, &min_len) <= 0) {
        return unsupported;
    }

    if (OPS_INT32_OVERFLOW_1 min_len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    if (out == NULL) {
        return (int32_t) min_len;
    }

    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;

    if (OPS_OPENSSL_ERROR_6 EVP_PKEY_get_octet_string_param(pkey, param, out, min_len, &written) <= 0) {
        // The size query answered and the fetch did not. Detected by trying,
        // never by naming the variant, so a release that starts supporting the
        // export starts working here rather than staying refused.
        return unsupported;
    }

    return (int32_t) written;
}

int32_t mlxkem_get_public_encoded(key_spec *spec, uint8_t *out, size_t out_len) {
    // ENCODED_PUBLIC_KEY, not PUB_KEY: PUB_KEY is not gettable on any hybrid.
    // A generic OpenSSL error is right here - no variant refuses this one, so
    // a refusal means something genuinely went wrong.
    return mlxkem_get_param(spec, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, JO_OPENSSL_ERROR, out, out_len);
}

int32_t mlxkem_get_private_encoded(key_spec *spec, uint8_t *out, size_t out_len) {
    return mlxkem_get_param(spec, OSSL_PKEY_PARAM_PRIV_KEY,
                            JO_HYBRID_PRIVATE_EXPORT_UNSUPPORTED, out, out_len);
}

/*
 * Shared body for the two decoders. There is no ASN.1 codec for a hybrid key,
 * so both go through EVP_PKEY_fromdata.
 *
 * Note the asymmetry with the getters: the public half is IMPORTED under
 * OSSL_PKEY_PARAM_PUB_KEY even though it is EXPORTED under
 * ENCODED_PUBLIC_KEY. That is what mlx_kem_imexport_types advertises and what
 * the probe measured; it is not a typo.
 */
static int32_t mlxkem_decode(key_spec *spec, int32_t type, const char *param, int selection,
                             uint8_t *src, size_t src_len) {
    jo_assert(spec != NULL);
    jo_assert(src != NULL);

    const char *name = mlxkem_name(type);
    if (name == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    if (src_len == 0) {
        // Zero where zero is meaningless takes the same code as a negative
        // length, per the range-check rule in native-code.md.
        return JO_INPUT_LEN_IS_NEGATIVE;
    }

    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY *decoded = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), name, NULL);

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string((char *) param, src, src_len);
    params[1] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_7 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(1403);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_8 EVP_PKEY_fromdata_init(ctx) <= 0) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(1404);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_9 EVP_PKEY_fromdata(ctx, &decoded, selection, params) <= 0) {
        ret_code = JO_INVALID_KEY_TYPE;
        goto exit;
    }

    if (decoded == NULL) {
        ret_code = JO_INVALID_KEY_TYPE;
        goto exit;
    }

    // Only replace the spec's key once the new one is in hand, so a failed
    // decode leaves the caller's spec as it was.
    if (spec->key != NULL) {
        EVP_PKEY_free(spec->key);
    }
    spec->key = decoded;
    decoded = NULL;
    ret_code = JO_SUCCESS;

exit:
    EVP_PKEY_free(decoded);
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}

int32_t mlxkem_decode_public_key(key_spec *spec, int32_t type, uint8_t *src, size_t src_len) {
    return mlxkem_decode(spec, type, OSSL_PKEY_PARAM_PUB_KEY, EVP_PKEY_PUBLIC_KEY, src, src_len);
}

int32_t mlxkem_decode_private_key(key_spec *spec, int32_t type, uint8_t *src, size_t src_len) {
    return mlxkem_decode(spec, type, OSSL_PKEY_PARAM_PRIV_KEY, EVP_PKEY_KEYPAIR, src, src_len);
}
