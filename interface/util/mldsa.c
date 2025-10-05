//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "mldsa.h"

#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "bc_err_codes.h"
#include "key_spec.h"
#include "ops.h"


/**
 * Sets up hash for non-digest modes.
 *
 * NB: Follows BC equivalent but if context_len is negative it will skip adding preHash byte, context len byte.
 *
 * @param ctx mldsa context
 * @param md the hash to preload
 * @param ret_code  pointer to receive error code.
 * @return 1 = success, 0 = failure
 */
int setup_hash_with_tr_and_context(const mldsa_ctx *ctx, EVP_MD_CTX *md, int32_t *ret_code) {
    if (1 != EVP_DigestUpdate(md, ctx->tr, 64)) {
        *ret_code = JO_OPENSSL_ERROR;
        return 0;
    }

    if (ctx->context_len >= 0) {
        const uint8_t pre_hash = (ctx->hash_type == MLDSA_HASH_NONE) ? 0 : 1;
        if (1 != EVP_DigestUpdate(md, &pre_hash, 1)) {
            *ret_code = JO_OPENSSL_ERROR;
            return 0;
        }

        const uint8_t len = (uint8_t) ctx->context_len & 0xFFl;

        if (1 != EVP_DigestUpdate(md, &len, 1)) {
            *ret_code = JO_OPENSSL_ERROR;
            return 0;
        }

        if (1 != EVP_DigestUpdate(md, ctx->context, len)) {
            *ret_code = JO_OPENSSL_ERROR;
            return 0;
        }
    }

    return 1;
}

/**
 * Interpret operation and set up the message digest that will receive updates.
 *
 * @param hash Hashing mode
 * @param ret_code pointer for error codes
 * @param ctx the message digest we are setting up
 * @return 1 = success, 0 = fail
 */
int setup_hash(int hash, int32_t *ret_code, EVP_MD_CTX **ctx) {
    *ctx = EVP_MD_CTX_new();
    if (*ctx == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        goto fail;
    }

    if (hash == MLDSA_HASH_NONE) {
        if (1 != EVP_DigestInit_ex2(*ctx, EVP_shake256(), NULL)) {
            *ret_code = JO_OPENSSL_ERROR;
            goto fail;
        }
        return 1;
    }

    *ret_code = JO_UNEXPECTED_STATE;
fail:
    EVP_MD_CTX_free(*ctx);
    return 0;
}


/**
 * Extract the Tr from the public key
 * @param key_spec the key spex
 * @param tr place to write Tr value, must be 64 bytes long
 * @param ret_code pointer for error codes
 * @return 0 = fail, 1 = success
 */
int extract_tr(const key_spec *key_spec, int32_t type, uint8_t *tr, int32_t *ret_code) {
    size_t min_len;

    switch (type) {
        case KS_MLDSA_44:
            min_len = 1312;
            break;

        case KS_MLDSA_65:
            min_len = 1952;
            break;

        case KS_MLDSA_87:
            min_len = 2592;
            break;
        default:
            return JO_INCORRECT_KEY_TYPE;
    }

    uint8_t key_enc[min_len];

    size_t written = 0;

    if (1 != EVP_PKEY_get_octet_string_param(key_spec->key, OSSL_PKEY_PARAM_PUB_KEY, key_enc, min_len, &written)) {
        *ret_code = JO_OPENSSL_ERROR;
        return 0;
    }

    if (written != min_len) {
        *ret_code = JO_EXTRACTED_KEY_UNEXPECTED_LEN;
        return 0;
    }


    EVP_MD_CTX *shake = EVP_MD_CTX_new();
    if (shake == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        return 0;
    }

    if (1 != EVP_DigestInit_ex2(shake, EVP_shake256(), NULL)) {
        EVP_MD_CTX_free(shake);
        *ret_code = JO_OPENSSL_ERROR;
        return 0;
    }

    // Rho + T1
    if (1 != EVP_DigestUpdate(shake, key_enc, written)) {
        EVP_MD_CTX_free(shake);
        *ret_code = JO_OPENSSL_ERROR;
        return 0;
    }

    if (1 != EVP_DigestFinalXOF(shake, (unsigned char *) tr, TR_LEN)) {
        EVP_MD_CTX_free(shake);
        *ret_code = JO_OPENSSL_ERROR;
        return 0;
    }

    EVP_MD_CTX_free(shake);
    OPENSSL_cleanse(key_enc, min_len);

    return 1;
}


/**
 * Derive Mu either calculates the Mu or it will take the content of the mu_buffer and use that if
 * the caller is passing in an external Mu.
 *
 * An external Mu must be 64 bytes long, it is neither padded nor truncated.
 *
 * @param ctx mldsa ctx
 * @param mu output for Mu
 * @param ret_code pointer to error code receiver
 * @return 1 = success, 0 = failed
 */
int derive_mu(const mldsa_ctx *ctx, const uint8_t *mu, int32_t *ret_code) {
    assert(mu != NULL);

    /* Assumption: passed in pointer *mu references an allocation that is Mu_BYTES long */

    if (ctx->mu_mode == MLDSA_Mu_EXTERNAL) {
        if (ctx->mu_buf == NULL || ctx->hash != NULL) {
            *ret_code = JO_UNEXPECTED_STATE;
            return 0;
        }

        uint8_t *externalMu = NULL;
        const size_t len = BIO_get_mem_data(ctx->mu_buf, &externalMu);
        if (len != Mu_BYTES) {
            *ret_code = JO_EXTERNAL_MU_INVALID_LEN;
            return 0;
        }
        memcpy((void *)mu, externalMu, Mu_BYTES);
        BIO_reset(ctx->mu_buf);
        return 1;
    }


    if (ctx->hash_type == MLDSA_HASH_NONE) {
        /*
         * Standard ML-DSA without a pre-hash, in this implementation the SHAKE256 instance
         * has been updated with the TR, context and other parameters during initialization.
         *
         * The shake instance is then used as the target of the update function.
         */

        if (1 != EVP_DigestFinalXOF(ctx->hash, (unsigned char *) mu, Mu_BYTES)) {
            *ret_code = JO_OPENSSL_ERROR;
            return 0;
        }

        if (1 != EVP_MD_CTX_reset(ctx->hash)) {
            *ret_code = JO_OPENSSL_ERROR;
            return 0;
        }
    } else {
        *ret_code = JO_UNEXPECTED_STATE;
        return 0;
    }

    return 1;
}


int32_t mldsa_generate_key_pair(key_spec *spec, int32_t type, uint8_t *seed, size_t seed_len) {
    assert(spec != NULL);


    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    OSSL_PARAM params[] = {
        OSSL_PARAM_END,
        OSSL_PARAM_END
    };

    if (seed != NULL) {
        if (seed_len != MLDSA_SEED_LEN) {
            ret_code = JO_INVALID_SEED_LEN;
            goto exit;
        }
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, seed, seed_len);
    }

    switch (type) {
        case KS_MLDSA_44:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA_44,NULL);
            break;

        case KS_MLDSA_65:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA_65,NULL);
            break;

        case KS_MLDSA_87:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA_87,NULL);

            break;
        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
    }


    if (ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (1 != EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (1 != EVP_PKEY_CTX_set_params(ctx, params)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (1 != EVP_PKEY_keygen(ctx, &(spec->key))) {
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


int32_t mldsa_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    size_t min_len;

    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }


    const char *algo = EVP_PKEY_get0_type_name(key_spec->key);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    if (0 != strncmp(algo, "ML-DSA", 6)) {
        return JO_INCORRECT_KEY_TYPE;
    }


    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
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

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out, min_len,
                                                                 &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET(1000);
    }

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t mldsa_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    size_t min_len;

    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    const char *algo = EVP_PKEY_get0_type_name(key_spec->key);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    if (0 != strncmp(algo, "ML-DSA", 6)) {
        return JO_INCORRECT_KEY_TYPE;
    }

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

int32_t mldsa_get_private_seed(key_spec *key_spec, uint8_t *out, size_t out_len) {
    const size_t min_len = 32;

    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }


    const char *algo = EVP_PKEY_get0_type_name(key_spec->key);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    if (0 != strncmp(algo, "ML-DSA", 6)) {
        return JO_INCORRECT_KEY_TYPE;
    }


    if (out == NULL) {
        return (int32_t) min_len;
    }


    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;

    if (OPS_OPENSSL_ERROR_1
        1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ML_DSA_SEED, out, min_len, &written)) {
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t mldsa_decode_private_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len) {
    int32_t ret_code = JO_FAIL;
    size_t min_len = 0;
    const char *type;

    assert(key_spec != NULL);

    /*
        * KeyFactory has not been initialized to expect a certain key type
        * so attempt to use length to determine ML-DSA private key type
        */
    if (typeId == KS_NONE) {
        switch (src_len) {
            case 2560:
                typeId = KS_MLDSA_44;
                break;
            case 4032:
                typeId = KS_MLDSA_65;
                break;
            case 4896:
                typeId = KS_MLDSA_87;
                break;
            default:
                ret_code = JO_UNKNOWN_KEY_LEN;
                goto exit;
        }
    }


    switch (typeId) {
        case KS_MLDSA_44:
            min_len = 2560;
            type = "ML-DSA-44";
            break;
        case KS_MLDSA_65:
            min_len = 4032;
            type = "ML-DSA-65";
            break;
        case KS_MLDSA_87:
            min_len = 4896;
            type = "ML-DSA-87";
            break;

        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
    }


    if (src_len != 32 && min_len != src_len) {
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

int32_t mldsa_decode_public_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len) {
    int32_t ret_code = JO_FAIL;
    size_t min_len = 0;
    const char *type = NULL;

    assert(key_spec != NULL);


    /*
     * KeyFactory has not been initialized to expect a certain key type
     * so attempt to use length to determine ML-DSA public key type
     */
    if (typeId == KS_NONE) {
        switch (src_len) {
            case 1312:
                typeId = KS_MLDSA_44;
                break;
            case 1952:
                typeId = KS_MLDSA_65;
                break;
            case 2592:
                typeId = KS_MLDSA_87;
                break;
            default:
                ret_code = JO_UNKNOWN_KEY_LEN;
                goto exit;
        }
    }


    switch (typeId) {
        case KS_MLDSA_44:
            min_len = 1312;
            type = "ML-DSA-44";
            break;
        case KS_MLDSA_65:
            min_len = 1952;
            type = "ML-DSA-65";
            break;
        case KS_MLDSA_87:
            min_len = 2592;
            type = "ML-DSA-87";
            break;
        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
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


mldsa_ctx *mldsa_ctx_create(void) {
    mldsa_ctx *ctx = (mldsa_ctx *) OPENSSL_zalloc(sizeof(mldsa_ctx));
    assert(ctx);
    return ctx;
}


void mldsa_ctx_destroy(mldsa_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->sig != NULL) {
        EVP_SIGNATURE_free(ctx->sig);
    }

    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
    }

    if (ctx->hash != NULL) {
        EVP_MD_CTX_free(ctx->hash);
    }

    if (ctx->mu_buf != NULL) {
        BIO_free_all(ctx->mu_buf);
    }

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}


int32_t mldsa_ctx_init_sign(mldsa_ctx *ctx, const key_spec *key_spec, const uint8_t *sign_ctx, int32_t sign_ctx_len,
                            int32_t mu_mode) {
    assert(ctx != NULL);
    assert(key_spec != NULL);

    int32_t ret_code = JO_FAIL;

    if (key_spec->key == NULL) {
        ret_code = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    if (sign_ctx_len >= MAX_CTX_LEN) {
        ret_code = JO_CONTEXT_BYTES_TOO_LONG;
        goto exit;
    }

    OPENSSL_cleanse(ctx->context, MAX_CTX_LEN);
    OPENSSL_cleanse(ctx->tr, TR_LEN);

    if (sign_ctx != NULL) {
        memcpy(ctx->context, sign_ctx, sign_ctx_len);
    }
    ctx->context_len = sign_ctx_len;

    if (ctx->sig != NULL) {
        EVP_SIGNATURE_free(ctx->sig);
        ctx->sig = NULL;
    }

    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
        ctx->pctx = NULL;
    }

    if (ctx->hash != NULL) {
        EVP_MD_CTX_free(ctx->hash);
        ctx->hash = NULL;
    }

    if (ctx->mu_buf != NULL) {
        BIO_free_all(ctx->mu_buf);
        ctx->mu_buf = NULL;
    }

    ctx->opp = MLDSA_SIGN;
    ctx->hash_type = MLDSA_HASH_NONE;
    ctx->mu_mode = mu_mode;

    switch (ctx->mu_mode) {
        case MLDSA_Mu_CALCULATE_ONLY:
        case MLDSA_Mu_INTERNAL:
            break;
        case MLDSA_Mu_EXTERNAL:
            ctx->mu_buf = BIO_new(BIO_s_mem());
            break;
        default:
            ret_code = JO_UNKNOWN_MU_MODE;
            goto exit;
    }

    int32_t typeId = KS_NONE;

    if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-44")) {
        ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-44",NULL);
        typeId = KS_MLDSA_44;
    } else if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-65")) {
        ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-65",NULL);
        typeId = KS_MLDSA_65;
    } else if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-87")) {
        ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-87",NULL);
        typeId = KS_MLDSA_87;
    } else {
        ret_code = JO_INCORRECT_KEY_TYPE;
        goto exit;
    }

    // switch (key_spec->type) {
    //     case KS_MLDSA_44:
    //         ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-44",NULL);
    //         break;
    //
    //     case KS_MLDSA_65:
    //         ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-65",NULL);
    //         break;
    //
    //     case KS_MLDSA_87:
    //         ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-87",NULL);
    //         break;
    //     default:
    //         ret_code = JO_INCORRECT_KEY_TYPE;
    //         goto exit;
    // }


    if (ctx->mu_mode == MLDSA_Mu_INTERNAL || ctx->mu_mode == MLDSA_Mu_CALCULATE_ONLY) {
        if (!extract_tr(key_spec, typeId, ctx->tr, &ret_code)) {
            goto exit;
        }

        if (!setup_hash(ctx->hash_type, &ret_code, &ctx->hash)) {
            goto exit;
        }

        if (ctx->hash_type == MLDSA_HASH_NONE) {
            if (!setup_hash_with_tr_and_context(ctx, ctx->hash, &ret_code)) {
                goto exit;
            }
        }
    }

    const int one = 1; // TODO look for constant
    const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, (void *)&one),
        OSSL_PARAM_END
    };


    ctx->pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key_spec->key, NULL);

    if (OPS_OPENSSL_ERROR_1 ctx->pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1000);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_sign_message_init(ctx->pctx, ctx->sig, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1001);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    return ret_code;
}


int32_t mldsa_ctx_init_verify(
    mldsa_ctx *ctx,
    const key_spec *key_spec,
    const uint8_t *sign_ctx,
    int32_t sign_ctx_len,
    int32_t mu_mode
) {
    assert(ctx != NULL);
    assert(key_spec != NULL);

    int32_t ret_code = JO_FAIL;

    if (key_spec->key == NULL) {
        ret_code = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    if (sign_ctx_len >= MAX_CTX_LEN) {
        ret_code = JO_CONTEXT_BYTES_TOO_LONG;
        goto exit;
    }

    OPENSSL_cleanse(ctx->context, MAX_CTX_LEN);
    OPENSSL_cleanse(ctx->tr, TR_LEN);

    if (sign_ctx != NULL) {
        OPENSSL_cleanse(ctx->context, sizeof(ctx->context));
        memcpy(ctx->context, sign_ctx, sign_ctx_len);
    }

    ctx->context_len = sign_ctx_len;

    // Free last used signature and PKEY
    if (ctx->sig != NULL) {
        EVP_SIGNATURE_free(ctx->sig);
        ctx->sig = NULL;
    }

    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
        ctx->pctx = NULL;
    }

    if (ctx->hash != NULL) {
        EVP_MD_CTX_free(ctx->hash);
        ctx->hash = NULL;
    }

    if (ctx->mu_buf != NULL) {
        BIO_free_all(ctx->mu_buf);
        ctx->mu_buf = NULL;
    }


    ctx->opp = MLDSA_VERIFY;
    ctx->hash_type = MLDSA_HASH_NONE;
    ctx->mu_mode = mu_mode;


    switch (ctx->mu_mode) {
        case MLDSA_Mu_EXTERNAL:
            ctx->mu_buf = BIO_new(BIO_s_mem());
        case MLDSA_Mu_INTERNAL:
            break;

        case MLDSA_Mu_CALCULATE_ONLY:
            ret_code = JO_INVALID_MU_MODE_FOR_VERIFY;
            goto exit;
        default:
            ret_code = JO_UNKNOWN_MU_MODE;
            goto exit;
    }


    int32_t typeId = KS_NONE;
    if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-44")) {
        ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-44",NULL);
        typeId = KS_MLDSA_44;
    } else if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-65")) {
        ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-65",NULL);
        typeId = KS_MLDSA_65;
    } else if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-87")) {
        ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-87",NULL);
        typeId = KS_MLDSA_87;
    } else {
        ret_code = JO_INCORRECT_KEY_TYPE;
        goto exit;
    }

    // switch (key_spec->type) {
    //     case KS_MLDSA_44:
    //         ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-44",NULL);
    //         break;
    //
    //     case KS_MLDSA_65:
    //         ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-65",NULL);
    //         break;
    //
    //     case KS_MLDSA_87:
    //         ctx->sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-87",NULL);
    //         break;
    //     default:
    //         ret_code = JO_INCORRECT_KEY_TYPE;
    //         goto exit;
    // }


    if (ctx->mu_mode == MLDSA_Mu_INTERNAL) {
        if (!extract_tr(key_spec, typeId, ctx->tr, &ret_code)) {
            goto exit;
        }

        if (!setup_hash(ctx->hash_type, &ret_code, &ctx->hash)) {
            goto exit;
        }

        if (ctx->hash_type == MLDSA_HASH_NONE) {
            if (!setup_hash_with_tr_and_context(ctx, ctx->hash, &ret_code)) {
                goto exit;
            }
        }
    }

    const int one = 1;

    const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MU, (void *)&one),
        OSSL_PARAM_END
    };


    ctx->pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key_spec->key, NULL);

    if (OPS_OPENSSL_ERROR_1 ctx->pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1003);
        goto exit;
    }


    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_verify_message_init(ctx->pctx, ctx->sig, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1004);
        goto exit;
    }


    ret_code = JO_SUCCESS;


exit:

    return ret_code;
}


int32_t mldsa_ctx_sign(const mldsa_ctx *ctx, const uint8_t *out, const size_t out_len) {
    assert(ctx != NULL);
    int ret_code = JO_FAIL;

    if (ctx->hash == NULL && ctx->mu_buf == NULL) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }

    if (ctx->opp != MLDSA_SIGN) {
        ret_code = JO_UNEXPECTED_STATE;
        goto exit;
    }

    size_t sig_len = 0;


    if (ctx->mu_mode == MLDSA_Mu_CALCULATE_ONLY) {
        sig_len = Mu_BYTES;
    } else {
        /* Java API can query for length by passing null array */
        if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_sign(ctx->pctx, NULL, &sig_len,NULL, 0)) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;;
        }
    }


    if (OPS_INT32_OVERFLOW_1 sig_len > INT32_MAX) {
        ret_code = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }


    if (out != NULL) {
        if (sig_len > out_len) {
            ret_code = JO_OUTPUT_TOO_SMALL;
            goto exit;
        }
        uint8_t mu[Mu_BYTES];

        switch (ctx->mu_mode) {
            case MLDSA_Mu_CALCULATE_ONLY:
                if (!derive_mu(ctx, out, &ret_code)) {
                    goto exit;
                }
                break;
            case MLDSA_Mu_EXTERNAL:
            case MLDSA_Mu_INTERNAL:
                if (!derive_mu(ctx, mu, &ret_code)) {
                    goto exit;
                }

                const size_t sig_len_ = sig_len;

                if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_sign(ctx->pctx, (unsigned char *) out, &sig_len, mu,
                                                           Mu_BYTES)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;;
                }

                if (OPS_LEN_CHANGE_1 sig_len_ != sig_len) {
                    ret_code = JO_UNEXPECTED_SIG_LEN_CHANGE;
                    goto exit;
                }


                OPENSSL_cleanse(mu, Mu_BYTES);
                break;
            default:
                // Mu mode should have been asserted during init
                ret_code = JO_UNEXPECTED_STATE;
                goto exit;
        }
    }

    /* integer overflow tested by this point */
    ret_code = (int32_t) sig_len;


exit:
    return ret_code;
}

int32_t mldsa_ctx_verify(mldsa_ctx *ctx, const uint8_t *sig, const size_t sig_len) {
    assert(ctx != NULL);
    int ret_code = JO_FAIL;

    if (ctx->hash == NULL && ctx->mu_buf == NULL) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }

    if (ctx->opp != MLDSA_VERIFY) {
        ret_code = JO_UNEXPECTED_STATE;
        goto exit;
    }


    uint8_t mu[Mu_BYTES] ={0};

    if (!derive_mu(ctx, mu, &ret_code)) {
        goto exit;
    }


    ERR_set_mark();
    int ret = EVP_PKEY_verify(ctx->pctx, sig, sig_len, mu, Mu_BYTES);

    OPENSSL_cleanse(mu, Mu_BYTES);

    if (OPS_OPENSSL_ERROR_1 0) {
        ERR_pop_to_mark();
        ret = -1;
    }

    if (ret == 1) {
        ERR_clear_last_mark();
        ret_code = JO_SUCCESS;
    } else {
        if (ret < 0) {
            ret_code = JO_OPENSSL_ERROR;
        } else {
            ERR_pop_to_mark();
            ret_code = JO_FAIL;
        }
    }


exit:
    return ret_code;
}

int32_t mldsa_update(const mldsa_ctx *ctx, const uint8_t *in, const size_t in_len) {
    assert(ctx != NULL);
    int32_t ret_code = JO_FAIL;

    if (ctx->hash == NULL && ctx->mu_buf == NULL) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }


    if (ctx->mu_buf != NULL) {
        if (in_len > INT32_MAX) {
            // Tested in MLDSAInternalLayerTest
            ret_code = JO_INPUT_TOO_LONG_INT32;
            goto exit;
        }

        if (OPS_OPENSSL_ERROR_1 !BIO_write(ctx->mu_buf, in, (int) in_len)) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;
        }
    } else {
        if (OPS_OPENSSL_ERROR_2 1 != EVP_DigestUpdate(ctx->hash, in, in_len)) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;
        }
    }

    ret_code = JO_SUCCESS;


exit:
    return ret_code;
}
