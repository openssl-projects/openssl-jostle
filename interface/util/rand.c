//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "rand.h"

#include <stddef.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"

/*
 * OpenSSL DRBGs are commonly configured with a 2^16-byte max request.
 * Keep each RAND_priv_bytes_ex call at or below that boundary and loop for
 * larger SecureRandom.nextBytes() requests.
 */
#define RAND_MAX_REQUEST ((size_t) 65536)

/*
 * SecureRandom owns its own libctx so its lifecycle and provider-name binding
 * stay independent of the provider-wide libctx used by other native services.
 */
static OSSL_LIB_CTX *rand_libctx = NULL;
static char *rand_provider_name = NULL;

struct jo_rand_ctx_st {
    EVP_RAND_CTX *evp_ctx;
    size_t max_request;
};

static unsigned int rand_strength(int32_t strength) {
    return (unsigned int) strength;
}

int32_t rand_init(const char *provider_name, int32_t *created) {
    jo_assert(provider_name != NULL);
    jo_assert(created != NULL);

    *created = 0;
    if (rand_libctx != NULL) {
        // Native RAND state is process-wide and intentionally bound to the
        // first successfully loaded provider name.
        jo_assert(rand_provider_name != NULL);
        if (strcmp(rand_provider_name, provider_name) != 0) {
            return JO_UNEXPECTED_STATE;
        }

        return JO_SUCCESS;
    }

    char *provider_name_copy = OPENSSL_strdup(provider_name);
    jo_assert(provider_name_copy != NULL);

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    jo_assert(libctx != NULL);

    ERR_clear_error();
    if (OSSL_PROVIDER_load(libctx, provider_name) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        OPENSSL_free(provider_name_copy);
        return JO_OPENSSL_ERROR;
    }

    rand_libctx = libctx;
    rand_provider_name = provider_name_copy;
    *created = 1;
    return JO_SUCCESS;
}

void rand_destroy(void) {
    if (rand_libctx != NULL) {
        OSSL_LIB_CTX_free(rand_libctx);
        rand_libctx = NULL;
    }
    if (rand_provider_name != NULL) {
        OPENSSL_free(rand_provider_name);
        rand_provider_name = NULL;
    }
}

JO_RAND_CTX *rand_ctx_create(const char *mechanism, const char *variant, int use_df,
                             int32_t strength, int prediction_resistant,
                             const uint8_t *personalization_string,
                             size_t personalization_string_len,
                             int32_t *err) {
    jo_assert(mechanism != NULL);
    jo_assert(variant != NULL);
    jo_assert(strength >= 0);
    jo_assert(strength <= JO_RAND_MAX_STRENGTH);
    jo_assert(rand_libctx != NULL);
    jo_assert(personalization_string_len == 0 || personalization_string != NULL);
    jo_assert(err != NULL);

    *err = JO_FAIL;

    ERR_clear_error();

    JO_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    jo_assert(ctx != NULL);

    EVP_RAND *rand = EVP_RAND_fetch(rand_libctx, mechanism, NULL);
    if (OPS_OPENSSL_ERROR_1 rand == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INIT_FAIL,
                       "rand_ctx_create: EVP_RAND_fetch failed");
        *err = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3030);
        EVP_RAND_free(rand);
        rand_ctx_destroy(ctx);
        return NULL;
    }

    EVP_RAND_CTX *parent = RAND_get0_private(rand_libctx);
    if (OPS_OPENSSL_ERROR_6 parent == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INIT_FAIL,
                       "rand_ctx_create: RAND_get0_private failed");
        *err = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(3031);
        EVP_RAND_free(rand);
        rand_ctx_destroy(ctx);
        return NULL;
    }

    ctx->evp_ctx = EVP_RAND_CTX_new(rand, parent);
    EVP_RAND_free(rand);
    if (OPS_OPENSSL_ERROR_9 ctx->evp_ctx == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INIT_FAIL,
                       "rand_ctx_create: EVP_RAND_CTX_new failed");
        *err = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(3032);
        rand_ctx_destroy(ctx);
        return NULL;
    }

    //
    // The variant selector is mechanism-specific: CTR-DRBG takes a cipher
    // (and the derivation-function flag); HASH-DRBG and HMAC-DRBG take a
    // digest, and HMAC-DRBG additionally pins the MAC to HMAC. Passing a
    // cipher to a hash mechanism (or vice versa) is rejected by OpenSSL, so
    // the array is built per mechanism rather than unconditionally.
    //
    OSSL_PARAM params[4];
    int n = 0;
    int df = use_df ? 1 : 0;
    if (strcmp(mechanism, "CTR-DRBG") == 0) {
        params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                                       (char *) variant, 0);
        params[n++] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &df);
    } else {
        params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
                                                       (char *) variant, 0);
        if (strcmp(mechanism, "HMAC-DRBG") == 0) {
            params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC,
                                                           (char *) "HMAC", 0);
        }
    }
    params[n] = OSSL_PARAM_construct_end();
    if (OPS_OPENSSL_ERROR_10 1 != EVP_RAND_instantiate(ctx->evp_ctx, rand_strength(strength),
                                                       prediction_resistant != 0,
                                                       personalization_string,
                                                       personalization_string_len, params)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INIT_FAIL,
                       "rand_ctx_create: EVP_RAND_instantiate failed");
        *err = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(3033);
        rand_ctx_destroy(ctx);
        return NULL;
    }

    //
    // The per-generate maximum request size is the DRBG's own runtime limit
    // (OpenSSL enforces it in EVP_RAND_generate), so read it from the live ctx
    // and cache it for chunking rather than hard-coding a value that could drift
    // from a variant's or custom provider's actual limit. RAND_MAX_REQUEST is
    // only the fallback when the query is unavailable.
    //
    size_t max_request = RAND_MAX_REQUEST;
    OSSL_PARAM max_request_params[] = {
        OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max_request),
        OSSL_PARAM_construct_end()
    };
    if (1 == EVP_RAND_CTX_get_params(ctx->evp_ctx, max_request_params) && max_request > 0) {
        ctx->max_request = max_request;
    } else {
        ctx->max_request = RAND_MAX_REQUEST;
    }

    *err = JO_SUCCESS;
    return ctx;
}

void rand_ctx_destroy(JO_RAND_CTX *ctx) {
    if (ctx == NULL) {
        return;
    }

    EVP_RAND_CTX_free(ctx->evp_ctx);
    OPENSSL_free(ctx);
}

int32_t rand_ctx_random_bytes(JO_RAND_CTX *ctx, uint8_t *output,
                              int32_t output_len, int32_t strength,
                              int prediction_resistant,
                              const uint8_t *additional_input,
                              size_t additional_input_len) {
    jo_assert(ctx != NULL);
    jo_assert(output != NULL);
    jo_assert(output_len >= 0);
    jo_assert(strength >= 0);
    jo_assert(strength <= JO_RAND_MAX_STRENGTH);
    jo_assert(additional_input_len == 0 || additional_input != NULL);

    int state = EVP_RAND_get_state(ctx->evp_ctx);
    if (OPS_FAILED_SET_2 0) {
        state = -1;
    }
    if (state != EVP_RAND_STATE_READY) {
        return JO_UNEXPECTED_STATE;
    }

    uint8_t *out = output;
    size_t remaining = (size_t) output_len;

    ERR_clear_error();

    while (remaining > 0) {
        size_t request = remaining > ctx->max_request ? ctx->max_request : remaining;
        const uint8_t *adin = additional_input;
        size_t adin_len = additional_input_len;

        if (OPS_OPENSSL_ERROR_1 1 != EVP_RAND_generate(ctx->evp_ctx, out, request,
                                                       rand_strength(strength),
                                                       prediction_resistant != 0, adin, adin_len)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3040);
        }

        additional_input = NULL;
        additional_input_len = 0;
        out += request;
        remaining -= request;
    }

    return JO_SUCCESS;
}

int32_t rand_ctx_reseed(JO_RAND_CTX *ctx, int32_t strength,
                        int prediction_resistant,
                        const uint8_t *additional_input,
                        size_t additional_input_len) {
    jo_assert(ctx != NULL);
    jo_assert(strength >= 0);
    jo_assert(strength <= JO_RAND_MAX_STRENGTH);
    jo_assert(additional_input_len == 0 || additional_input != NULL);

    ERR_clear_error();

    int state = EVP_RAND_get_state(ctx->evp_ctx);
    if (OPS_FAILED_SET_1 0) {
        state = -1;
    }
    if (OPS_FAILED_INIT_1 state == EVP_RAND_STATE_UNINITIALISED) {
        if (OPS_OPENSSL_ERROR_1 1 != EVP_RAND_instantiate(ctx->evp_ctx, rand_strength(strength),
                                                          prediction_resistant != 0,
                                                          additional_input,
                                                          additional_input_len, NULL)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3050);
        }
        return JO_SUCCESS;
    }

    if (OPS_FAILED_INIT_2 state == EVP_RAND_STATE_READY) {
        if (OPS_OPENSSL_ERROR_6 1 != EVP_RAND_reseed(ctx->evp_ctx, prediction_resistant != 0,
                                                     NULL, 0, additional_input,
                                                     additional_input_len)) {
            return JO_RAND_RESEED OPS_OFFSET_OPENSSL_ERROR_6(3051);
        }
        return JO_SUCCESS;
    }

    return JO_UNEXPECTED_STATE;
}

int32_t rand_drbg_strength(const char *mechanism, const char *variant) {
    jo_assert(mechanism != NULL);
    jo_assert(variant != NULL);
    jo_assert(rand_libctx != NULL);

    ERR_clear_error();

    EVP_RAND *rand = EVP_RAND_fetch(rand_libctx, mechanism, NULL);
    if (rand == NULL) {
        return JO_OPENSSL_ERROR;
    }

    EVP_RAND_CTX *parent = RAND_get0_private(rand_libctx);
    if (parent == NULL) {
        EVP_RAND_free(rand);
        return JO_OPENSSL_ERROR;
    }

    EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(rand, parent);
    EVP_RAND_free(rand);
    if (ctx == NULL) {
        return JO_OPENSSL_ERROR;
    }

    //
    // The DRBG's security strength is derived from the variant (cipher key
    // length for CTR, digest size for HASH/HMAC) and is reported once the
    // variant params are set — no instantiate (and so no entropy draw) is
    // needed to read it. Mirror rand_ctx_create's per-mechanism param shape.
    //
    OSSL_PARAM params[3];
    int n = 0;
    if (strcmp(mechanism, "CTR-DRBG") == 0) {
        params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
                                                       (char *) variant, 0);
    } else {
        params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
                                                       (char *) variant, 0);
        if (strcmp(mechanism, "HMAC-DRBG") == 0) {
            params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC,
                                                           (char *) "HMAC", 0);
        }
    }
    params[n] = OSSL_PARAM_construct_end();

    int32_t result = JO_OPENSSL_ERROR;
    if (1 == EVP_RAND_CTX_set_params(ctx, params)) {
        unsigned int strength = 0;
        OSSL_PARAM query[2] = {
            OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength),
            OSSL_PARAM_construct_end()
        };
        if (1 == EVP_RAND_CTX_get_params(ctx, query)) {
            result = strength > (unsigned int) INT32_MAX
                     ? JO_OUTPUT_TOO_LONG_INT32
                     : (int32_t) strength;
        }
    }

    EVP_RAND_CTX_free(ctx);
    return result;
}
