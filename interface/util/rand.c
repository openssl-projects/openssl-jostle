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
#include <openssl/evp.h>
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
#define RAND_MAX_STRENGTH ((int32_t) 256)
#define RAND_OSSL_STRENGTH ((unsigned int) 0)

/*
 * SecureRandom owns its own libctx so its lifecycle and provider-name binding
 * stay independent of the provider-wide libctx used by other native services.
 */
static OSSL_LIB_CTX *rand_libctx = NULL;
static char *rand_provider_name = NULL;

struct jo_rand_ctx_st {
    uint8_t *personalization_string;
    size_t personalization_string_len;
    int personalization_pending;
};

static int rand_strength_supported(int32_t strength) {
    return strength <= RAND_MAX_STRENGTH;
}

static int32_t rand_ctx_additional_input(JO_RAND_CTX *ctx,
                                         const uint8_t *additional_input,
                                         size_t additional_input_len,
                                         uint8_t **allocated,
                                         const uint8_t **ctx_additional_input,
                                         size_t *ctx_additional_input_len) {
    jo_assert(ctx != NULL);
    jo_assert(additional_input_len == 0 || additional_input != NULL);
    jo_assert(allocated != NULL);
    jo_assert(ctx_additional_input != NULL);
    jo_assert(ctx_additional_input_len != NULL);

    *allocated = NULL;
    *ctx_additional_input = additional_input;
    *ctx_additional_input_len = additional_input_len;

    if (ctx->personalization_pending == 0 || ctx->personalization_string_len == 0) {
        return JO_SUCCESS;
    }

    if (additional_input_len == 0) {
        *ctx_additional_input = ctx->personalization_string;
        *ctx_additional_input_len = ctx->personalization_string_len;
        return JO_SUCCESS;
    }

    size_t combined_len = ctx->personalization_string_len + additional_input_len;
    uint8_t *combined = OPENSSL_malloc(combined_len);
    jo_assert(combined != NULL);

    memcpy(combined, ctx->personalization_string, ctx->personalization_string_len);
    memcpy(combined + ctx->personalization_string_len, additional_input,
           additional_input_len);

    *allocated = combined;
    *ctx_additional_input = combined;
    *ctx_additional_input_len = combined_len;
    return JO_SUCCESS;
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

int32_t rand_random_bytes(uint8_t *output, int32_t output_len, int32_t strength,
                          int prediction_resistant, const uint8_t *additional_input,
                          size_t additional_input_len) {
    jo_assert(output != NULL);
    jo_assert(output_len >= 0);
    jo_assert(strength >= 0);
    jo_assert(rand_libctx != NULL);
    jo_assert(additional_input_len == 0 || additional_input != NULL);

    if (!rand_strength_supported(strength)) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    uint8_t *out = output;
    size_t remaining = (size_t) output_len;

    ERR_clear_error();

    if (prediction_resistant == 0 && additional_input == NULL) {
        while (remaining > 0) {
            size_t request = remaining > RAND_MAX_REQUEST ? RAND_MAX_REQUEST : remaining;

            if (1 != RAND_priv_bytes_ex(rand_libctx, out, request, RAND_OSSL_STRENGTH)) {
                return JO_OPENSSL_ERROR;
            }

            out += request;
            remaining -= request;
        }

        return JO_SUCCESS;
    }

    EVP_RAND_CTX *ctx = RAND_get0_private(rand_libctx);
    if (OPS_OPENSSL_ERROR_6 ctx == NULL) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(3020);
    }

    int state = EVP_RAND_get_state(ctx);
    if (OPS_FAILED_SET_2 0) {
        state = -1;
    }
    if (OPS_FAILED_INIT_1 state == EVP_RAND_STATE_UNINITIALISED) {
        if (OPS_OPENSSL_ERROR_7 1 != EVP_RAND_instantiate(ctx, RAND_OSSL_STRENGTH,
                                                          prediction_resistant != 0, NULL, 0, NULL)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(3021);
        }
    } else if (state != EVP_RAND_STATE_READY) {
        return JO_UNEXPECTED_STATE;
    }

    while (remaining > 0) {
        size_t request = remaining > RAND_MAX_REQUEST ? RAND_MAX_REQUEST : remaining;
        const uint8_t *adin = additional_input;
        size_t adin_len = additional_input_len;

        if (OPS_OPENSSL_ERROR_8 1 != EVP_RAND_generate(ctx, out, request, RAND_OSSL_STRENGTH,
                                                       prediction_resistant != 0, adin, adin_len)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(3022);
        }

        additional_input = NULL;
        additional_input_len = 0;
        out += request;
        remaining -= request;
    }

    return JO_SUCCESS;
}

int32_t rand_instantiate(int32_t strength, int prediction_resistant,
                         const uint8_t *personalization_string,
                         size_t personalization_string_len) {
    jo_assert(strength >= 0);
    jo_assert(rand_libctx != NULL);
    jo_assert(personalization_string_len == 0 || personalization_string != NULL);

    if (!rand_strength_supported(strength)) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    ERR_clear_error();

    EVP_RAND_CTX *ctx = RAND_get0_private(rand_libctx);
    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3000);
    }

    int state = EVP_RAND_get_state(ctx);
    if (OPS_FAILED_SET_1 0) {
        state = -1;
    }
    if (OPS_FAILED_INIT_1 state == EVP_RAND_STATE_UNINITIALISED) {
        if (OPS_OPENSSL_ERROR_2 1 != EVP_RAND_instantiate(ctx, RAND_OSSL_STRENGTH,
                                                          prediction_resistant != 0,
                                                          personalization_string,
                                                          personalization_string_len, NULL)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(3001);
        }
        return JO_SUCCESS;
    }

    if (OPS_FAILED_INIT_2 state == EVP_RAND_STATE_READY) {
        if (prediction_resistant != 0) {
            if (OPS_OPENSSL_ERROR_3 1 != EVP_RAND_reseed(ctx, 1, NULL, 0, NULL, 0)) {
                return JO_RAND_RESEED OPS_OFFSET_OPENSSL_ERROR_3(3002);
            }
        }
        return JO_SUCCESS;
    }

    return JO_UNEXPECTED_STATE;
}

int32_t rand_reseed(int32_t strength, int prediction_resistant,
                    const uint8_t *additional_input, size_t additional_input_len) {
    jo_assert(strength >= 0);
    jo_assert(rand_libctx != NULL);
    jo_assert(additional_input_len == 0 || additional_input != NULL);

    if (!rand_strength_supported(strength)) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    ERR_clear_error();

    EVP_RAND_CTX *ctx = RAND_get0_private(rand_libctx);
    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3010);
    }

    int state = EVP_RAND_get_state(ctx);
    if (OPS_FAILED_SET_1 0) {
        state = -1;
    }
    if (OPS_FAILED_INIT_1 state == EVP_RAND_STATE_UNINITIALISED) {
        if (OPS_OPENSSL_ERROR_4 1 != EVP_RAND_instantiate(ctx, RAND_OSSL_STRENGTH,
                                                          prediction_resistant != 0, NULL, 0, NULL)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(3011);
        }
        return JO_SUCCESS;
    }

    if (OPS_FAILED_INIT_2 state == EVP_RAND_STATE_READY) {
        if (OPS_OPENSSL_ERROR_5 1 != EVP_RAND_reseed(ctx, prediction_resistant != 0,
                                                     NULL, 0, additional_input,
                                                     additional_input_len)) {
            return JO_RAND_RESEED OPS_OFFSET_OPENSSL_ERROR_5(3012);
        }
        return JO_SUCCESS;
    }

    return JO_UNEXPECTED_STATE;
}

JO_RAND_CTX *rand_ctx_create(int32_t strength, int prediction_resistant,
                             const uint8_t *personalization_string,
                             size_t personalization_string_len,
                             int32_t *err) {
    jo_assert(strength >= 0);
    jo_assert(rand_libctx != NULL);
    jo_assert(personalization_string_len == 0 || personalization_string != NULL);
    jo_assert(err != NULL);

    (void) prediction_resistant;
    *err = JO_FAIL;

    if (!rand_strength_supported(strength)) {
        *err = JO_RAND_INSUFFICIENT_STRENGTH;
        return NULL;
    }

    JO_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    jo_assert(ctx != NULL);

    if (personalization_string_len > 0) {
        ctx->personalization_string = OPENSSL_malloc(personalization_string_len);
        jo_assert(ctx->personalization_string != NULL);

        memcpy(ctx->personalization_string, personalization_string,
               personalization_string_len);
        ctx->personalization_string_len = personalization_string_len;
        ctx->personalization_pending = 1;
    }

    *err = JO_SUCCESS;
    return ctx;
}

void rand_ctx_destroy(JO_RAND_CTX *ctx) {
    if (ctx == NULL) {
        return;
    }

    OPENSSL_clear_free(ctx->personalization_string,
                       ctx->personalization_string_len);
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
    jo_assert(additional_input_len == 0 || additional_input != NULL);

    uint8_t *allocated = NULL;
    const uint8_t *ctx_additional_input = NULL;
    size_t ctx_additional_input_len = 0;

    int32_t ret_code = rand_ctx_additional_input(ctx, additional_input,
                                                 additional_input_len,
                                                 &allocated,
                                                 &ctx_additional_input,
                                                 &ctx_additional_input_len);
    if (ret_code == JO_SUCCESS) {
        ret_code = rand_random_bytes(output, output_len, strength,
                                     prediction_resistant,
                                     ctx_additional_input,
                                     ctx_additional_input_len);
    }

    OPENSSL_clear_free(allocated, ctx_additional_input_len);
    if (ret_code == JO_SUCCESS) {
        ctx->personalization_pending = 0;
    }

    return ret_code;
}

int32_t rand_ctx_reseed(JO_RAND_CTX *ctx, int32_t strength,
                        int prediction_resistant,
                        const uint8_t *additional_input,
                        size_t additional_input_len) {
    jo_assert(ctx != NULL);
    jo_assert(strength >= 0);
    jo_assert(additional_input_len == 0 || additional_input != NULL);

    uint8_t *allocated = NULL;
    const uint8_t *ctx_additional_input = NULL;
    size_t ctx_additional_input_len = 0;

    int32_t ret_code = rand_ctx_additional_input(ctx, additional_input,
                                                 additional_input_len,
                                                 &allocated,
                                                 &ctx_additional_input,
                                                 &ctx_additional_input_len);
    if (ret_code == JO_SUCCESS) {
        ret_code = rand_reseed(strength, prediction_resistant,
                               ctx_additional_input,
                               ctx_additional_input_len);
    }

    OPENSSL_clear_free(allocated, ctx_additional_input_len);
    if (ret_code == JO_SUCCESS) {
        ctx->personalization_pending = 0;
    }

    return ret_code;
}
