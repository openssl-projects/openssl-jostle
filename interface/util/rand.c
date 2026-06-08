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

int32_t rand_random_bytes(uint8_t *output, int32_t output_len, int32_t strength) {
    jo_assert(output != NULL);
    jo_assert(output_len >= 0);
    jo_assert(strength >= 0);
    jo_assert(rand_libctx != NULL);

    uint8_t *out = output;
    size_t remaining = (size_t) output_len;

    ERR_clear_error();
    while (remaining > 0) {
        size_t request = remaining > RAND_MAX_REQUEST ? RAND_MAX_REQUEST : remaining;

        if (1 != RAND_priv_bytes_ex(rand_libctx, out, request, (unsigned int) strength)) {
            return JO_OPENSSL_ERROR;
        }

        out += request;
        remaining -= request;
    }

    return JO_SUCCESS;
}

int32_t rand_instantiate(int32_t strength, int prediction_resistant) {
    jo_assert(strength >= 0);
    jo_assert(rand_libctx != NULL);

    ERR_clear_error();

    EVP_RAND_CTX *ctx = RAND_get0_private(rand_libctx);
    if (ctx == NULL) {
        return JO_OPENSSL_ERROR;
    }

    unsigned int available_strength = EVP_RAND_get_strength(ctx);
    if (available_strength < (unsigned int) strength) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    int state = EVP_RAND_get_state(ctx);
    if (state == EVP_RAND_STATE_UNINITIALISED) {
        if (1 != EVP_RAND_instantiate(ctx, (unsigned int) strength,
                                      prediction_resistant != 0, NULL, 0, NULL)) {
            return JO_OPENSSL_ERROR;
        }
        return JO_SUCCESS;
    }

    if (state == EVP_RAND_STATE_READY) {
        if (prediction_resistant != 0) {
            if (1 != EVP_RAND_reseed(ctx, 1, NULL, 0, NULL, 0)) {
                return JO_RAND_RESEED;
            }
        }
        return JO_SUCCESS;
    }

    return JO_UNEXPECTED_STATE;
}

int32_t rand_reseed(int32_t strength, int prediction_resistant) {
    jo_assert(strength >= 0);
    jo_assert(rand_libctx != NULL);

    ERR_clear_error();

    EVP_RAND_CTX *ctx = RAND_get0_private(rand_libctx);
    if (ctx == NULL) {
        return JO_OPENSSL_ERROR;
    }

    unsigned int available_strength = EVP_RAND_get_strength(ctx);
    if (available_strength < (unsigned int) strength) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    int state = EVP_RAND_get_state(ctx);
    if (state == EVP_RAND_STATE_UNINITIALISED) {
        if (1 != EVP_RAND_instantiate(ctx, (unsigned int) strength,
                                      prediction_resistant != 0, NULL, 0, NULL)) {
            return JO_OPENSSL_ERROR;
        }
        return JO_SUCCESS;
    }

    if (state == EVP_RAND_STATE_READY) {
        if (1 != EVP_RAND_reseed(ctx, prediction_resistant != 0, NULL, 0, NULL, 0)) {
            return JO_RAND_RESEED;
        }
        return JO_SUCCESS;
    }

    return JO_UNEXPECTED_STATE;
}
