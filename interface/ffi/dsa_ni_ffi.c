//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <stdint.h>
#include <openssl/crypto.h>

#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/dsa.h"
#include "types.h"


/*
 * Length validation for an FFC component buffer (p / q / g / x / y),
 * run AFTER the null checks so the check order matches the JNI bridge
 * (which can only see lengths after loading the arrays). Both bridges
 * MUST return identical codes for identical inputs — including the
 * combined edge cases (e.g. zero-length component plus null
 * RandSource resolves to the RandSource code on both sides).
 */
static int32_t check_component_len(size_t buf_len) {
    if (buf_len == 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (buf_len > (size_t) INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }
    return JO_SUCCESS;
}


// =============================================================
// Domain-parameter generation / construction
// =============================================================

key_spec *JoDSA_generateParameters(int32_t p_bits, int32_t q_bits,
                                   int32_t *ret_val,
                                   void *rnd_src) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    // Bridge backstop on the bit sizes — the util layer's precondition
    // is bits > 0 (the Java SPI applies the FIPS 186-4 policy bounds).
    if (p_bits <= 0 || q_bits <= 0) {
        *ret_val = JO_DSA_BITS_OUT_OF_RANGE;
        return NULL;
    }
    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dsa_generate_parameters(spec, p_bits, q_bits, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


key_spec *JoDSA_makeParamsFromComponents(uint8_t *p, size_t p_size,
                                         uint8_t *q, size_t q_size,
                                         uint8_t *g, size_t g_size,
                                         int32_t *ret_val) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (p == NULL || q == NULL || g == NULL) {
        *ret_val = JO_INPUT_IS_NULL;
        return NULL;
    }

    int32_t check;
    if (JO_SUCCESS != (check = check_component_len(p_size))
        || JO_SUCCESS != (check = check_component_len(q_size))
        || JO_SUCCESS != (check = check_component_len(g_size))) {
        *ret_val = check;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dsa_make_params_from_components(spec, p, p_size,
                                               q, q_size, g, g_size);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Key generation
// =============================================================

key_spec *JoDSA_generateKeyPair(key_spec *params,
                                int32_t *ret_val,
                                void *rnd_src) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (params == NULL) {
        *ret_val = JO_KEY_SPEC_IS_NULL;
        return NULL;
    }
    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dsa_generate_key(spec, params, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Construct EVP_PKEY from raw components
// =============================================================

key_spec *JoDSA_makePrivateFromComponents(uint8_t *p, size_t p_size,
                                          uint8_t *q, size_t q_size,
                                          uint8_t *g, size_t g_size,
                                          uint8_t *x, size_t x_size,
                                          int32_t *ret_val,
                                          void *rnd_src) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (p == NULL || q == NULL || g == NULL || x == NULL) {
        *ret_val = JO_INPUT_IS_NULL;
        return NULL;
    }
    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    int32_t check;
    if (JO_SUCCESS != (check = check_component_len(p_size))
        || JO_SUCCESS != (check = check_component_len(q_size))
        || JO_SUCCESS != (check = check_component_len(g_size))
        || JO_SUCCESS != (check = check_component_len(x_size))) {
        *ret_val = check;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dsa_make_private_from_components(spec, p, p_size,
                                                q, q_size, g, g_size,
                                                x, x_size, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


key_spec *JoDSA_makePublicFromComponents(uint8_t *p, size_t p_size,
                                         uint8_t *q, size_t q_size,
                                         uint8_t *g, size_t g_size,
                                         uint8_t *y, size_t y_size,
                                         int32_t *ret_val) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (p == NULL || q == NULL || g == NULL || y == NULL) {
        *ret_val = JO_INPUT_IS_NULL;
        return NULL;
    }

    int32_t check;
    if (JO_SUCCESS != (check = check_component_len(p_size))
        || JO_SUCCESS != (check = check_component_len(q_size))
        || JO_SUCCESS != (check = check_component_len(g_size))
        || JO_SUCCESS != (check = check_component_len(y_size))) {
        *ret_val = check;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dsa_make_public_from_components(spec, p, p_size,
                                               q, q_size, g, g_size,
                                               y, y_size);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Component getter
// =============================================================

int32_t JoDSA_getComponent(key_spec *spec, int32_t component,
                           uint8_t *out, size_t out_len) {
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return dsa_get_component(spec, component, out, out_len);
}


// =============================================================
// Sign / verify session
// =============================================================

dsa_ctx *JoDSA_allocateSigner(int32_t *err) {
    return dsa_ctx_create(err);
}

void JoDSA_disposeSigner(dsa_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    dsa_ctx_destroy(ctx);
}

int32_t JoDSA_initSign(dsa_ctx *ctx, key_spec *key,
                       const char *digest_name,
                       void *rnd_src) {
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (digest_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    return dsa_ctx_init_sign(ctx, key, digest_name, rnd_src);
}

int32_t JoDSA_initVerify(dsa_ctx *ctx, key_spec *key,
                         const char *digest_name) {
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }
    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (digest_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    return dsa_ctx_init_verify(ctx, key, digest_name);
}

int32_t JoDSA_update(dsa_ctx *ctx,
                     uint8_t *input, size_t input_size,
                     int32_t in_off, int32_t in_len) {
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }
    if (input == NULL) {
        return JO_INPUT_IS_NULL;
    }
    if (in_off < 0) {
        return JO_INPUT_OFFSET_IS_NEGATIVE;
    }
    if (in_len < 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (!check_in_range(input_size, in_off, in_len)) {
        return JO_INPUT_OUT_OF_RANGE;
    }

    return dsa_ctx_update(ctx, input + in_off, in_len);
}

int32_t JoDSA_sign(dsa_ctx *ctx,
                   uint8_t *output, size_t output_size,
                   int32_t out_off,
                   void *rnd_src) {
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (output == NULL) {
        return dsa_ctx_sign(ctx, NULL, 0, rnd_src);
    }
    if (out_off < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }
    if ((size_t) out_off > output_size) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }
    size_t out_len = output_size - (size_t) out_off;

    return dsa_ctx_sign(ctx, output + (size_t) out_off, out_len, rnd_src);
}

int32_t JoDSA_verify(dsa_ctx *ctx,
                     uint8_t *sig, size_t sig_size,
                     int32_t sig_len,
                     void *rnd_src) {
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    if (sig == NULL) {
        return JO_SIG_IS_NULL;
    }
    if (sig_len < 0) {
        return JO_SIG_LENGTH_IS_NEGATIVE;
    }
    if (!check_in_range(sig_size, 0, sig_len)) {
        return JO_SIG_OUT_OF_RANGE;
    }
    return dsa_ctx_verify(ctx, sig, sig_len, rnd_src);
}
