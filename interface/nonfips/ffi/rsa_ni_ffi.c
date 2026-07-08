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
#include "../util/rsa.h"
#include "types.h"


// =============================================================
// Lifecycle
// =============================================================

rsa_ctx *JoRSA_allocateSigner(int32_t *err) {
    return rsa_ctx_create(err);
}

void JoRSA_disposeSigner(rsa_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    rsa_ctx_destroy(ctx);
}


// =============================================================
// Key generation
// =============================================================

key_spec *JoRSA_generateKeyPair(int32_t bits,
                              uint8_t *pubexp, size_t pubexp_len,
                              int32_t *ret_val,
                              void *rnd_src) {
    // ret_val is the out-channel for the error code; dereferencing
    // without a null check is the classic out-parameter bug.
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }
    if (pubexp == NULL) {
        *ret_val = JO_RSA_PUB_EXP_IS_NULL;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = rsa_generate_key(spec, bits, pubexp, pubexp_len, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Component-based decoding
// =============================================================

int32_t JoRSA_decodePublicComponents(key_spec *spec,
                                   uint8_t *n, size_t n_len,
                                   uint8_t *e, size_t e_len) {
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (n == NULL) {
        return JO_RSA_MODULUS_IS_NULL;
    }
    if (e == NULL) {
        return JO_RSA_PUB_EXP_IS_NULL;
    }
    return rsa_decode_public_components(spec, n, n_len, e, e_len);
}


int32_t JoRSA_decodePrivateComponents(key_spec *spec,
                                    uint8_t *n, size_t n_len,
                                    uint8_t *e, size_t e_len,
                                    uint8_t *d, size_t d_len) {
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (n == NULL) {
        return JO_RSA_MODULUS_IS_NULL;
    }
    if (e == NULL) {
        return JO_RSA_PUB_EXP_IS_NULL;
    }
    if (d == NULL) {
        return JO_RSA_PRIV_EXP_IS_NULL;
    }
    return rsa_decode_private_components(spec, n, n_len, e, e_len, d, d_len);
}


int32_t JoRSA_decodePrivateComponentsCrt(key_spec *spec,
                                       uint8_t *n,    size_t n_len,
                                       uint8_t *e,    size_t e_len,
                                       uint8_t *d,    size_t d_len,
                                       uint8_t *p,    size_t p_len,
                                       uint8_t *q,    size_t q_len,
                                       uint8_t *dp,   size_t dp_len,
                                       uint8_t *dq,   size_t dq_len,
                                       uint8_t *qinv, size_t qinv_len) {
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (n == NULL) {
        return JO_RSA_MODULUS_IS_NULL;
    }
    if (e == NULL) {
        return JO_RSA_PUB_EXP_IS_NULL;
    }
    if (d == NULL) {
        return JO_RSA_PRIV_EXP_IS_NULL;
    }
    if (p == NULL) {
        return JO_RSA_PRIME_P_IS_NULL;
    }
    if (q == NULL) {
        return JO_RSA_PRIME_Q_IS_NULL;
    }
    if (dp == NULL) {
        return JO_RSA_PRIME_EXP_P_IS_NULL;
    }
    if (dq == NULL) {
        return JO_RSA_PRIME_EXP_Q_IS_NULL;
    }
    if (qinv == NULL) {
        return JO_RSA_CRT_COEFFICIENT_IS_NULL;
    }
    return rsa_decode_private_components_crt(spec,
                                             n, n_len, e, e_len, d, d_len,
                                             p, p_len, q, q_len,
                                             dp, dp_len, dq, dq_len,
                                             qinv, qinv_len);
}


// =============================================================
// Component getter
// =============================================================

int32_t JoRSA_getComponent(key_spec *spec, int32_t component,
                         uint8_t *out, size_t out_len) {
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return rsa_get_component(spec, component, out, out_len);
}


// =============================================================
// Sign / verify session
// =============================================================

int32_t JoRSA_initSign(rsa_ctx *ctx, key_spec *key,
                     const char *digest_name,
                     int32_t padding_mode,
                     const char *mgf1_md_name,
                     int32_t salt_len,
                     void *rnd_src) {
    jo_assert(ctx != NULL);

    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (digest_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    return rsa_ctx_init_sign(ctx, key, digest_name,
                             padding_mode, mgf1_md_name, salt_len,
                             rnd_src);
}


int32_t JoRSA_initVerify(rsa_ctx *ctx, key_spec *key,
                       const char *digest_name,
                       int32_t padding_mode,
                       const char *mgf1_md_name,
                       int32_t salt_len) {
    jo_assert(ctx != NULL);

    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (digest_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    return rsa_ctx_init_verify(ctx, key, digest_name,
                               padding_mode, mgf1_md_name, salt_len);
}


int32_t JoRSA_update(rsa_ctx *ctx,
                   uint8_t *input, size_t input_size,
                   int32_t in_off, int32_t in_len) {
    jo_assert(ctx != NULL);

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

    return rsa_ctx_update(ctx, input + in_off, in_len);
}


int32_t JoRSA_sign(rsa_ctx *ctx,
                 uint8_t *output, size_t output_size,
                 int32_t out_off,
                 void *rnd_src) {
    jo_assert(ctx != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (output == NULL) {
        // Caller wants required length.
        return rsa_ctx_sign(ctx, NULL, 0, rnd_src);
    }
    if (out_off < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }
    if ((size_t) out_off > output_size) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }
    size_t out_len = output_size - (size_t) out_off;

    return rsa_ctx_sign(ctx, output + (size_t) out_off, out_len, rnd_src);
}


int32_t JoRSA_verify(rsa_ctx *ctx,
                   uint8_t *sig, size_t sig_size,
                   int32_t sig_len) {
    jo_assert(ctx != NULL);

    if (sig == NULL) {
        return JO_SIG_IS_NULL;
    }
    if (sig_len < 0) {
        return JO_SIG_LENGTH_IS_NEGATIVE;
    }
    if (!check_in_range(sig_size, 0, sig_len)) {
        return JO_SIG_OUT_OF_RANGE;
    }
    return rsa_ctx_verify(ctx, sig, sig_len);
}
