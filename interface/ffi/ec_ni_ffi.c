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
#include "../util/ec.h"
#include "types.h"


// =============================================================
// Curve introspection
// =============================================================

int32_t JoEC_curveSupported(const char *curve_name) {
    return ec_curve_supported(curve_name);
}


// =============================================================
// Key generation
// =============================================================

key_spec *JoEC_generateKeyPair(const char *curve_name,
                               int32_t *ret_val,
                               void *rnd_src) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (curve_name == NULL) {
        *ret_val = JO_NAME_IS_NULL;
        return NULL;
    }
    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = ec_generate_key(spec, curve_name, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Construct EVP_PKEY from raw private-key components
// =============================================================

key_spec *JoEC_makePrivateFromComponents(const char *curve_name,
                                         uint8_t *scalar, size_t scalar_size,
                                         int32_t *ret_val,
                                         void *rnd_src) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (curve_name == NULL) {
        *ret_val = JO_NAME_IS_NULL;
        return NULL;
    }
    if (scalar == NULL) {
        *ret_val = JO_INPUT_IS_NULL;
        return NULL;
    }
    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = ec_make_private_from_components(spec, curve_name,
                                               scalar, scalar_size,
                                               rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Component getter
// =============================================================

int32_t JoEC_getComponent(key_spec *spec, int32_t component,
                          uint8_t *out, size_t out_len) {
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return ec_get_component(spec, component, out, out_len);
}


// =============================================================
// Sign / verify session
// =============================================================

ec_ctx *JoEC_allocateSigner(int32_t *err) {
    return ec_ctx_create(err);
}

void JoEC_disposeSigner(ec_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    ec_ctx_destroy(ctx);
}

int32_t JoEC_initSign(ec_ctx *ctx, key_spec *key,
                     const char *digest_name,
                     void *rnd_src) {
    jo_assert(ctx != NULL);

    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (digest_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    return ec_ctx_init_sign(ctx, key, digest_name, rnd_src);
}

int32_t JoEC_initVerify(ec_ctx *ctx, key_spec *key,
                       const char *digest_name) {
    jo_assert(ctx != NULL);

    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (digest_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    return ec_ctx_init_verify(ctx, key, digest_name);
}

int32_t JoEC_update(ec_ctx *ctx,
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

    return ec_ctx_update(ctx, input + in_off, in_len);
}

int32_t JoEC_sign(ec_ctx *ctx,
                 uint8_t *output, size_t output_size,
                 int32_t out_off,
                 void *rnd_src) {
    jo_assert(ctx != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (output == NULL) {
        return ec_ctx_sign(ctx, NULL, 0, rnd_src);
    }
    if (out_off < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }
    if ((size_t) out_off > output_size) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }
    size_t out_len = output_size - (size_t) out_off;

    return ec_ctx_sign(ctx, output + (size_t) out_off, out_len, rnd_src);
}

int32_t JoEC_verify(ec_ctx *ctx,
                   uint8_t *sig, size_t sig_size,
                   int32_t sig_len,
                   void *rnd_src) {
    jo_assert(ctx != NULL);

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
    return ec_ctx_verify(ctx, sig, sig_len, rnd_src);
}


// =============================================================
// Key agreement (ECDH)
// =============================================================

ec_kex_ctx *JoEC_allocateKex(int32_t *err) {
    return ec_kex_create(err);
}

void JoEC_disposeKex(ec_kex_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    ec_kex_destroy(ctx);
}

int32_t JoEC_kexInit(ec_kex_ctx *ctx, key_spec *my_priv, void *rnd_src) {
    jo_assert(ctx != NULL);

    if (my_priv == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return ec_kex_init(ctx, my_priv, rnd_src);
}

int32_t JoEC_kexSetPeer(ec_kex_ctx *ctx, key_spec *peer_pub,
                        void *rnd_src) {
    jo_assert(ctx != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    if (peer_pub == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return ec_kex_set_peer(ctx, peer_pub, rnd_src);
}

int32_t JoEC_kexDerive(ec_kex_ctx *ctx,
                       uint8_t *out, size_t out_size,
                       int32_t out_off,
                       void *rnd_src) {
    jo_assert(ctx != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (out == NULL) {
        return ec_kex_derive(ctx, NULL, 0, rnd_src);
    }
    if (out_off < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }
    if ((size_t) out_off > out_size) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }
    size_t out_len = out_size - (size_t) out_off;

    return ec_kex_derive(ctx, out + (size_t) out_off, out_len, rnd_src);
}
