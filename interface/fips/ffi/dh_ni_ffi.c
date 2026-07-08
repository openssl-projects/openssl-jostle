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
#include "../util/dh.h"
#include "types.h"


/*
 * Length validation for an FFC component buffer (p / g / x / y), run
 * AFTER the null checks so the check order matches the JNI bridge —
 * both bridges MUST return identical codes for identical inputs,
 * including the combined edge cases (dsa_ni_ffi.c rationale).
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
// Group introspection
// =============================================================

int32_t JoDH_groupSupported(const char *group_name) {
    if (group_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    return dh_group_supported(group_name);
}


// =============================================================
// Key generation (named group)
// =============================================================

key_spec *JoDH_generateKeyPairByGroup(const char *group_name,
                                      int32_t *ret_val,
                                      void *rnd_src) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (group_name == NULL) {
        *ret_val = JO_NAME_IS_NULL;
        return NULL;
    }
    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dh_generate_key_by_group(spec, group_name, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Domain-parameter generation / construction
// =============================================================

key_spec *JoDH_generateParameters(int32_t p_bits,
                                  int32_t *ret_val,
                                  void *rnd_src) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    // Bridge backstop on the bit size — the util layer's precondition
    // is bits > 0 (the Java SPI applies the 512..8192 policy bounds).
    if (p_bits <= 0) {
        *ret_val = JO_DH_BITS_OUT_OF_RANGE;
        return NULL;
    }
    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dh_generate_parameters(spec, p_bits, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


key_spec *JoDH_makeParamsFromComponents(uint8_t *p, size_t p_size,
                                        uint8_t *g, size_t g_size,
                                        int32_t *ret_val) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (p == NULL || g == NULL) {
        *ret_val = JO_INPUT_IS_NULL;
        return NULL;
    }

    int32_t check;
    if (JO_SUCCESS != (check = check_component_len(p_size))
        || JO_SUCCESS != (check = check_component_len(g_size))) {
        *ret_val = check;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dh_make_params_from_components(spec, p, p_size, g, g_size);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Key generation (from established parameters)
// =============================================================

key_spec *JoDH_generateKeyPair(key_spec *params,
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
    *ret_val = dh_generate_key(spec, params, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Construct EVP_PKEY from raw components
// =============================================================

key_spec *JoDH_makePrivateFromComponents(uint8_t *p, size_t p_size,
                                         uint8_t *g, size_t g_size,
                                         uint8_t *x, size_t x_size,
                                         int32_t *ret_val,
                                         void *rnd_src) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (p == NULL || g == NULL || x == NULL) {
        *ret_val = JO_INPUT_IS_NULL;
        return NULL;
    }
    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    int32_t check;
    if (JO_SUCCESS != (check = check_component_len(p_size))
        || JO_SUCCESS != (check = check_component_len(g_size))
        || JO_SUCCESS != (check = check_component_len(x_size))) {
        *ret_val = check;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dh_make_private_from_components(spec, p, p_size,
                                               g, g_size, x, x_size,
                                               rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


key_spec *JoDH_makePublicFromComponents(uint8_t *p, size_t p_size,
                                        uint8_t *g, size_t g_size,
                                        uint8_t *y, size_t y_size,
                                        int32_t *ret_val) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (p == NULL || g == NULL || y == NULL) {
        *ret_val = JO_INPUT_IS_NULL;
        return NULL;
    }

    int32_t check;
    if (JO_SUCCESS != (check = check_component_len(p_size))
        || JO_SUCCESS != (check = check_component_len(g_size))
        || JO_SUCCESS != (check = check_component_len(y_size))) {
        *ret_val = check;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = dh_make_public_from_components(spec, p, p_size,
                                              g, g_size, y, y_size);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}


// =============================================================
// Component getter
// =============================================================

int32_t JoDH_getComponent(key_spec *spec, int32_t component,
                          uint8_t *out, size_t out_len) {
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return dh_get_component(spec, component, out, out_len);
}


// =============================================================
// Key agreement
// =============================================================

dh_kex_ctx *JoDH_allocateKex(int32_t *err) {
    return dh_kex_create(err);
}

void JoDH_disposeKex(dh_kex_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    dh_kex_destroy(ctx);
}

int32_t JoDH_kexInit(dh_kex_ctx *ctx, key_spec *my_priv, void *rnd_src) {
    if (ctx == NULL) {
        return JO_KEX_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    if (my_priv == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return dh_kex_init(ctx, my_priv, rnd_src);
}

int32_t JoDH_kexSetPeer(dh_kex_ctx *ctx, key_spec *peer_pub,
                        void *rnd_src) {
    if (ctx == NULL) {
        return JO_KEX_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    if (peer_pub == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return dh_kex_set_peer(ctx, peer_pub, rnd_src);
}

int32_t JoDH_kexDerive(dh_kex_ctx *ctx,
                       uint8_t *out, size_t out_size,
                       int32_t out_off,
                       void *rnd_src) {
    if (ctx == NULL) {
        return JO_KEX_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (out == NULL) {
        return dh_kex_derive(ctx, NULL, 0, rnd_src);
    }
    if (out_off < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }
    if ((size_t) out_off > out_size) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }
    size_t out_len = out_size - (size_t) out_off;

    return dh_kex_derive(ctx, out + (size_t) out_off, out_len, rnd_src);
}
