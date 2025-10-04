//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/crypto.h>

#include "../util/key_spec.h"
#include "../util/mldsa.h"
#include "../util/bc_err_codes.h"
#include "types.h"

key_spec *MLDSA_generateKeyPair(int32_t type, int32_t *ret_val) {
    *ret_val = JO_FAIL;

    key_spec *spec = OPENSSL_zalloc(sizeof(key_spec));

    assert(spec != NULL);

    *ret_val = mldsa_generate_key_pair(spec, type, NULL, 0);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

    return spec;
}


key_spec *MLDSA_generateKeyPairSeed(int32_t type, int32_t *ret_val, uint8_t *seed, size_t seed_size, int32_t seed_len) {
    *ret_val = JO_FAIL;

    key_spec *spec = OPENSSL_zalloc(sizeof(key_spec));
    assert(spec != NULL);


    if (seed == NULL) {
        *ret_val = JO_SEED_IS_NULL;
        goto exit;
    }

    if (seed_len < 0) {
        *ret_val = JO_SEED_LEN_IS_NEGATIVE;
        goto exit;
    }

    if ((size_t)seed_len > seed_size) { // seed_len asserted non-negative by this point

        *ret_val = JO_INVALID_SEED_LEN_OUT_OF_RANGE;
        goto exit;
    }

    *ret_val = mldsa_generate_key_pair(spec, type, seed, seed_len);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    return spec;
}


int32_t MLDSA_getPublicKey(key_spec *kp, uint8_t *output, const size_t output_len) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    ret_val = mldsa_get_public_encoded(kp, output, output_len);

exit:
    return ret_val;
}

int32_t MLDSA_getPrivateKey(key_spec *kp, uint8_t *output, const size_t output_len) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    ret_val = mldsa_get_private_encoded(kp, output, output_len);

exit:
    return ret_val;
}

int32_t MLDSA_getSeed(key_spec *kp, uint8_t *output, const size_t output_len) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (kp->key == NULL) {
        ret_val = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    ret_val = mldsa_get_private_seed(kp, output, output_len);

exit:
    return ret_val;
}

int32_t MLDSA_decodePublicKey(key_spec *key_spec,
                              int32_t key_type,
                              uint8_t *input,
                              size_t input_size,
                              int32_t in_off,
                              int32_t in_len) {
    int32_t ret_val = JO_FAIL;

    if (key_spec == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (input == NULL) {
        ret_val = JO_INPUT_IS_NULL;;
        goto exit;
    }

    if (in_off < 0) {
        ret_val = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(input_size, in_off, in_len)) {
        ret_val = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

  //  key_spec->type = key_type;

    uint8_t *start = input + in_off;
    ret_val = mldsa_decode_public_key(key_spec,key_type, start, in_len);


exit:
    return ret_val;
}


int32_t MLDSA_decodePrivateKey(key_spec *key_spec, int32_t key_type, uint8_t *input, size_t input_size, int32_t in_off,
                               int32_t in_len) {
    int32_t ret_val = JO_FAIL;

    if (key_spec == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (input == NULL) {
        ret_val = JO_INPUT_IS_NULL;;
        goto exit;
    }

    if (in_off < 0) {
        ret_val = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(input_size, in_off, in_len)) {
        ret_val = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }


    uint8_t *start = input + in_off;
    ret_val = mldsa_decode_private_key(key_spec, key_type, start, in_len);


exit:
    return ret_val;
}


void MLDSA_disposeSigner(mldsa_ctx *ctx) {
    if (ctx == NULL) {
        mldsa_ctx_destroy(ctx);
    }
}


mldsa_ctx *MLDSA_allocateSigner(void) {
    return mldsa_ctx_create();
}


int32_t MLDSA_initVerifier(mldsa_ctx *ctx,
                           key_spec *kp,
                           const uint8_t *context,
                           const size_t context_size,
                           int32_t context_len,
                           int32_t mu_mode) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (context_len >= 0) {
        if (context == NULL) {
            ret_val = JO_CONTEXT_BYTES_NULL;
            goto exit;
        }

        if ((size_t) context_len > context_size) {
            ret_val = JO_CONTEXT_LEN_PAST_END;
            goto exit;
        }
    }

    ret_val = mldsa_ctx_init_verify(ctx, kp, context, context_len, mu_mode);


exit:
    return ret_val;
}

int32_t MLDSA_initSign(mldsa_ctx *ctx,
                       key_spec *kp,
                       const uint8_t *context,
                       const size_t context_size,
                       int32_t context_len,
                       int32_t mu_mode
) {
    assert(ctx);
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (context_len >= 0) {
        if ((size_t) context_len > context_size) {
            ret_val = JO_CONTEXT_LEN_PAST_END;
            goto exit;
        }
    }

    ret_val = mldsa_ctx_init_sign(ctx, kp, context, context_len, mu_mode);

exit:
    return ret_val;
}

int32_t MLDSA_update(mldsa_ctx *ctx, const uint8_t *input, const size_t input_size, const int32_t in_off,
                     const int32_t in_len) {
    assert(ctx);
    int32_t ret_code = JO_FAIL;

    if (input == NULL) {
        ret_code = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (in_len < 0) {
        ret_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (in_off < 0) {
        ret_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(input_size, in_off, in_len)) {
        ret_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    const uint8_t *in = input + in_off;
    ret_code = mldsa_update(ctx, in, in_len);

exit:
    return ret_code;
}


int32_t MLDSA_sign(mldsa_ctx *ctx, const uint8_t *output, const size_t output_size, const int32_t out_off) {
    assert(ctx);
    int32_t ret_val = JO_FAIL;
    size_t out_len = 0;


    if (out_off < 0) {
        ret_val = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    out_len = output_size - (size_t) out_off;

    if (!check_in_range(output_size, out_off, out_len)) {
        ret_val = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    const uint8_t *output_data = output + (size_t) out_off;

    ret_val = mldsa_ctx_sign(ctx, output_data, out_len);

exit:
    return ret_val;
}

int32_t MLDSA_verify(
    mldsa_ctx *ctx,
    const uint8_t *sig,
    const size_t sig_size,
    const int32_t sig_len) {
    assert(ctx);
    int32_t ret_val = JO_FAIL;


    if (sig == NULL) {
        ret_val = JO_SIG_IS_NULL;
        goto exit;
    }

    if (sig_len < 0) {
        ret_val = JO_SIG_LENGTH_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(sig_size, 0, sig_len)) {
        ret_val = JO_SIG_OUT_OF_RANGE;
        goto exit;
    }

    ret_val = mldsa_ctx_verify(ctx, sig, sig_len);

exit:
    return ret_val;
}
