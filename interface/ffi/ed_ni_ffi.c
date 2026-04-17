//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <stdint.h>
#include <stdio.h>
#include <openssl/crypto.h>

#include "../util/key_spec.h"
#include "../util/edec.h"
#include "../util/bc_err_codes.h"
#include "types.h"
#include "../util/jo_assert.h"

key_spec *EDDSA_generateKeyPair(int32_t type, int32_t *ret_val, void *rnd_src) {
    *ret_val = JO_FAIL;

    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    key_spec *spec = OPENSSL_zalloc(sizeof(key_spec));

    jo_assert(spec != NULL);

    *ret_val = edec_generate_key(spec, type, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

    return spec;
}


int32_t EDDSA_getPublicKey(key_spec *kp, uint8_t *output, const size_t output_len) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    ret_val = edec_get_public_encoded(kp, output, output_len);

exit:
    return ret_val;
}

int32_t EDDSA_getPrivateKey(key_spec *kp, uint8_t *output, const size_t output_len) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    ret_val = edec_get_private_encoded(kp, output, output_len);

exit:
    return ret_val;
}


int32_t EDDSA_decodePublicKey(key_spec *key_spec,
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
    ret_val = edec_decode_public_key(key_spec, key_type, start, in_len);


exit:
    return ret_val;
}


int32_t EDDSA_decodePrivateKey(key_spec *key_spec, int32_t key_type, uint8_t *input, size_t input_size, int32_t in_off,
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
    ret_val = edec_decode_private_key(key_spec, key_type, start, in_len);


exit:
    return ret_val;
}


void EDDSA_disposeSigner(edec_ctx *ctx) {
    edec_ctx_destroy(ctx);
}


edec_ctx *EDDSA_allocateSigner(int *err) {
    return edec_ctx_create(err);
}


int32_t EDDSA_initVerifier(edec_ctx *ctx,
                           key_spec *kp,
                           const char *name,
                           int name_len,
                           const uint8_t *context,
                           const size_t context_size,
                           int32_t context_len) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (context != NULL) {
        if ((size_t) context_len > context_size) {
            ret_val = JO_CONTEXT_LEN_PAST_END;
            goto exit;
        }
    }

    ret_val = edec_ctx_init_verify(ctx, kp, name, name_len, context, context_len);


exit:
    return ret_val;
}

int32_t EDDSA_initSign(edec_ctx *ctx,
                       key_spec *kp,
                       const char *name,
                       int name_len,
                       const uint8_t *context,
                       const size_t context_size,
                       int32_t context_len,
                       void *rnd_src
) {
    jo_assert(ctx);
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (context != NULL) {
        if (context_len >= 0) {
            if ((size_t) context_len > context_size) {
                ret_val = JO_CONTEXT_LEN_PAST_END;
                goto exit;
            }
        }
    }

    ret_val = edec_ctx_init_sign(ctx, kp, name, name_len, context, context_len, rnd_src);

exit:
    return ret_val;
}

int32_t EDDSA_update(edec_ctx *ctx, const uint8_t *input, const size_t input_size, const int32_t in_off,
                     const int32_t in_len) {
    jo_assert(ctx);
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
    ret_code = edec_ctx_update(ctx, in, in_len);

exit:
    return ret_code;
}


int32_t EDDSA_sign(
    edec_ctx *ctx,
    const uint8_t *output,
    const size_t output_size,
    const int32_t out_off,
    void *rnd_src) {
    jo_assert(ctx);
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

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

    ret_val = edec_ctx_sign(ctx, output_data, out_len, rnd_src);

exit:
    return ret_val;
}

int32_t EDDSA_verify(
    edec_ctx *ctx,
    const uint8_t *sig,
    const size_t sig_size,
    const int32_t sig_len) {
    jo_assert(ctx);
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

    ret_val = edec_ctx_verify(ctx, sig, sig_len);

exit:
    return ret_val;
}
