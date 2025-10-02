//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/crypto.h>

#include "../util/key_spec.h"
#include "../util/mlkem.h"
#include "../util/bc_err_codes.h"
#include "types.h"

key_spec *MLKEM_generateKeyPair(int32_t type, int32_t *ret_val) {
    *ret_val = JO_FAIL;

    key_spec *spec = OPENSSL_zalloc(sizeof(key_spec));

    assert(spec != NULL);

    *ret_val = mlkem_generate_key_pair(spec, type, NULL, 0);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

    return spec;
}


key_spec *MLKEM_generateKeyPairSeed(int32_t type, int32_t *ret_val, uint8_t *seed, size_t seed_size,
                                      int32_t seed_len) {
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

    if ((size_t) seed_len > seed_size) {
        // seed_len asserted non-negative by this point

        *ret_val = JO_INVALID_SEED_LEN_OUT_OF_RANGE;
        goto exit;
    }

    *ret_val = mlkem_generate_key_pair(spec, type, seed, seed_len);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    return spec;
}

int32_t MLKEM_getPublicKey(key_spec *kp, uint8_t *output, const size_t output_len) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    ret_val = mlkem_get_public_encoded(kp, output, output_len);

exit:
    return ret_val;
}

int32_t MLKEM_getPrivateKey(key_spec *kp, uint8_t *output, const size_t output_len) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    ret_val = mlkem_get_private_encoded(kp, output, output_len);

exit:
    return ret_val;
}

int32_t MLKEM_getSeed(key_spec *kp, uint8_t *output, const size_t output_len) {
    int32_t ret_val = JO_FAIL;

    if (kp == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (kp->key == NULL) {
        ret_val = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    ret_val = mlkem_get_private_seed(kp, output, output_len);

    exit:
        return ret_val;
}


int32_t MLKEM_decodePublicKey(key_spec *key_spec,
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

//    key_spec->type = key_type;

    uint8_t *start = input + in_off;
    ret_val = mlkem_decode_public_key(key_spec, key_type, start, in_len);


    exit:
        return ret_val;
}

int32_t MLKEM_decodePrivateKey(key_spec *key_spec, int32_t key_type, uint8_t *input, size_t input_size,
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

   // key_spec->type = key_type;

    uint8_t *start = input + in_off;
    ret_val = mlkem_decode_private_key(key_spec, key_type, start, in_len);


    exit:
        return ret_val;
}
