//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <stdint.h>
#include <openssl/crypto.h>

#include "../util/key_spec.h"
#include "../util/mlxkem.h"
#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "types.h"

key_spec *JoMLXKEM_generateKeyPair(int32_t type, int32_t *ret_val, void *rnd_src) {
    *ret_val = JO_FAIL;

    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    key_spec *spec = OPENSSL_zalloc(sizeof(key_spec));

    jo_assert(spec != NULL);

    *ret_val = mlxkem_generate_key_pair(spec, type, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        return NULL;
    }

    return spec;
}

int32_t JoMLXKEM_getPublicKey(key_spec *kp, uint8_t *output, const size_t output_len) {
    if (kp == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return mlxkem_get_public_encoded(kp, output, output_len);
}

int32_t JoMLXKEM_getPrivateKey(key_spec *kp, uint8_t *output, const size_t output_len) {
    if (kp == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return mlxkem_get_private_encoded(kp, output, output_len);
}

/*
 * Shared body for the two decode entry points. Identical validation set to the
 * JNI twin, and returning identical codes for identical inputs - the two
 * bridges must not disagree.
 *
 * FFI receives the full array size as a parameter so it can do its own range
 * check; JNI derives it from the byte-array ctx.
 */
static int32_t mlxkem_decode_ffi(key_spec *key_spec, int32_t key_type, uint8_t *input,
                                 size_t input_size, int32_t in_off, int32_t in_len,
                                 int is_private) {
    if (key_spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
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

    uint8_t *start = input + in_off;
    return is_private
               ? mlxkem_decode_private_key(key_spec, key_type, start, (size_t) in_len)
               : mlxkem_decode_public_key(key_spec, key_type, start, (size_t) in_len);
}

int32_t JoMLXKEM_decodePublicKey(key_spec *key_spec, int32_t key_type, uint8_t *input,
                                 size_t input_size, int32_t in_off, int32_t in_len) {
    return mlxkem_decode_ffi(key_spec, key_type, input, input_size, in_off, in_len, 0);
}

int32_t JoMLXKEM_decodePrivateKey(key_spec *key_spec, int32_t key_type, uint8_t *input,
                                  size_t input_size, int32_t in_off, int32_t in_len) {
    return mlxkem_decode_ffi(key_spec, key_type, input, input_size, in_off, in_len, 1);
}
