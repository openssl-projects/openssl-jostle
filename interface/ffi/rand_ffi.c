//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/rand.h"

static int rand_strength_supported(int32_t strength) {
    return strength >= 0 && strength <= JO_RAND_MAX_STRENGTH;
}

JO_RAND_CTX *JoRand_createContext(int32_t strength, uint8_t prediction_resistant,
                                  uint8_t *personalization_string,
                                  size_t personalization_string_size,
                                  int32_t *err) {
    if (err == NULL) {
        return NULL;
    }

    if (!rand_strength_supported(strength)) {
        *err = JO_RAND_INSUFFICIENT_STRENGTH;
        return NULL;
    }

    if (personalization_string == NULL && personalization_string_size > 0) {
        *err = JO_INPUT_IS_NULL;
        return NULL;
    }

    return rand_ctx_create(strength, prediction_resistant != 0,
                           personalization_string, personalization_string_size,
                           err);
}

void JoRand_disposeContext(JO_RAND_CTX *ctx) {
    rand_ctx_destroy(ctx);
}

int32_t JoRand_contextRandomBytes(JO_RAND_CTX *ctx, uint8_t *output,
                                  size_t output_size, int32_t output_len,
                                  int32_t strength, uint8_t prediction_resistant,
                                  uint8_t *additional_input,
                                  size_t additional_input_size) {
    if (ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    if (output_len < 0) {
        return JO_OUTPUT_LEN_IS_NEGATIVE;
    }

    if (!rand_strength_supported(strength)) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    if (output_len == 0) {
        return JO_SUCCESS;
    }

    if (!check_in_range(output_size, 0, (size_t) output_len)) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    if (additional_input == NULL && additional_input_size > 0) {
        return JO_INPUT_IS_NULL;
    }

    return rand_ctx_random_bytes(ctx, output, output_len, strength,
                                 prediction_resistant != 0, additional_input,
                                 additional_input_size);
}

int32_t JoRand_contextReseed(JO_RAND_CTX *ctx, int32_t strength,
                             uint8_t prediction_resistant,
                             uint8_t *additional_input,
                             size_t additional_input_size) {
    if (ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (!rand_strength_supported(strength)) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    if (additional_input == NULL && additional_input_size > 0) {
        return JO_INPUT_IS_NULL;
    }

    return rand_ctx_reseed(ctx, strength, prediction_resistant != 0,
                           additional_input, additional_input_size);
}
