//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/rand.h"

int32_t JoRand_randomBytes(uint8_t *output, size_t output_size, int32_t output_len, int32_t strength) {
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    if (output_len < 0) {
        return JO_OUTPUT_LEN_IS_NEGATIVE;
    }

    if (strength < 0) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    if (output_len == 0) {
        return JO_SUCCESS;
    }

    if (!check_in_range(output_size, 0, (size_t) output_len)) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    return rand_random_bytes(output, output_len, strength);
}

int32_t JoRand_instantiate(int32_t strength, uint8_t prediction_resistant) {
    if (strength < 0) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    return rand_instantiate(strength, prediction_resistant != 0);
}

int32_t JoRand_reseed(int32_t strength, uint8_t prediction_resistant) {
    if (strength < 0) {
        return JO_RAND_INSUFFICIENT_STRENGTH;
    }

    return rand_reseed(strength, prediction_resistant != 0);
}
