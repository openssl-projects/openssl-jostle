//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//

//
// Created by MEGAN WOODS on 28/3/2026.
//

#include "rand_upcall_ffi.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/err.h>

#include "../util/bc_err_codes.h"
#include "../util/ops.h"

int rand_up_call_next_bytes(void *rnd_up_call, unsigned char *out, size_t out_len,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *adin, size_t adin_len) {
    (void) (adin); // unused
    (void) (adin_len); // unused


    if (OPS_RAND_UP_CALL_NULL rnd_up_call == NULL) {
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "handler fail, rand up call is null: %d",
                       JO_RAND_NO_RAND_UP_CALL);
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (OPS_INT32_OVERFLOW_1 out_len > INT_MAX) {
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "out_len > INT_MAX: %d", JO_OPENSSL_ERROR);
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_2 strength > INT_MAX) {
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "strength > INT_MAX: %d", JO_OPENSSL_ERROR);
        return JO_OPENSSL_ERROR;
    }

    int32_t len = (int32_t) out_len;
    int32_t strn = (int32_t) strength;


    int rc = ((ffi_get_rand) rnd_up_call)(out, len, strn, prediction_resistance);
    if (OPS_SHORT_SIZE_1 rc >= 0 && rc < len) {
        rc = JO_RAND_UP_SHORT_RESULT;
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "handler fail, short output: %d", rc);
    }


    return rc;
}
