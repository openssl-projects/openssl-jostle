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

int rand_up_call_next_bytes(void *rnd_up_call, unsigned char *out, size_t out_len,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *adin, size_t adin_len) {
    (void) (adin); // unused
    (void) (adin_len); // unused


    if (rnd_up_call == NULL) {
        ERR_add_error_txt(":", "rnd_up_call was null in rand_up_call_next_bytes (FFI)");
        return JO_OPENSSL_ERROR;
    }

    if (out_len > INT_MAX) {
        ERR_add_error_txt(":", "out_len > INT_MAX");
        return JO_OPENSSL_ERROR;
    }

    if (strength > INT_MAX) {
        ERR_add_error_txt(":", "strength > INT_MAX");
        return JO_OPENSSL_ERROR;
    }

    int32_t len = (int32_t) out_len;
    int32_t strn = (int32_t) strength;

    ffi_get_rand call = (ffi_get_rand) rnd_up_call;

    int rc = call(out, len, strn, prediction_resistance);
    if (rc >= 0 && rc < len) {
        rc = JO_RAND_UP_SHORT_RESULT;
    }


    return rc;
}
