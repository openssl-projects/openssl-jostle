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
#include "../util/xec.h"
#include "types.h"

/*
 * FFI bridge for X25519 / X448 key generation. Symbol prefixed Jo* to
 * avoid clashing with any libcrypto export. Returns identical error codes
 * to the JNI bridge (xec_ni_jni.c) for identical inputs. The kex path is
 * shared with EC (JoEC_* in ec_ni_ffi.c) — XEC adds only keygen.
 */
key_spec *JoXEC_generateKeyPair(const char *name,
                                int32_t *ret_val,
                                void *rnd_src) {
    jo_assert(ret_val != NULL);
    *ret_val = JO_FAIL;

    if (name == NULL) {
        *ret_val = JO_NAME_IS_NULL;
        return NULL;
    }
    if (rnd_src == NULL) {
        *ret_val = JO_RAND_NO_RAND_UP_CALL;
        return NULL;
    }

    key_spec *spec = create_spec();
    *ret_val = xec_generate_key(spec, name, rnd_src);

    if (*ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }
    return spec;
}
