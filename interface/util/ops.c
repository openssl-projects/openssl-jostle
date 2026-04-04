//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <stdint.h>
#include "ops.h"

#include <openssl/rand.h>


#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"


#ifdef JOSTLE_OPS

static uint32_t OPS_ARR[OPS_MAX_TEST] = {0};

bool is_ops_set(const uint32_t index) {
    jo_assert(index < OPS_MAX_TEST);
    return OPS_ARR[index] != 0;
}

void set_ops_test(const uint32_t index, const uint32_t value) {
    jo_assert(index < OPS_MAX_TEST);
    OPS_ARR[index] = value;
}

int OPS_GetRandomBytes(uint8_t *buf, size_t len, int32_t strength, int32_t pred, void *rnd_src) {
    // TODO work out how to pass up the need for prediction resistance
    (void) (pred);


    rand_set_java_srand_call(rnd_src);

    EVP_RAND_CTX *ctx = RAND_get0_public(get_global_jostle_ossl_lib_ctx());
    return EVP_RAND_generate(ctx, buf, len, strength, pred,NULL, 0);
}


#endif
