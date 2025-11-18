//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "ctr_u128_t.h"
#include <assert.h>
#include <memory.h>
#include <stdio.h>
#include <openssl/crypto.h>



ctr_u128_t *ctr_u128_new(void) {
    ctr_u128_t *ctr = (ctr_u128_t *) OPENSSL_zalloc(sizeof(ctr_u128_t));
    assert(ctr != NULL);
    return ctr;
}

void counter_init(ctr_u128_t *ctr, uint8_t *iv, size_t iv_len) {
    assert(ctr != NULL);
    assert(iv_len <= COUNTER_SIZE);

    ctr->mag[0] = 0U;
    ctr->mag[1] = 0U;
    ctr->iv_len = iv_len;

    if (iv_len > 8 && iv_len < COUNTER_SIZE) {
        ctr->limit = 1ULL << (COUNTER_SIZE - iv_len) * 8;
    }

    memcpy(ctr->original_counter, iv, iv_len);
}

void counter_add(ctr_u128_t *ctr, uint64_t high, uint64_t low) {
    assert(ctr);

    uint64_t *mag = ctr->mag;
    const uint64_t h = ctr->mag[HIGH];
    const uint64_t l = ctr->mag[LOW];

    ctr->rolled = 0;

    mag[HIGH] = h + high + ((l + low) < l);
    mag[LOW] = l + low;

    if (mag[HIGH] == h) {
        if (mag[LOW] < l) {
            ctr->rolled = 1;
        }
    } else {
        if (mag[HIGH] < h) {
            ctr->rolled = 1;
        }
    }
}

void counter_sub(ctr_u128_t *ctr, uint64_t high, uint64_t low) {
    assert(ctr);

    const uint64_t h = ctr->mag[HIGH];
    const uint64_t l = ctr->mag[LOW];
    uint64_t *mag = ctr->mag;

    ctr->rolled = 0;
    mag[HIGH] = h - high - ((l - low) > l);
    mag[LOW] = l - low;

    if (mag[HIGH] == h) {
        if (mag[LOW] > l) {
            ctr->rolled = -1;
        }
    } else {
        if (mag[HIGH] > h) {
            ctr->rolled = -1;
        }
    }
}

uint32_t counter_valid(ctr_u128_t *ctr) {
    if (ctr->iv_len < 8) {
        return 0; // Invalid iv,
    }

    if (ctr->rolled != 0) {
        return 0; // either overflow or underflow is a fail
    }

    // Special case for 16 byte IVs.
    if (ctr->iv_len == 16) {
        return 1; /* no limit so return valid */
    }

    // Special case for 8 byte IVs.
    if (ctr->iv_len == 8 && ctr->mag[HIGH] == 0) {
        return 1;
    }

    //
    // For 9 to 15 byte IVs mag[HIGH] should always be zero
    //
    if (ctr->mag[HIGH] == 0 && ctr->mag[LOW] < ctr->limit) {
        return 1; /* less than limit */
    }

    /* Exceeded limit or overflowed into high  */
    return 0;
}


void counter_seek(ctr_u128_t *ctr, uint64_t high, uint64_t low) {
    assert(ctr);
    ctr->mag[HIGH] = high;
    ctr->mag[LOW] = low;
    ctr->rolled = 0;
}

void counter_reset(ctr_u128_t *ctr) {
    assert(ctr);
    ctr->rolled = 0;
    ctr->mag[HIGH] = 0U;
    ctr->mag[LOW] = 0U;
}

void counter_free(ctr_u128_t *ctr) {
    if (ctr != NULL) {
        OPENSSL_clear_free(ctr, sizeof(*ctr));
    }
}
