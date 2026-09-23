//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <stdint.h>
#include "ops.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>


#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"

#ifdef JOSTLE_OPS

static uint32_t OPS_ARR[OPS_MAX_TEST] = {0};

int is_ops_set(const uint32_t index) {
    jo_assert(index < OPS_MAX_TEST);
    return OPS_ARR[index];
}

void set_ops_test(const uint32_t index, const uint32_t value) {
    jo_assert(index < OPS_MAX_TEST);
    OPS_ARR[index] = value;
}

int OPS_GetRandomBytes(uint8_t *buf, size_t len, int32_t strength, int32_t pred, void *rnd_src) {
    // TODO work out how to pass up the need for prediction resistance
    (void) (pred);


    rand_set_java_srand_call(rnd_src);

    EVP_RAND_CTX *ctx = RAND_get0_public(get_global_jostle_fips_ossl_lib_ctx());
    // The generate call reads the thread-local up-call target; clear it
    // only after the draw completes.
    int ret = EVP_RAND_generate(ctx, buf, len, strength, pred, NULL, 0);
    rand_clear_java_srand_call();
    return ret;
}

int get_ops_test(const uint32_t index) {
    return OPS_ARR[index];
}

//
// Disposal ledger. Per-type counts of creates and destroys, per interface
// library. The lock is created once and passed on every CRYPTO_atomic_add:
// without native atomics the call falls back to it and returns 0 if it is
// NULL, which would silently drop a count, so the return is asserted.
//
static int ledger_created_counts[JO_LEDGER_TYPES] = {0};
static int ledger_destroyed_counts[JO_LEDGER_TYPES] = {0};
static CRYPTO_RWLOCK *ledger_lock = NULL;
static CRYPTO_ONCE ledger_once = CRYPTO_ONCE_STATIC_INIT;

static void ledger_init(void) {
    ledger_lock = CRYPTO_THREAD_lock_new();
}

static CRYPTO_RWLOCK *ledger_lock_get(void) {
    jo_assert(CRYPTO_THREAD_run_once(&ledger_once, ledger_init) == 1);
    jo_assert(ledger_lock != NULL);
    return ledger_lock;
}

static void ledger_add(int *slot, int amount) {
    int ret = 0;
    jo_assert(CRYPTO_atomic_add(slot, amount, &ret, ledger_lock_get()) == 1);
}

static int ledger_read(int *slot) {
    int ret = 0;
    jo_assert(CRYPTO_atomic_load_int(slot, &ret, ledger_lock_get()) == 1);
    return ret;
}

void ledger_created(int type) {
    jo_assert(type >= 0 && type < JO_LEDGER_TYPES);
    ledger_add(&ledger_created_counts[type], 1);
}

void ledger_destroyed(int type) {
    jo_assert(type >= 0 && type < JO_LEDGER_TYPES);
    ledger_add(&ledger_destroyed_counts[type], 1);
}

int ledger_get_created(int type) {
    jo_assert(type >= 0 && type < JO_LEDGER_TYPES);
    return ledger_read(&ledger_created_counts[type]);
}

int ledger_get_destroyed(int type) {
    jo_assert(type >= 0 && type < JO_LEDGER_TYPES);
    return ledger_read(&ledger_destroyed_counts[type]);
}

// Atomic per slot: each count is brought to zero through the same add the
// counters use, so a reset never races a concurrent count into a torn value.
void ledger_reset(void) {
    for (int t = 0; t < JO_LEDGER_TYPES; t++) {
        ledger_add(&ledger_created_counts[t], -ledger_read(&ledger_created_counts[t]));
        ledger_add(&ledger_destroyed_counts[t], -ledger_read(&ledger_destroyed_counts[t]));
    }
}


#endif
