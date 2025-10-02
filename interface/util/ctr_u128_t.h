//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

/* A 128 bit counter */

#ifndef COUNTER_H
#define COUNTER_H
#include <stdint.h>
#include <stdlib.h>

#define LOW 0
#define HIGH 1
#define COUNTER_SIZE 16

/*
 * 128 bit block counter implementation for 16 byte block ciphers.
 * This is to manage the IV for OpenSSLs ctr implementation.
 * Actual
 */
typedef struct ctr_u128_t {
    uint64_t mag[2]; /* actual block counter */
    size_t iv_len; /* bytes of IV supplied used to calculate limit for a given IV len */
    uint8_t original_counter[COUNTER_SIZE]; /*  Copy of original IV */
    uint64_t limit; /* max blocks for iv_len in [9,15] */
    int32_t rolled; /* Flag set -1, 0, 1 for underflow, ok, and overflow conditions */
} ctr_u128_t;

/*
 * Allocate a new ctr_u128_t
 */
ctr_u128_t *ctr_u128_new(void);

/*
 * Initialise the counter with an IV
 */
void counter_init(ctr_u128_t *counter, uint8_t *iv, size_t iv_len);


/*
 * Add high,low to the counter
 * Will set rolled flag to 1 to indicate 128b overflow
 */
void counter_add(ctr_u128_t *ctr, uint64_t high, uint64_t low);

/*
 * Subtract high,low from counter.
 * Will set the rolled flag to -1 to indicted underflow.
 */
void counter_sub(ctr_u128_t *ctr, uint64_t high, uint64_t low);

/*
 * Test counter validity.
 * Returns 1 if the counter is valid or zero if not.
 * A counter is valid if it has not rolled and is less than the limit if the limit > 0
 */
uint32_t counter_valid(ctr_u128_t *ctr);

/*
    Set the high and low u64 of the counter, and reset the rolled flag to zero.
    Does not validate seek location, users should call counter_valid.
*/
void counter_seek(ctr_u128_t *ctr, uint64_t high, uint64_t low);

/*
 * Reset the counter to its original state.
 */
void counter_reset(ctr_u128_t *ctr);


/*
 * Zero and free the counter.
 */
void counter_free(ctr_u128_t *ctr);


#endif //COUNTER_H
