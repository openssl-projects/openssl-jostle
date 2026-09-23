//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef OPS_H
#define OPS_H
#include <stdbool.h>
#include <stdint.h>

// Disposal ledger types. One value per native context type a Java-held
// handle owns; created / destroyed are counted per type in operations-test
// builds. Append only: LedgerType.ordinal() in OperationsTestNI is the
// C value, the same trap as OpsTestFlag.
typedef enum jo_ledger_type {
    JO_LEDGER_MD_CTX = 0,
    JO_LEDGER_MAC_CTX,
    JO_LEDGER_BLOCK_CIPHER_CTX,
    JO_LEDGER_CCM_CTX,
    JO_LEDGER_KEY_SPEC,
    JO_LEDGER_ASN1_CTX,
    JO_LEDGER_RSA_CTX,
    JO_LEDGER_RSA_OAEP_CTX,
    JO_LEDGER_RSA_PKCS1_CTX,
    JO_LEDGER_DSA_CTX,
    JO_LEDGER_EC_CTX,
    JO_LEDGER_EC_KEX_CTX,
    JO_LEDGER_DH_KEX_CTX,
    JO_LEDGER_EDEC_CTX,
    JO_LEDGER_MLDSA_CTX,
    JO_LEDGER_SLH_DSA_CTX,
    JO_LEDGER_KS_CTX,
    JO_LEDGER_RAND_CTX,
    JO_LEDGER_X509_CERT,
    JO_LEDGER_X509_CRL,
    JO_LEDGER_TYPES
} jo_ledger_type;


// If we are doing a build that includes
// code for operations testing.

#ifdef JOSTLE_OPS
#include <stdlib.h>

#define OPS_ARR ops_test_array
#define OPS_INT32_OVERFLOW_1 is_ops_set(0) ||
#define OPS_INT32_OVERFLOW_2 is_ops_set(1) ||
#define OPS_INT32_OVERFLOW_3 is_ops_set(2) ||

#define OPS_FAILED_ACCESS_1 is_ops_set(3) ||
#define OPS_FAILED_ACCESS_2 is_ops_set(4) ||
#define OPS_FAILED_ACCESS_3 is_ops_set(5) ||
#define OPS_FAILED_ACCESS_4 is_ops_set(6) ||

#define OPS_POINTER_CHANGE is_ops_set(7) ||
#define OPS_OPENSSL_ERROR_1 is_ops_set(8) ||
#define OPS_OPENSSL_ERROR_2 is_ops_set(9) ||
#define OPS_OPENSSL_ERROR_3 is_ops_set(10) ||
#define OPS_OPENSSL_ERROR_4 is_ops_set(11) ||
#define OPS_OPENSSL_ERROR_5 is_ops_set(12) ||
#define OPS_OPENSSL_ERROR_6 is_ops_set(13) ||

#define OPS_LEN_CHANGE_1 is_ops_set(14) ||

#define OPS_FAILED_CREATE_1 is_ops_set(15) ||
#define OPS_FAILED_CREATE_2 is_ops_set(16) ||

#define OPS_FAILED_INIT_1 is_ops_set(17) ||
#define OPS_FAILED_INIT_2 is_ops_set(18) ||

#define OPS_FAILED_SET_1 is_ops_set(19) ||
#define OPS_FAILED_SET_2 is_ops_set(20) ||

#define OPS_THREAD_ATTACH_1 is_ops_set(21) ||
#define OPS_JNI_FAIL_CREATE_1  is_ops_set(22) ||
#define OPS_SHORT_SIZE_1 is_ops_set(23) ||
#define OPS_RAND_UP_CALL_NULL is_ops_set(24) ||

#define OPS_ALTERNATE_1 !is_ops_set(25) &&
#define OPS_ALTERNATE_2 !is_ops_set(26) &&
#define OPS_ALTERNATE_3 !is_ops_set(27) &&

#define OPS_OPENSSL_ERROR_7  is_ops_set(28) ||
#define OPS_OPENSSL_ERROR_8  is_ops_set(29) ||
#define OPS_OPENSSL_ERROR_9  is_ops_set(30) ||
#define OPS_OPENSSL_ERROR_10 is_ops_set(31) ||
#define OPS_OPENSSL_ERROR_11 is_ops_set(32) ||
#define OPS_OPENSSL_ERROR_12 is_ops_set(33) ||

// Slot index must match OpsTestFlag.ordinal() in OperationsTestNI — new
// flags are appended, never inserted next to their family.
#define OPS_FAILED_ACCESS_5 is_ops_set(34) ||
#define OPS_ALTERNATE_4 !is_ops_set(35) &&
#define OPS_FAILED_ACCESS_6 is_ops_set(36) ||
#define OPS_ALTERNATE_5 !is_ops_set(37) &&
#define OPS_FAILED_ACCESS_7 is_ops_set(38) ||
#define OPS_FAILED_ACCESS_8 is_ops_set(39) ||
#define OPS_FAILED_ACCESS_9 is_ops_set(40) ||
#define OPS_LEDGER_SKIP_FREE_1 is_ops_set(41) ||

#define OPS_MAX_TEST 42

// Per-flag offset macros. Pairs with OPS_OPENSSL_ERROR_N (same suffix).
// Expansion includes the leading "+" so non-OPS builds drop entirely.
//   OPS build:  + (is_ops_set(N) ? -(x) : 0)
//   non-OPS:    (empty)
// Usage:
//   if (OPS_OPENSSL_ERROR_3 ctx == NULL) {
//       ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(2100);
//       goto exit;
//   }
// OPS flag set:    ret_code = JO_OPENSSL_ERROR - 2100  (test sees -2102).
// Real failure:    ret_code = JO_OPENSSL_ERROR        (plain -2).
// Non-OPS build:   ret_code = JO_OPENSSL_ERROR        (no "+ 0" residue).
#define OPS_OFFSET_OPENSSL_ERROR_1(x)  + (is_ops_set(8)  ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_2(x)  + (is_ops_set(9)  ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_3(x)  + (is_ops_set(10) ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_4(x)  + (is_ops_set(11) ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_5(x)  + (is_ops_set(12) ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_6(x)  + (is_ops_set(13) ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_7(x)  + (is_ops_set(28) ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_8(x)  + (is_ops_set(29) ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_9(x)  + (is_ops_set(30) ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_10(x) + (is_ops_set(31) ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_11(x) + (is_ops_set(32) ? -(x) : 0)
#define OPS_OFFSET_OPENSSL_ERROR_12(x) + (is_ops_set(33) ? -(x) : 0)

// Same shape, other OPS flag families.
#define OPS_OFFSET_FAILED_CREATE_1(x)  + (is_ops_set(15) ? -(x) : 0)
#define OPS_OFFSET_FAILED_CREATE_2(x)  + (is_ops_set(16) ? -(x) : 0)
#define OPS_OFFSET_FAILED_INIT_1(x)    + (is_ops_set(17) ? -(x) : 0)
#define OPS_OFFSET_FAILED_INIT_2(x)    + (is_ops_set(18) ? -(x) : 0)
#define OPS_OFFSET_FAILED_SET_1(x)     + (is_ops_set(19) ? -(x) : 0)
#define OPS_OFFSET_FAILED_SET_2(x)     + (is_ops_set(20) ? -(x) : 0)
#define OPS_OFFSET_LEN_CHANGE_1(x)     + (is_ops_set(14) ? -(x) : 0)
#define OPS_OFFSET_POINTER_CHANGE(x)   + (is_ops_set(7)  ? -(x) : 0)
#define OPS_OFFSET_SHORT_SIZE_1(x)     + (is_ops_set(23) ? -(x) : 0)
#define OPS_OFFSET_THREAD_ATTACH_1(x)  + (is_ops_set(21) ? -(x) : 0)
#define OPS_OFFSET_JNI_FAIL_CREATE_1(x) + (is_ops_set(22) ? -(x) : 0)

int is_ops_set(const uint32_t index);

void set_ops_test(const uint32_t index, const uint32_t value);

int OPS_GetRandomBytes(uint8_t *buf, size_t len, int32_t strength, int32_t pred, void * rnd_src);

int get_ops_test(const uint32_t index);

// Disposal ledger: JO_LEDGER_CREATED at every success return of a create,
// JO_LEDGER_DESTROYED after the NULL check of every destroy. Counted with
// CRYPTO_atomic_add under a ledger-owned lock; a failed add aborts.
#define JO_LEDGER_CREATED(t) ledger_created(t)
#define JO_LEDGER_DESTROYED(t) ledger_destroyed(t)

void ledger_created(int type);

void ledger_destroyed(int type);

void ledger_reset(void);

int ledger_get_created(int type);

int ledger_get_destroyed(int type);

#endif

#ifndef JOSTLE_OPS
#define OPS_INT32_OVERFLOW_1
#define OPS_INT32_OVERFLOW_2
#define OPS_INT32_OVERFLOW_3

#define OPS_FAILED_ACCESS_1
#define OPS_FAILED_ACCESS_2
#define OPS_FAILED_ACCESS_3
#define OPS_FAILED_ACCESS_4
#define OPS_POINTER_CHANGE
#define OPS_OPENSSL_ERROR_1
#define OPS_OPENSSL_ERROR_2
#define OPS_OPENSSL_ERROR_3
#define OPS_OPENSSL_ERROR_4
#define OPS_OPENSSL_ERROR_5
#define OPS_OPENSSL_ERROR_6
#define OPS_LEN_CHANGE_1

#define OPS_FAILED_CREATE_1
#define OPS_FAILED_CREATE_2
#define OPS_FAILED_INIT_1
#define OPS_FAILED_INIT_2

#define OPS_FAILED_SET_1
#define OPS_FAILED_SET_2

#define OPS_THREAD_ATTACH_1
#define OPS_JNI_FAIL_CREATE_1
#define OPS_SHORT_SIZE_1
#define OPS_RAND_UP_CALL_NULL

#define OPS_ALTERNATE_1
#define OPS_ALTERNATE_2
#define OPS_ALTERNATE_3
#define OPS_ALTERNATE_4
#define OPS_ALTERNATE_5

#define OPS_OPENSSL_ERROR_7
#define OPS_OPENSSL_ERROR_8
#define OPS_OPENSSL_ERROR_9
#define OPS_OPENSSL_ERROR_10
#define OPS_OPENSSL_ERROR_11
#define OPS_OPENSSL_ERROR_12
#define OPS_FAILED_ACCESS_5
#define OPS_FAILED_ACCESS_6
#define OPS_FAILED_ACCESS_7
#define OPS_FAILED_ACCESS_8
#define OPS_FAILED_ACCESS_9
#define OPS_LEDGER_SKIP_FREE_1

// Non-OPS: the ledger vanishes; the enum stays so call sites compile.
#define JO_LEDGER_CREATED(t) ((void) 0)
#define JO_LEDGER_DESTROYED(t) ((void) 0)

// Non-OPS: macros vanish entirely. Call sites read the same in both builds.
#define OPS_OFFSET_OPENSSL_ERROR_1(x)
#define OPS_OFFSET_OPENSSL_ERROR_2(x)
#define OPS_OFFSET_OPENSSL_ERROR_3(x)
#define OPS_OFFSET_OPENSSL_ERROR_4(x)
#define OPS_OFFSET_OPENSSL_ERROR_5(x)
#define OPS_OFFSET_OPENSSL_ERROR_6(x)
#define OPS_OFFSET_OPENSSL_ERROR_7(x)
#define OPS_OFFSET_OPENSSL_ERROR_8(x)
#define OPS_OFFSET_OPENSSL_ERROR_9(x)
#define OPS_OFFSET_OPENSSL_ERROR_10(x)
#define OPS_OFFSET_OPENSSL_ERROR_11(x)
#define OPS_OFFSET_OPENSSL_ERROR_12(x)

#define OPS_OFFSET_FAILED_CREATE_1(x)
#define OPS_OFFSET_FAILED_CREATE_2(x)
#define OPS_OFFSET_FAILED_INIT_1(x)
#define OPS_OFFSET_FAILED_INIT_2(x)
#define OPS_OFFSET_FAILED_SET_1(x)
#define OPS_OFFSET_FAILED_SET_2(x)
#define OPS_OFFSET_LEN_CHANGE_1(x)
#define OPS_OFFSET_POINTER_CHANGE(x)
#define OPS_OFFSET_SHORT_SIZE_1(x)
#define OPS_OFFSET_THREAD_ATTACH_1(x)
#define OPS_OFFSET_JNI_FAIL_CREATE_1(x)

#endif

#endif //OPS_H
