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

#define OPS_MAX_TEST 21

// Offset the error code by fixed amount during ops testing
#define OPS_OFFSET(x) - x

bool is_ops_set(const uint32_t index);

void set_ops_test(const uint32_t index, const uint32_t value);

#endif

#ifndef JOSTLE_OPS
#define OPS_INT32_OVERFLOW_1
#define OPS_INT32_OVERFLOW_2
#define OPS_INT32_OVERFLOW_3

#define OPS_FAILED_ACCESS_1
#define OPS_FAILED_ACCESS_2
#define OPS_FAILED_ACCESS_3
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
#define OPS_OFFSET(x)
#endif

#endif //OPS_H
