//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef KEY_SPEC_H
#define KEY_SPEC_H
#include <openssl/types.h>

#define KS_NONE 0
#define KS_MLDSA_44 1
#define KS_MLDSA_65 2
#define KS_MLDSA_87 3

// #define KS_MLDSA_44_SHA512 4
// #define KS_MLDSA_65_SHA512 5
// #define KS_MLDSA_87_SHA512 6
#define KS_MLDSA_SEED 4



#define KS_SLH_DSA_SHA2_128f 5
#define KS_SLH_DSA_SHA2_128s 6
#define KS_SLH_DSA_SHA2_192f 7
#define KS_SLH_DSA_SHA2_192s 8
#define KS_SLH_DSA_SHA2_256f 9
#define KS_SLH_DSA_SHA2_256s 10
#define KS_SLH_DSA_SHAKE_128f 11
#define KS_SLH_DSA_SHAKE_128s 12
#define KS_SLH_DSA_SHAKE_192f 13
#define KS_SLH_DSA_SHAKE_192s 14
#define KS_SLH_DSA_SHAKE_256f 15
#define KS_SLH_DSA_SHAKE_256s 16

#define KS_ML_KEM_512 17
#define KS_ML_KEM_768 18
#define KS_ML_KEM_1024 19




typedef struct key_spec {
    EVP_PKEY *key;
} key_spec;


key_spec *create_spec(void);

/*
 * free the underlying PKEY
 */
void free_spec(key_spec *spec);

/*
 * free the key_spec and also freeing the PKEY if not already done so.
 * this would be normally called by the disposal daemon.
 */
void free_key_spec(key_spec *spec);

#endif //KEY_SPEC_H
