//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// Memory-hard password KDFs - nonfips tree only. See kdf_memhard.c for why
// these are not carried in the FIPS interface library.
//

#ifndef KDF_MEMHARD_H
#define KDF_MEMHARD_H
#include <stddef.h>
#include <stdint.h>

int32_t jo_scrypt(
    uint8_t *password, size_t password_len,
    uint8_t *salt, size_t salt_len,
    uint64_t n,
    uint32_t r,
    uint32_t p,
    uint8_t *out,
    size_t out_len
);

int32_t jo_argon2(
    int32_t type,
    uint32_t version,
    uint8_t *password, size_t password_len,
    uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint32_t memory_kib,
    uint32_t lanes,
    uint8_t *out,
    size_t out_len
);

#endif //KDF_MEMHARD_H
