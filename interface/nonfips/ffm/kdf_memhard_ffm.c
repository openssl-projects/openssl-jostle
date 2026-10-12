//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FFM bridge for scrypt and Argon2, nonfips only. The FIPS library exports neither symbol: KdfFIPSFFM inherits a
// constructor that resolves every KdfNIFFM symbol with orElseThrow, so these live on MemoryHardKdfNIFFM instead.
//

#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "../util/kdf_memhard.h"
#include "../util/bc_err_codes.h"

/* Output checks in the order kdf_check_output (kdf_ffm.c) uses, so the KDF family answers alike. */
static int32_t memhard_check_output(uint8_t *output, size_t out_size, int32_t out_offset, int32_t out_len)
{
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    if (out_offset < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }

    if (out_len < 0) {
        return JO_OUTPUT_LEN_IS_NEGATIVE;
    }

    if (out_len == 0) {
        return JO_OUTPUT_LEN_IS_ZERO;
    }

    if (!check_in_range(out_size, out_offset, out_len)) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    return JO_SUCCESS;
}

int32_t JoKDF_SCRYPT(
    uint8_t *passwd, size_t passwd_len,
    uint8_t *salt, size_t salt_len,
    int32_t n,
    int32_t r,
    int32_t p,
    uint8_t *output,
    size_t out_size,
    int32_t out_offset,
    int32_t out_len
) {
    int32_t ret_code;

    if (passwd == NULL) {
        return JO_KDF_PASSWORD_NULL;
    }

    if (salt == NULL) {
        return JO_KDF_SALT_NULL;
    }

    if (salt_len == 0) {
        return JO_KDF_SALT_EMPTY;
    }

    if (n < 2) {
        return JO_KDF_SCRYPT_N_TOO_SMALL;
    }

    if ((n & (n - 1)) != 0) {
        return JO_KDF_SCRYPT_N_NOT_POW2;
    }

    if (r < 1) {
        return JO_KDF_SCRYPT_R_TOO_SMALL;
    }

    if (p < 1) {
        return JO_KDF_SCRYPT_P_TOO_SMALL;
    }

    ret_code = memhard_check_output(output, out_size, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    return jo_scrypt(
        passwd, passwd_len,
        salt, salt_len,
        (uint64_t) n,
        (uint32_t) r,
        (uint32_t) p,
        output + out_offset, (size_t) out_len);
}

int32_t JoKDF_ARGON2(
    int32_t type,
    int32_t version,
    uint8_t *passwd, size_t passwd_len,
    uint8_t *salt, size_t salt_len,
    int32_t iterations,
    int32_t memory_kib,
    int32_t lanes,
    uint8_t *output,
    size_t out_size,
    int32_t out_offset,
    int32_t out_len
) {
    int32_t ret_code;

    if (passwd == NULL) {
        return JO_KDF_PASSWORD_NULL;
    }

    if (salt == NULL) {
        return JO_KDF_SALT_NULL;
    }

    if (salt_len == 0) {
        return JO_KDF_SALT_EMPTY;
    }

    if (salt_len < JO_ARGON2_MIN_SALT_LEN) {
        return JO_KDF_ARGON2_SALT_TOO_SHORT;
    }

    if (type < 0 || type > 2) {
        return JO_KDF_ARGON2_TYPE_INVALID;
    }

    if (version != 0x10 && version != 0x13) {
        return JO_KDF_ARGON2_VERSION_INVALID;
    }

    if (iterations < 1) {
        return JO_KDF_ARGON2_ITER_TOO_SMALL;
    }

    if (lanes < 1) {
        return JO_KDF_ARGON2_LANES_TOO_SMALL;
    }

    // RFC 9106 floor: 8 * lanes KiB, compared in 64 bits so the multiply cannot overflow.
    if (memory_kib < 1 || (int64_t) memory_kib < (int64_t) 8 * (int64_t) lanes) {
        return JO_KDF_ARGON2_MEMORY_TOO_SMALL;
    }

    if (memory_kib > JO_ARGON2_MAX_MEMORY_KIB) {
        return JO_KDF_ARGON2_MEMORY_TOO_LARGE;
    }

    ret_code = memhard_check_output(output, out_size, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    if (out_len < JO_ARGON2_MIN_OUT_LEN) {
        return JO_KDF_ARGON2_OUTPUT_TOO_SHORT;
    }

    return jo_argon2(
        type,
        (uint32_t) version,
        passwd, passwd_len,
        salt, salt_len,
        (uint32_t) iterations,
        (uint32_t) memory_kib,
        (uint32_t) lanes,
        output + out_offset, (size_t) out_len);
}
