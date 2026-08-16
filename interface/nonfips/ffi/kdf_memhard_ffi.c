//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FFI bridge for the memory-hard password KDFs (scrypt, Argon2).
//
// Nonfips tree only, with no fips twin: the FIPS interface library deliberately
// exports neither JoKDF_SCRYPT nor JoKDF_ARGON2. That is load-bearing, not
// cosmetic - KdfFIPSFFI extends KdfNIFFI and inherits a constructor that
// resolves every symbol with orElseThrow(), so binding these there would fail
// the FIPS KDF NI at construction. See util/kdf_memhard.c for the FIPS
// rationale.
//

#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "../util/kdf_memhard.h"
#include "../util/bc_err_codes.h"

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
    int32_t ret_code = JO_FAIL;

    if (passwd == NULL) {
        ret_code = JO_KDF_PASSWORD_NULL;
        goto exit;
    }

    if (salt == NULL) {
        ret_code = JO_KDF_SALT_NULL;
        goto exit;
    }

    if (salt_len == 0) {
        ret_code = JO_KDF_SALT_EMPTY;
        goto exit;
    }

    if (n < 2) {
        ret_code = JO_KDF_SCRYPT_N_TOO_SMALL;
        goto exit;
    }

    if ((n & (n - 1)) != 0) {
        ret_code = JO_KDF_SCRYPT_N_NOT_POW2;
        goto exit;
    }

    if (r < 1) {
        ret_code = JO_KDF_SCRYPT_R_TOO_SMALL;
        goto exit;
    }

    if (p < 1) {
        ret_code = JO_KDF_SCRYPT_P_TOO_SMALL;
        goto exit;
    }

    if (output == NULL) {
        ret_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (out_offset < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (out_len < 0) {
        ret_code = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(out_size, out_offset, out_len)) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }


    uint8_t *out = output + out_offset;

    ret_code = jo_scrypt(
        passwd, passwd_len,
        salt, salt_len,
        n,
        r,
        p,
        out, out_len);


exit:
    return ret_code;
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
    int32_t ret_code = JO_FAIL;

    if (passwd == NULL) {
        ret_code = JO_KDF_PASSWORD_NULL;
        goto exit;
    }

    if (salt == NULL) {
        ret_code = JO_KDF_SALT_NULL;
        goto exit;
    }

    if (salt_len == 0) {
        ret_code = JO_KDF_SALT_EMPTY;
        goto exit;
    }

    if (type < 0 || type > 2) {
        ret_code = JO_KDF_ARGON2_TYPE_INVALID;
        goto exit;
    }

    if (version != 0x10 && version != 0x13) {
        ret_code = JO_KDF_ARGON2_VERSION_INVALID;
        goto exit;
    }

    if (iterations < 1) {
        ret_code = JO_KDF_ARGON2_ITER_TOO_SMALL;
        goto exit;
    }

    if (lanes < 1) {
        ret_code = JO_KDF_ARGON2_LANES_TOO_SMALL;
        goto exit;
    }

    //
    // RFC 9106 floor: 8 * lanes KiB. Compared in 64-bit so the multiply cannot
    // overflow for lanes up to INT32_MAX.
    //
    if (memory_kib < 1 || (int64_t) memory_kib < (int64_t) 8 * (int64_t) lanes) {
        ret_code = JO_KDF_ARGON2_MEMORY_TOO_SMALL;
        goto exit;
    }

    if (output == NULL) {
        ret_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (out_offset < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (out_len < 0) {
        ret_code = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(out_size, out_offset, out_len)) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    uint8_t *out = output + out_offset;

    ret_code = jo_argon2(
        type,
        (uint32_t) version,
        passwd, passwd_len,
        salt, salt_len,
        (uint32_t) iterations,
        (uint32_t) memory_kib,
        (uint32_t) lanes,
        out, out_len);

exit:
    return ret_code;
}
