//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "../util/kdf.h"
#include "../util/bc_err_codes.h"

int32_t KDF_PBKDF2(
    uint8_t *passwd, size_t passwd_len,
    uint8_t *salt, size_t salt_len,
    int32_t iter,
    uint8_t *digest_name,
    size_t digest_name_len,
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

    if (iter < 0) {
        ret_code = JO_KDF_PBE_ITER_NEGATIVE;
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

    if (digest_name == NULL) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }


    if (digest_name_len == 0) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    uint8_t *out = output + out_offset;

    ret_code = pbkdf2(
        passwd, passwd_len,
        salt, salt_len,
        iter,
        digest_name,
        digest_name_len,
        out, out_len);


exit:
    return ret_code;
}


int32_t KDF_SCRYPT(
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

    if (r < 0) {
        ret_code = JO_KDF_SCRYPT_R_NEGATIVE;
        goto exit;
    }

    if (p < 0) {
        ret_code = JO_KDF_SCRYPT_P_NEGATIVE;
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

    ret_code = scrypt(
        passwd, passwd_len,
        salt, salt_len,
        n,
        r,
        p,
        out, out_len);


exit:
    return ret_code;
}
