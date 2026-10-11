//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//

#include "../util/md.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/ops.h"
#include "../util/jo_assert.h"

md_ctx *JoMD_Allocate(const char *digest_name, size_t name_len, int32_t xof_len, int32_t *err, int32_t err_len) {
    /* err is jostle's own: a null or empty one is a broken invariant, so it aborts. */
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);
    if (digest_name == NULL) {
        *err = JO_NAME_IS_NULL;
        return NULL;
    }
    // name_len is the name's UTF-8 byte count: an empty name or an embedded NUL names nothing, as on JNI.
    if (name_len == 0 || strnlen(digest_name, name_len) != name_len) {
        *err = JO_NAME_NOT_FOUND;
        return NULL;
    }

    md_ctx *ctx = md_ctx_create(digest_name, xof_len, err);

    return ctx;
}

md_ctx *JoMD_Copy(md_ctx *src, int32_t *err, int32_t err_len) {
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);
    int32_t check_rc = md_ctx_check(src);
    if (UNSUCCESSFUL(check_rc)) {
        *err = check_rc;
        return NULL;
    }

    return md_ctx_copy(src, err);
}

void JoMD_Dispose(md_ctx *ctx) {
    // md_ctx_destroy frees nothing on a NULL or wrong kind.
    md_ctx_destroy(ctx);
}

int32_t JoMD_UpdateByte(md_ctx *ctx, uint8_t data) {
    int32_t check_rc = md_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }
    return md_ctx_update(ctx, (uint8_t *) &data, 1);
}

int32_t JoMD_UpdateBytes(md_ctx *ctx, uint8_t *input, const size_t input_size, const int32_t in_off, const int32_t in_len) {
    int32_t check_rc = md_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }
    int32_t ret_code = JO_FAIL;

    if (input == NULL) {
        ret_code = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (in_off < 0) {
        ret_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }


    if (!check_in_range(input_size, in_off, in_len)) {
        ret_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    uint8_t *in = input + (size_t) in_off;
    ret_code = md_ctx_update(ctx, in, in_len);

exit:
    return ret_code;
}

int32_t JoMD_GetDigestLen(md_ctx *ctx) {
    int32_t check_rc = md_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }
    if (ctx->digest_byte_length <= 0) {
        return JO_NOT_INITIALIZED;
    }

    if (OPS_INT32_OVERFLOW_4 ctx->digest_byte_length > INT32_MAX) {
        return JO_MD_DIGEST_LEN_INT_OVERFLOW;
    }

    return  ctx->digest_byte_length;
}

int32_t JoMD_Digest(md_ctx *ctx, uint8_t *output, size_t output_size, int32_t out_off, int32_t out_len) {
    int32_t check_rc = md_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    if (output == NULL) {
        /* Caller wants length — must match JoMD_GetDigestLen contract */
        if (ctx->digest_byte_length <= 0) {
            return JO_NOT_INITIALIZED;
        }
        if (OPS_INT32_OVERFLOW_5 ctx->digest_byte_length > INT32_MAX) {
            return JO_MD_DIGEST_LEN_INT_OVERFLOW;
        }
        return ctx->digest_byte_length;
    }

    int32_t ret_code = JO_FAIL;
    if (out_off < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (out_len < 0) {
        ret_code = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(output_size, out_off, (size_t)out_len)) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (out_len < ctx->digest_byte_length) {
        ret_code = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }

    uint8_t *output_data = output + (size_t) out_off;


    ret_code = md_ctx_finalize(ctx, output_data);

    exit:
    return ret_code;
}


int32_t JoMD_Reset(md_ctx *ctx) {
    int32_t check_rc = md_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    return md_ctx_reset(ctx);
}
