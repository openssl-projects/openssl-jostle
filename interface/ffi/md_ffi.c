#include <assert.h>

#include "../util/md.h"
#include <stdlib.h>
#include <openssl/evp.h>

#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/ops.h"

md_ctx *MD_Allocate(const char *digest_name, int32_t xof_len, int32_t *err) {
    assert(err != NULL);
    if (digest_name == NULL) {
        *err = JO_NAME_IS_NULL;
        return NULL;
    }

    md_ctx *ctx = md_ctx_create(digest_name, xof_len, err);

    return ctx;
}

void MD_Dispose(md_ctx *ctx) {
    md_ctx_destroy(ctx);
}

int32_t MB_UpdateByte(md_ctx *ctx, uint8_t data) {
    assert(ctx != NULL);
    return md_ctx_update(ctx, (uint8_t *) &data, 1);
}

int32_t MB_UpdateBytes(md_ctx *ctx, uint8_t *input, const size_t input_size, const int32_t in_off, const int32_t in_len) {
    assert(ctx != NULL);
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

int32_t MD_GetDigestLen(md_ctx *ctx) {
    assert(ctx != NULL);
    if (ctx->digest_byte_length <= 0) {
        return JO_NOT_INITIALIZED;
    }

    if (OPS_INT32_OVERFLOW_1 ctx->digest_byte_length > INT_MAX) {
        return JO_MD_DIGEST_LEN_INT_OVERFLOW;
    }

    return  ctx->digest_byte_length;
}

int32_t MB_Digest(md_ctx *ctx, uint8_t *output, size_t output_size, int32_t out_off, int32_t out_len) {
    assert(ctx != NULL);

    if (output == NULL) {
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


void MD_Reset(md_ctx *ctx) {

    assert(ctx != NULL);

    md_ctx_reset(ctx);
}
