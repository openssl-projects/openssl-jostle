//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <assert.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include "types.h"
#include "../util/block_cipher_ctx.h"

/*
 * Check that nominates offset and len are within the "size" of the array we re accessing.
*/
inline bool range_check(const size_t size, const size_t len, const size_t offset) {
    return (len <= size) && (offset <= size - len);
}

/**
 *
 * @param cipherId Ordinal from OSSLCipher enum
 * @param modeId Ordinal from OSSLMode enum
 * @param padding >0 is padded
 * @return NULL if failed or a pointer to a block_cipher_ctx
 */
uint64_t BlockCipherNI_make_instance(int32_t cipherId, int32_t modeId, int32_t padding) {
    block_cipher_ctx *ctx = block_cipher_ctx_create(cipherId, modeId, padding);
    return (uint64_t) ctx;
}

/**
 * Initialise the block cipher
 * @param ref pointer to underlying block_cipher_ctx
 * @param opp_mode Operation mode, Encrypt, Decrypt follows integers define in Cipher class
 * @param key Pointer to ket array
 * @param key_size length of key array
 * @param iv pointer to iv, may be null
 * @param iv_size length of iv array or 0 if null
 * @return success failure code
 */
int32_t BlockCipherNI_init(
    uint64_t ref,
    int32_t opp_mode,
    uint8_t *key,
    size_t key_size,
    uint8_t *iv,
    size_t iv_size,
    int32_t tag_len) {
    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);

    int32_t return_code = JO_FAIL;

    if (key == NULL) {
        return_code = JO_KEY_IS_NULL;
        goto exit;
    }

    if (tag_len < 0) {
        return_code = JO_INVALID_TAG_LEN;
        goto exit;
    }

    return_code = block_cipher_ctx_init(
        ctx,
        opp_mode,
        key,
        key_size,
        iv,
        iv_size,
        tag_len);

exit:
    return return_code;
}


/**
 * Return the block size of the underlying cipher
 * @param ref pointer to block_cipher_ctx
 * @return block size
 */
int32_t BlockCipherNI_getBlockSize(uint64_t ref) {
    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);
    return block_cipher_ctx_get_block_size(ctx);
}


/**
 *
 * @param ref Pointer to block_cipher_ctx
 * @param input Input aad
 * @param input_size overall size of input array
 * @param in_off offset within input array
 * @param in_len length of input to use as aad
 * @return
 */
int32_t BlockCipherNI_updateAAD
(
    uint64_t ref,
    uint8_t *input,
    size_t input_size,
    int32_t in_off,
    int32_t in_len) {
    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);
    int32_t return_code = JO_FAIL;

    if (input == NULL) {
        return_code = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (in_off < 0) {
        return_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        return_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!range_check(input_size, in_len, in_off)) {
        return_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }


    /* in_off asserted as non-negative by this point */
    /* in_off asserted as in range by this point */

    uint8_t *input_data = input + (size_t) in_off;


    return_code = block_cipher_ctx_updateAAD(ctx, input_data, in_len);

exit:
    return return_code;
}


/**
 * Update the block cipher
 *
 * @param ref Pointer to block_cipher_ctx
 * @param output Output array
 * @param output_size total length of output array
 * @param out_off offset within output array
 * @param input pointer to input array
 * @param input_size total length of input array
 * @param in_off offset without input array to start at
 * @param in_len number of bytes to process
 * @return number of bytes written to output array
 */
int32_t BlockCipherNI_update
(
    uint64_t ref,
    uint8_t *output,
    size_t output_size,
    int32_t out_off,
    uint8_t *input,
    size_t input_size,
    int32_t in_off,
    int32_t in_len) {
    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);
    int32_t return_code = JO_FAIL;

    if (input == NULL) {
        return_code = JO_INPUT_IS_NULL;
        goto exit;
    }


    if (output == NULL) {
        return_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }


    if (out_off < 0) {
        return_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_off < 0) {
        return_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        return_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!range_check(input_size, in_len, in_off)) {
        return_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    /* out_off asserted as non-negative by this point */
    const size_t out_len = output_size - (size_t) out_off;

    if (!range_check(output_size, out_len, out_off)) {
        return_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    /* in_off and out_off asserted as non-negative by this point */
    /* in_off and out_off asserted as in range by this point */

    uint8_t *input_data = input + (size_t) in_off;
    uint8_t *output_data = output + (size_t) out_off;

    return_code = block_cipher_ctx_update(ctx, input_data, in_len, output_data, out_len);

exit:
    return return_code;
}

/**
 * Call final on the block cipher
 *
 * @param ctx pointer to  block_cipher_ctx
 * @param output pointer to output array
 * @param output_size total length of output array
 * @param out_off the offset without the output array
 * @return number of bytes written to output array
 */
int32_t BlockCipherNI_doFinal(block_cipher_ctx *ctx, uint8_t *output, size_t output_size, int32_t out_off) {
    assert(ctx);

    int32_t return_code = JO_FAIL;


    if (output == NULL) {
        return_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (out_off < 0) {
        return_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    /* out_off asserted as non-negative by this point */
    const size_t out_len = output_size - (size_t) out_off;

    if (!range_check(output_size, out_len, out_off)) {
        return_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    uint8_t *output_data = output + (size_t) out_off;
    return_code = block_cipher_ctx_final(ctx, output_data, out_len);

exit:
    return return_code;
}

int32_t BlockCipherNI_getUpdateSize(block_cipher_ctx *ctx, int32_t len) {
    assert(ctx != NULL);
    int32_t return_code = JO_FAIL;

    if (len < 0) {
        return_code = JO_FINAL_SIZE_LEN_IS_NEGATIVE;
        goto exit;
    }

    return_code = block_cipher_get_update_size(ctx, (size_t) len);

exit:
    return return_code;
}


int32_t BlockCipherNI_getFinalSize(block_cipher_ctx *ctx, int32_t len) {
    assert(ctx != NULL);
    int32_t return_code = JO_FAIL;

    if (len < 0) {
        return_code = JO_FINAL_SIZE_LEN_IS_NEGATIVE;
        goto exit;
    }

    return_code = block_cipher_get_final_size(ctx, (size_t) len);

exit:
    return return_code;
}


/**
 * Dispose of the block cipher instance, underlying implementation is null safe
 * @param ctx pointer to block_cipher_ctx
 */
void BlockCipherNI_dispose
(block_cipher_ctx *ctx) {
    block_cipher_ctx_destroy(ctx);
}
