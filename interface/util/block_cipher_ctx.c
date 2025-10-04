//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "block_cipher_ctx.h"
#include <assert.h>
#include "bc_err_codes.h"
#include <limits.h>
#include <string.h>

#include "ctr_u128_t.h"
#include "ops.h"


#define Iv_len_test(a) if (iv_len != a) return JO_INVALID_IV_LEN;


inline int valid_for_ctr(size_t iv_len, size_t block_len) {
    size_t maxCounterSize = (8 > block_len / 2) ? block_len / 2 : 8;

    if (block_len - iv_len > maxCounterSize) {
        return JO_FAIL;
    }
    return JO_SUCCESS;
}


block_cipher_ctx *block_cipher_ctx_create(uint32_t cipher_Id, uint32_t mode_Id, uint8_t padding) {
    block_cipher_ctx *ctx = NULL;


    ctx = OPENSSL_zalloc(sizeof(block_cipher_ctx));
    if (ctx == NULL) {
        goto failed;
    }

    ctx->cipher_id = cipher_Id;
    ctx->mode_id = mode_Id;
    ctx->padding = padding;
    ctx->evp = EVP_CIPHER_CTX_new();


    if (ctx->evp == NULL) {
        goto failed;;
    }

    if (mode_Id == CTR) {
        /* Only 16 byte block sizes at this point */
        ctx->counter = ctr_u128_new();
        if (ctx->counter == NULL) {
            goto failed;
        }
    }

    return ctx;

failed:
    block_cipher_ctx_destroy(ctx);
    ctx = NULL;
    return ctx;
}


int32_t block_cipher_ctx_init(
    block_cipher_ctx *ctx,
    int32_t opp_mode,
    uint8_t *key,
    size_t key_len,
    uint8_t *iv,
    size_t iv_len,
    int32_t tag_len) {
    const EVP_CIPHER *evp_cipher = NULL;

    if (key == NULL) {
        return JO_KEY_IS_NULL;
    }

    if (iv == NULL) {
        iv_len = 0;
    }

    if (tag_len < 0 || tag_len > MAX_TAG_LEN) {
        return JO_INVALID_TAG_LEN;
    }

    ctx->tag_len = tag_len;
    ctx->tag_index = 0;

    /*
     * Modes that do not take an iv
     */

    switch (ctx->mode_id) {
        case ECB:
            if (iv_len != 0) {
                return JO_MODE_TAKES_NO_IV;
            }
            break;
        default:
            if (iv == NULL || iv_len == 0) {
                return JO_IV_IS_NULL;
            }
            break;
    }

    /*
     * Streaming modes
     */
    switch (ctx->mode_id) {
        case CFB1:
        case CFB8:
        case CFB64:
        case CFB128:
        case CTR:
        case OFB:
        case GCM:
            ctx->streaming = 1;
            break;
        default:
            ctx->streaming = 0;
    }


    switch (ctx->cipher_id) {
        case AES128:
            ctx->cipher_block_size = BLOCK_SIZE_AES;
            if (key_len != 16) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_aes_128_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_128_cbc();
                    break;
                case CFB1:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_128_cfb1();
                    break;
                case CFB8:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_128_cfb8();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_128_cfb128();
                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_128_ofb();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_AES) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_aes_128_ctr();

                    break;
                case XTS:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_128_xts();
                    break;

                // case WRAP:
                // case WRAP_PAD:

                // case OCB: Authenticated
                // case CCM: Authenticated
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_aes_128_gcm();
                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // AES128

        case AES192:
            ctx->cipher_block_size = BLOCK_SIZE_AES;
            if (key_len != 24) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_aes_192_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_192_cbc();
                    break;
                case CFB1:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_192_cfb1();
                    break;
                case CFB8:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_192_cfb8();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_192_cfb128();
                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_192_ofb();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_AES) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_aes_192_ctr();

                    break;
                // case WRAP:
                // case WRAP_PAD:

                // case OCB: Authenticated
                // case CCM: Authenticated
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_aes_192_gcm();
                    break;
                // case XTS: Not available
                default:
                    return JO_INVALID_MODE;
            }
            break; // AES192

        case AES256:
            ctx->cipher_block_size = BLOCK_SIZE_AES;
            if (key_len != 32) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_aes_256_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_256_cbc();
                    break;
                case CFB1:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_256_cfb1();
                    break;
                case CFB8:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_256_cfb8();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_256_cfb128();
                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_256_ofb();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_AES) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_aes_256_ctr();

                    break;
                case XTS:
                    Iv_len_test(BLOCK_SIZE_AES)
                    evp_cipher = EVP_aes_256_xts();
                    break;

                // case WRAP:
                // case WRAP_PAD:

                // case OCB: Authenticated
                // case CCM: Authenticated
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_aes_256_gcm();
                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // AES256

        case ARIA128:
            ctx->cipher_block_size = BLOCK_SIZE_ARIA;
            if (key_len != 16) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_aria_128_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_128_cbc();
                    break;
                case CFB1:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_128_cfb1();
                    break;
                case CFB8:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_128_cfb8();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_128_cfb128();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_ARIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_aria_128_ctr();
                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_128_ofb();
                    break;

                // case CCM: Authenticated
                // case GCM: Authenticated
                default:
                    return JO_INVALID_MODE;
            }
            break; // AREA128

        case ARIA192:
            ctx->cipher_block_size = 16;
            if (key_len != 24) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_aria_192_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_192_cbc();
                    break;
                case CFB1:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_192_cfb1();
                    break;
                case CFB8:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_192_cfb8();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_192_cfb128();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_ARIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_aria_192_ctr();

                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_192_ofb();
                    break;

                // case CCM: Authenticated
                // case GCM: Authenticated
                default:
                    return JO_INVALID_MODE;
            }
            break; // AREA192

        case ARIA256:
            ctx->cipher_block_size = BLOCK_SIZE_ARIA;
            if (key_len != 32) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_aria_256_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_256_cbc();
                    break;
                case CFB1:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_256_cfb1();
                    break;
                case CFB8:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_256_cfb8();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_256_cfb128();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_ARIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_aria_256_ctr();

                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_aria_256_ofb();
                    break;

                // case CCM: Authenticated
                // case GCM: Authenticated
                default:
                    return JO_INVALID_MODE;
            }
            break; // AREA192

        case CAMELLIA128:
            ctx->cipher_block_size = BLOCK_SIZE_CAMELLIA;
            if (key_len != 16) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_camellia_128_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_128_cbc();
                    break;
                case CFB1:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_128_cfb1();
                    break;
                case CFB8:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_128_cfb8();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_128_cfb128();
                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_128_ofb();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_CAMELLIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_camellia_128_ctr();

                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // CAMELLIA128

        case CAMELLIA192:
            ctx->cipher_block_size = BLOCK_SIZE_CAMELLIA;
            if (key_len != 24) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_camellia_192_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_192_cbc();
                    break;
                case CFB1:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_192_cfb1();
                    break;
                case CFB8:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_192_cfb8();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_192_cfb128();
                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_192_ofb();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_CAMELLIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_camellia_192_ctr();

                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // CAMELLIA192

        case CAMELLIA256:
            ctx->cipher_block_size = BLOCK_SIZE_CAMELLIA;
            if (key_len != 32) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_camellia_256_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_256_cbc();
                    break;
                case CFB1:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_256_cfb1();
                    break;
                case CFB8:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_256_cfb8();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_256_cfb128();
                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_camellia_256_ofb();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_CAMELLIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_camellia_256_ctr();

                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // CAMELLIA256
        case SM4:
            ctx->cipher_block_size = BLOCK_SIZE_SM4;
            if (key_len != 16) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_sm4_ecb();
                    break;
                case CBC:
                    Iv_len_test(BLOCK_SIZE_SM4)
                    evp_cipher = EVP_sm4_cbc();
                    break;
                case CFB128:
                    Iv_len_test(BLOCK_SIZE_SM4)
                    evp_cipher = EVP_sm4_cfb128();
                    break;
                case OFB:
                    Iv_len_test(BLOCK_SIZE_SM4)
                    evp_cipher = EVP_sm4_ofb();
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_SM4) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_sm4_ctr();

                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // SM4
        default:
            return JO_INVALID_CIPHER; // Cipher mode
    }

    /* We should have exited early by this point */

    assert(evp_cipher != NULL);


    /*  Keep copies of the last key and iv for complete reset after do final */

    if (iv != NULL) {
        ctx->iv_len = iv_len;
        memcpy(ctx->last_iv, iv, iv_len);
    } else {
        ctx->iv_len = 0;
        OPENSSL_cleanse(ctx->last_iv, MAX_IV_LEN);
    }

    /* Copy original key for later use in reset */
    memcpy(ctx->last_key, key, key_len);
    ctx->key_len = key_len;

    uint8_t *iv_for_openssl = NULL;
    if (CTR == ctx->mode_id) {
        counter_init(ctx->counter, iv, iv_len);
        iv_for_openssl = ctx->counter->original_counter;
    } else {
        iv_for_openssl = iv;
    }


    switch (opp_mode) {
        case ENCRYPT_MODE:
            if (1 != EVP_EncryptInit_ex(ctx->evp, evp_cipher, NULL, key, iv_for_openssl)) {
                return JO_OPENSSL_ERROR;
            }
            ctx->op_mode = ENCRYPT_MODE;

            if (ctx->mode_id == GCM) {
                if (1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_IVLEN, (int) ctx->iv_len, NULL)) {
                    return JO_OPENSSL_ERROR;
                }
            }

            break;

        case DECRYPT_MODE:
            if (1 != EVP_DecryptInit_ex(ctx->evp, evp_cipher, NULL, key, iv_for_openssl)) {
                return JO_OPENSSL_ERROR;
            }

            if (ctx->mode_id == GCM) {
                if (1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_IVLEN, (int) ctx->iv_len, NULL)) {
                    return JO_OPENSSL_ERROR;
                }
            }


            ctx->op_mode = DECRYPT_MODE;
            break;
        default:
            return JO_INVALID_OP_MODE;
    }


    /* Apply / remove padding for appropriate modes */
    switch (ctx->mode_id) {
        case CBC:
        case ECB:
            if (ctx->padding == PADDED) {
                EVP_CIPHER_CTX_set_padding(ctx->evp, 1);
            } else {
                EVP_CIPHER_CTX_set_padding(ctx->evp, 0);
            }
            break;
        default:
            break;
    }


    ctx->processed = 0;
    return JO_SUCCESS;
}


int32_t block_cipher_ctx_updateAAD(
    block_cipher_ctx *ctx,
    uint8_t *input,
    size_t in_len) {
    assert(ctx != NULL);

    if (in_len == 0) {
        return 0;
    }

    if (input == NULL) {
        return JO_INPUT_IS_NULL;
    }


    if (OPS_INT32_OVERFLOW_1 in_len > INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }


    if (ctx->streaming == 0 && ctx->padding == NO_PADDING) {
        /* Block aligned */
        if (in_len % ctx->cipher_block_size != 0) {
            return JO_NOT_BLOCK_ALIGNED;
        }
    }

    if (ctx->mode_id == CTR) {
        //
        // Determine if we are going to spill into another block.
        //
        size_t excess = 0;
        if (ctx->processed % ctx->cipher_block_size != 0) {
            //
            // Partial block, work out remaining in that block
            //
            const size_t remaining = ctx->cipher_block_size - (ctx->processed % ctx->cipher_block_size);
            if (in_len > remaining) {
                excess = in_len - remaining;
            }
        } else {
            // Start of new block
            excess = in_len;
        }

        if (excess > 0) {
            size_t blocks = (excess / ctx->cipher_block_size) + (excess % ctx->cipher_block_size != 0);
            counter_add(ctx->counter, 0, blocks);
            if (0 == counter_valid(ctx->counter)) {
                return JO_CTR_MODE_OVERFLOW;
            }
        }
    }


    int32_t written = 0;

    /* in_len  asserted less than int32 max */

    if (ctx->op_mode == ENCRYPT_MODE) {
        if (1 != EVP_EncryptUpdate(ctx->evp, NULL, &written, input, (int) in_len)) {
            return JO_OPENSSL_ERROR;
        }
    } else if (ctx->op_mode == DECRYPT_MODE) {
        if (1 != EVP_DecryptUpdate(ctx->evp, NULL, &written, input, (int)in_len)) {
            return JO_OPENSSL_ERROR;
        }
    } else {
        return JO_INVALID_OP_MODE;
    }
    ctx->processed += in_len;
    return written;
}


int32_t block_cipher_ctx_update(
    block_cipher_ctx *ctx,
    uint8_t *input,
    size_t in_len,
    uint8_t *output,
    size_t out_len) {
    assert(ctx != NULL);

    if (in_len == 0) {
        return 0;
    }

    if (input == NULL) {
        return JO_INPUT_IS_NULL;
    }

    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    if (OPS_INT32_OVERFLOW_1 in_len > INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    if (OPS_INT32_OVERFLOW_2 out_len > INT_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    if (ctx->op_mode == ENCRYPT_MODE || ctx->tag_len == 0) {
        if (out_len < in_len) {
            return JO_OUTPUT_TOO_SMALL;
        }
    } else if (ctx->op_mode == DECRYPT_MODE) {
        int32_t a = ctx->tag_index + in_len - ctx->tag_len;
        if (a > 0) {
            // 'a' is not negative at this point
            if (out_len < (size_t) a) {
                return JO_OUTPUT_TOO_SMALL;
            }
        }
    }

    if (ctx->streaming == 0 && ctx->padding == NO_PADDING) {
        /* Block aligned */
        if (in_len % ctx->cipher_block_size != 0) {
            return JO_NOT_BLOCK_ALIGNED;
        }
    }

    if (ctx->mode_id == CTR) {
        //
        // Determine if we are going to spill into another block.
        //
        size_t excess = 0;
        if (ctx->processed % ctx->cipher_block_size != 0) {
            //
            // Partial block, work out remaining in that block
            //
            const size_t remaining = ctx->cipher_block_size - (ctx->processed % ctx->cipher_block_size);
            if (in_len > remaining) {
                excess = in_len - remaining;
            }
        } else {
            // Start of new block
            excess = in_len;
        }

        if (excess > 0) {
            size_t blocks = (excess / ctx->cipher_block_size) + (excess % ctx->cipher_block_size != 0);
            counter_add(ctx->counter, 0, blocks);
            if (0 == counter_valid(ctx->counter)) {
                return JO_CTR_MODE_OVERFLOW;
            }
        }
    }


    int32_t written = 0;

    /* in_len and out_len asserted less than int32 max */

    if (ctx->op_mode == ENCRYPT_MODE) {
        if (1 != EVP_EncryptUpdate(ctx->evp, output, &written, input, (int) in_len)) {
            return JO_OPENSSL_ERROR;
        }
    } else if (ctx->op_mode == DECRYPT_MODE) {
        if (ctx->mode_id == GCM) {
            //
            // Fill tag buffer
            //
            if (ctx->tag_index < ctx->tag_len) {
                uint32_t toCopy = ctx->tag_len - ctx->tag_index;
                if (toCopy > in_len) {
                    toCopy = in_len;
                }
                memcpy(&ctx->tag_buffer[ctx->tag_index], input, toCopy);
                input += toCopy;
                in_len -= toCopy;
                ctx->tag_index += toCopy;
            }

            if (in_len >= ctx->tag_len) {
                // What is in the tag buffer cannot be the tag so pass it to update
                int _out_len = 0;

                if (1 != EVP_DecryptUpdate(ctx->evp, output, &_out_len, ctx->tag_buffer, (int) ctx->tag_len)) {
                    return JO_OPENSSL_ERROR;
                }

                written += _out_len;
                output += _out_len;


                //
                // Update with everything else that cannot potentially be the tag
                //
                uint32_t toCopy = in_len - ctx->tag_len;
                if (1 != EVP_DecryptUpdate(ctx->evp, output, &_out_len, input, (int) toCopy)) {
                    return JO_OPENSSL_ERROR;
                }

                written += _out_len;
                input += toCopy;
                in_len -= toCopy;


                // in_len is now tag_len

                memcpy(ctx->tag_buffer, input, in_len); /* Copy into tag buf */
                ctx->tag_index = in_len;
            } else if (in_len > 0) {
                // Input will overflow tag buffer, update from head of tag buffer, in_len amout

                if (1 != EVP_DecryptUpdate(ctx->evp, output, &written, ctx->tag_buffer, (int) in_len)) {
                    return JO_OPENSSL_ERROR;
                }

                // Copy back to head of tag_buffer
                memcpy(ctx->tag_buffer, ctx->tag_buffer+in_len, ctx->tag_index-in_len);
                ctx->tag_index -= in_len;

                // Copy input into tag buffer
                memcpy(ctx->tag_buffer+ctx->tag_index, input, in_len);
                ctx->tag_index += in_len;
            }
        } else {
            if (1 != EVP_DecryptUpdate(ctx->evp, output, &written, input, (int) in_len)) {
                return JO_OPENSSL_ERROR;
            }
        }
    } else {
        return JO_INVALID_OP_MODE;
    }
    ctx->processed += in_len;
    return written;
}


size_t final_size(block_cipher_ctx *ctx, size_t len) {
    if (ctx->streaming == 1) {
        switch (ctx->mode_id) {
            case GCM:
                if (ctx->tag_len > 0) {
                    if (ctx->op_mode == ENCRYPT_MODE) {
                        len = len + ctx->tag_len;
                    } else if (ctx->op_mode == DECRYPT_MODE) {
                        len = len - ctx->tag_len;
                    } else {
                        return JO_INVALID_OP_MODE; // Unexpected state
                    }
                }
                break;
            default:
                return len;
        }
    }

    if (ctx->padding == PADDED) {
        size_t partial_block = ctx->processed % ctx->cipher_block_size;
        size_t total = len + partial_block;
        size_t left_over = total % ctx->cipher_block_size;

        if (left_over == 0) {
            len = (ctx->op_mode == ENCRYPT_MODE) ? total + ctx->cipher_block_size : total;
        } else {
            len = total - left_over + ctx->cipher_block_size;
        }
    }


    if (OPS_INT32_OVERFLOW_1 len > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }


    return (int32_t) len;
}

size_t internal_final_size(block_cipher_ctx *ctx) {
    if (ctx->streaming == 1) {
        return 0;
    }

    size_t len = 0;

    if (ctx->padding == PADDED) {
        size_t partial_block = ctx->processed % ctx->cipher_block_size;
        size_t total = partial_block;
        size_t left_over = total % ctx->cipher_block_size;

        if (left_over == 0) {
            len = (ctx->op_mode == ENCRYPT_MODE) ? total + ctx->cipher_block_size : total;
        } else {
            len = total - left_over + ctx->cipher_block_size;
        }
    }

    if (ctx->tag_len > 0) {
        if (ctx->op_mode == ENCRYPT_MODE) {
            len = len + ctx->tag_len;
        } else if (ctx->op_mode == DECRYPT_MODE) {
            len = 0;
        } else {
            return JO_INVALID_OP_MODE; // Unexpected state
        }
    }


    return len;
}


int32_t block_cipher_ctx_final(
    block_cipher_ctx *ctx,
    uint8_t *output,
    size_t out_len) {
    int32_t written = 0;


    if (output == NULL) {
        written = JO_OUTPUT_IS_NULL;
        goto failed;
    }

    if (OPS_INT32_OVERFLOW_1 out_len > INT_MAX) {
        written = JO_OUTPUT_TOO_LONG_INT32;
        goto failed;
    }

    /* out_len asserted less than int32 max */

    if (ctx->op_mode == ENCRYPT_MODE) {
        size_t min_out_len = internal_final_size(ctx);


        if (out_len < min_out_len) {
            written = JO_OUTPUT_TOO_SMALL;
            goto failed;
        }

        if (1 != EVP_EncryptFinal_ex(ctx->evp, output, &written)) {
            written = JO_OPENSSL_ERROR;
            goto failed;
        }

        if (ctx->mode_id == GCM) {
            // Load tag into struct.

            uint8_t *tag = output + written;

            if (1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_GET_TAG, ctx->tag_len, tag)) {
                written = JO_OPENSSL_ERROR;
                goto failed;
            }

            written += ctx->tag_len;
        }
    } else if (ctx->op_mode == DECRYPT_MODE) {
        size_t min_out_len = internal_final_size(ctx);

        if (out_len < min_out_len) {
            written = JO_OUTPUT_TOO_SMALL;
            goto failed;
        }

        if (ctx->mode_id == GCM) {
            //
            // Roll in last tag
            //
            if (1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_TAG, ctx->tag_len, ctx->tag_buffer)) {
                written = JO_OPENSSL_ERROR;
                goto failed;
            }
        }

        if (1 != EVP_DecryptFinal_ex(ctx->evp, output, &written)) {
            if (ctx->mode_id == GCM) {
                written = JO_TAG_INVALID;
            } else {
                written = JO_INVALID_CIPHER_TEXT;
            }
        }
    } else {
        written = JO_INVALID_OP_MODE;
    }

    // Reset
    block_cipher_ctx_init(ctx, ctx->op_mode, ctx->last_key, ctx->key_len, ctx->last_iv, ctx->iv_len, ctx->tag_len);

failed:
    return written;
}


int32_t block_cipher_set_tag(block_cipher_ctx *ctx, uint8_t *tag, size_t tag_len) {
    int32_t ret = JO_FAIL;

    if (tag == NULL) {
        ret = JO_TAG_IS_NULL;
        goto exit;
    }

    if (tag_len > MAX_TAG_LEN) {
        ret = JO_INVALID_TAG_LEN;
        goto exit;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_TAG, (int) tag_len, tag)) {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret = JO_SUCCESS;

exit:
    return ret;
}


int32_t block_cipher_ctx_get_block_size(block_cipher_ctx *ctx) {
    assert(ctx->cipher_block_size <= INT_MAX); // TODO error code instead
    return (int32_t) ctx->cipher_block_size;
}


int32_t block_cipher_get_final_size(block_cipher_ctx *ctx, size_t len) {
    assert(ctx != NULL);

    len = final_size(ctx, len);
    return (int32_t) len;
}

int32_t block_cipher_get_update_size(block_cipher_ctx *ctx, size_t len) {
    assert(ctx != NULL);
    if (ctx->streaming) {
        return len;
    }

    size_t remaining = 0;

    if (ctx->padding == PADDED) {
        remaining = ctx->processed % ctx->cipher_block_size;
    }

    return ctx->cipher_block_size * ((remaining + len) / ctx->cipher_block_size);
}


void block_cipher_ctx_destroy(block_cipher_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->counter != NULL) {
        counter_free(ctx->counter);
    }

    if (ctx->evp != NULL) {
        EVP_CIPHER_CTX_free(ctx->evp);
    }

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}
