//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "block_cipher_ctx.h"

#include "bc_err_codes.h"
#include <limits.h>
#include <string.h>
#include <openssl/err.h>

#include "ctr_u128_t.h"
#include "ops.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"



#define REQUIRE_IV_LEN(expected) if (iv_len != (expected)) return JO_INVALID_IV_LEN;


static inline int valid_for_ctr(size_t iv_len, size_t block_len) {

    if (iv_len > block_len) {
        return JO_FAIL;
    }

    size_t maxCounterSize = (8 > block_len / 2) ? block_len / 2 : 8;

    if (block_len - iv_len > maxCounterSize) {
        return JO_FAIL;
    }
    return JO_SUCCESS;
}


block_cipher_ctx *block_cipher_ctx_create(uint32_t cipher_Id, uint32_t mode_Id, uint32_t padding, int32_t *err) {
    block_cipher_ctx *ctx = NULL;


    if (padding != NO_PADDING && padding != PADDED) {
        *err = JO_FAIL;
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(block_cipher_ctx));
    if (ctx == NULL) {
        goto failed;
    }

    ctx->cipher_id = cipher_Id;
    ctx->mode_id = mode_Id;
    ctx->padding = padding;
    ctx->evp = EVP_CIPHER_CTX_new();


    if (ctx->evp == NULL) {
        goto failed;
    }

    if (mode_Id == CTR) {
        /* Only 16 byte block sizes at this point */
        ctx->counter = ctr_u128_new();
        if (ctx->counter == NULL) {
            goto failed;
        }
    }
    *err = JO_SUCCESS;
    return ctx;

failed:
    *err = JO_FAIL;
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
    EVP_CIPHER *evp_cipher = NULL;

    if (ctx->poisoned) {
        return JO_CTX_POISONED;
    }


    ctx->initialized = 0;

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
    // Clear any tag bytes buffered from a previous decrypt session.
    OPENSSL_cleanse(ctx->tag_buffer, MAX_TAG_LEN);

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



    ERR_clear_error();


    switch (ctx->cipher_id) {
        case AES128:
            ctx->cipher_block_size = BLOCK_SIZE_AES;
            // XTS uses two AES keys concatenated, so AES-128-XTS expects a
            // 32-byte key. Other AES-128 modes still want 16 bytes.
            if (key_len != (ctx->mode_id == XTS ? 32 : 16)) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_AES) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-CTR",NULL);

                    break;
                case XTS:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-XTS",NULL);
                    break;

                // case WRAP:
                // case WRAP_PAD:

                // case OCB: Authenticated
                // case CCM: Authenticated
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-GCM",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_AES) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-CTR",NULL);

                    break;
                // case WRAP:
                // case WRAP_PAD:

                // case OCB: Authenticated
                // case CCM: Authenticated
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-GCM",NULL);
                    break;
                // case XTS: Not available
                default:
                    return JO_INVALID_MODE;
            }
            break; // AES192

        case AES256:
            ctx->cipher_block_size = BLOCK_SIZE_AES;
            // XTS uses two AES-256 keys concatenated → 64 bytes.
            if (key_len != (ctx->mode_id == XTS ? 64 : 32)) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_AES) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-CTR",NULL);

                    break;
                case XTS:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-XTS",NULL);
                    break;

                // case WRAP:
                // case WRAP_PAD:

                // case OCB: Authenticated
                // case CCM: Authenticated
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-GCM",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-128-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-128-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-128-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-128-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-128-CFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_ARIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-128-CTR",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-128-OFB",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-192-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-192-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-192-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-192-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-192-CFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_ARIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-192-CTR",NULL);

                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-192-OFB",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-256-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-256-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-256-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-256-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-256-CFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_ARIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-256-CTR",NULL);

                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-256-OFB",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-128-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-128-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-128-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-128-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-128-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-128-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_CAMELLIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-128-CTR",NULL);

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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-192-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-192-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-192-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-192-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-192-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-192-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_CAMELLIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-192-CTR",NULL);

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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-256-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-256-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-256-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-256-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-256-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-256-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_CAMELLIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "CAMELLIA-256-CTR",NULL);

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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "SM4-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_SM4)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "SM4-CBC",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_SM4)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "SM4-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_SM4)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "SM4-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_SM4) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "SM4-CTR",NULL);

                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // SM4
        default:
            return JO_INVALID_CIPHER; // Cipher mode
    }

    if (OPS_FAILED_CREATE_1 evp_cipher == NULL) {
        if (evp_cipher != NULL) {
            EVP_CIPHER_free(evp_cipher);
        }
        return JO_OPENSSL_ERROR;
    }

    int32_t ret_code = JO_SUCCESS;


    if (iv != NULL) {
        if (iv != ctx->last_iv) {
            memcpy(ctx->last_iv, iv, iv_len);
        }
        if (iv_len < MAX_IV_LEN) {
            OPENSSL_cleanse(ctx->last_iv + iv_len, MAX_IV_LEN - iv_len);
        }
        ctx->iv_len = iv_len;
    } else {
        OPENSSL_cleanse(ctx->last_iv, MAX_IV_LEN);
        ctx->iv_len = 0;
    }

    if (key != ctx->last_key) {
        memcpy(ctx->last_key, key, key_len);
    }
    if (key_len < MAX_KEY_LEN) {
        OPENSSL_cleanse(ctx->last_key + key_len, MAX_KEY_LEN - key_len);
    }
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
            if (ctx->mode_id == GCM) {

                if (OPS_FAILED_INIT_2 1 != EVP_EncryptInit_ex(ctx->evp, evp_cipher, NULL, NULL, NULL)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
                if (OPS_OPENSSL_ERROR_1 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_IVLEN, (int) ctx->iv_len,
                                                                 NULL)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
                if (OPS_FAILED_INIT_1 1 != EVP_EncryptInit_ex(ctx->evp, NULL, NULL, key, iv_for_openssl)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
            } else {
                if (OPS_FAILED_INIT_1 1 != EVP_EncryptInit_ex(ctx->evp, evp_cipher, NULL, key, iv_for_openssl)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
            }
            ctx->op_mode = ENCRYPT_MODE;
            break;

        case DECRYPT_MODE:
            if (ctx->mode_id == GCM) {
                // Same three-step pattern as encrypt; see comment above.
                if (OPS_FAILED_INIT_2 1 != EVP_DecryptInit_ex(ctx->evp, evp_cipher, NULL, NULL, NULL)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
                if (OPS_OPENSSL_ERROR_1 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_IVLEN, (int) ctx->iv_len,
                                                                 NULL)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
                if (OPS_FAILED_INIT_1 1 != EVP_DecryptInit_ex(ctx->evp, NULL, NULL, key, iv_for_openssl)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
            } else {
                if (OPS_FAILED_INIT_1 1 != EVP_DecryptInit_ex(ctx->evp, evp_cipher, NULL, key, iv_for_openssl)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
            }
            ctx->op_mode = DECRYPT_MODE;
            break;
        default:
            ret_code = JO_INVALID_OP_MODE;
            goto exit;
    }


    /* Apply / remove padding for appropriate modes */
    switch (ctx->mode_id) {
        case CBC:
        case ECB: {
            const int pad = (ctx->padding == PADDED) ? 1 : 0;
            if (OPS_OPENSSL_ERROR_7 1 != EVP_CIPHER_CTX_set_padding(ctx->evp, pad)) {
                ret_code = JO_OPENSSL_ERROR;
                goto exit;
            }
            break;
        }
        default:
            break;
    }


    ctx->processed = 0;
    ctx->initialized = 1;

exit:
    EVP_CIPHER_free(evp_cipher);
    return ret_code;
}


int32_t block_cipher_ctx_updateAAD(
    block_cipher_ctx *ctx,
    uint8_t *input,
    size_t in_len) {
    jo_assert(ctx != NULL);

    if (ctx->poisoned) {
        return JO_CTX_POISONED;
    }


    if (ctx->mode_id != GCM) {
        return JO_INVALID_MODE;
    }

    if (in_len == 0) {
        return 0;
    }

    if (input == NULL) {
        return JO_INPUT_IS_NULL;
    }


    if (OPS_INT32_OVERFLOW_1 in_len > INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }


    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    // Block-aligned and CTR-counter blocks were removed: this function is
    // gated on `mode_id == GCM` above, and GCM is streaming (block-aligned
    // check requires streaming==0) and is not CTR. Both blocks were dead.

    int32_t written = 0;

    /* in_len  asserted less than int32 max */

    ERR_clear_error();

    if (ctx->op_mode == ENCRYPT_MODE) {
        if (OPS_OPENSSL_ERROR_2 1 != EVP_EncryptUpdate(ctx->evp, NULL, &written, input, (int) in_len)) {
            ctx->poisoned = 1;
            return JO_OPENSSL_ERROR;
        }
    } else if (ctx->op_mode == DECRYPT_MODE) {
        if (OPS_OPENSSL_ERROR_2 1 != EVP_DecryptUpdate(ctx->evp, NULL, &written, input, (int) in_len)) {
            ctx->poisoned = 1;
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
    jo_assert(ctx != NULL);

    if (ctx->poisoned) {
        return JO_CTX_POISONED;
    }

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
        if (ctx->tag_index + in_len > ctx->tag_len) {
            size_t a = ctx->tag_index + in_len - ctx->tag_len;
            if (out_len < a) {
                return JO_OUTPUT_TOO_SMALL;
            }
        }
    }


    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    if (ctx->streaming == 0 && ctx->padding == NO_PADDING) {
        if (ctx->mode_id == XTS) {
            if (in_len < ctx->cipher_block_size) {
                return JO_NOT_BLOCK_ALIGNED;
            }
        } else if (in_len % ctx->cipher_block_size != 0) {
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
                ctx->poisoned = 1;
                return JO_CTR_MODE_OVERFLOW;
            }
        }
    }


    int32_t written = 0;

    /* in_len and out_len asserted less than int32 max */

    ERR_clear_error();

    if (ctx->op_mode == ENCRYPT_MODE) {
        if (OPS_OPENSSL_ERROR_3 1 != EVP_EncryptUpdate(ctx->evp, output, &written, input, (int) in_len)) {
            ctx->poisoned = 1;
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

                if (OPS_OPENSSL_ERROR_3 1 != EVP_DecryptUpdate(ctx->evp, output, &_out_len, ctx->tag_buffer,
                                                               (int) ctx->tag_len)) {

                    ctx->poisoned = 1;
                    return JO_OPENSSL_ERROR;
                }

                written += _out_len;
                output += _out_len;


                //
                // Update with everything else that cannot potentially be the tag
                //
                uint32_t toCopy = in_len - ctx->tag_len;
                if (OPS_OPENSSL_ERROR_3 1 != EVP_DecryptUpdate(ctx->evp, output, &_out_len, input, (int) toCopy)) {
                    ctx->poisoned = 1;
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

                if (OPS_OPENSSL_ERROR_3 1 != EVP_DecryptUpdate(ctx->evp, output, &written, ctx->tag_buffer,
                                                               (int) in_len)) {
                    ctx->poisoned = 1;
                    return JO_OPENSSL_ERROR;
                }


                memmove(ctx->tag_buffer, ctx->tag_buffer+in_len, ctx->tag_index-in_len);
                ctx->tag_index -= in_len;

                // Copy input into tag buffer
                memcpy(ctx->tag_buffer+ctx->tag_index, input, in_len);
                ctx->tag_index += in_len;
            }
        } else {
            if (OPS_OPENSSL_ERROR_3 1 != EVP_DecryptUpdate(ctx->evp, output, &written, input, (int) in_len)) {
                ctx->poisoned = 1;
                return JO_OPENSSL_ERROR;
            }
        }
    } else {
        return JO_INVALID_OP_MODE;
    }
    ctx->processed += in_len;
    return written;
}


int32_t final_size(block_cipher_ctx *ctx, size_t len) {
    if (len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    if (ctx->streaming == 1) {
        switch (ctx->mode_id) {
            case GCM:

                if (ctx->tag_len > 0) {
                    if (ctx->op_mode == ENCRYPT_MODE) {
                        len = len + ctx->tag_len;
                    } else if (ctx->op_mode == DECRYPT_MODE) {
                        if (ctx->tag_len > len) {
                            len = 0;
                        } else {
                            len = len - ctx->tag_len;
                        }
                    } else {
                        return JO_INVALID_OP_MODE; // Unexpected state
                    }
                }
                break;
            default:
                return (int32_t) len;
        }
    }

    if (ctx->padding == PADDED && ctx->streaming == 0) {
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


int32_t internal_final_size(block_cipher_ctx *ctx) {
    size_t len = 0;

    // Padding-block accounting only applies to non-streaming PADDED modes.
    if (ctx->padding == PADDED && ctx->streaming == 0) {
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

    if (len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }
    return (int32_t) len;
}


int32_t block_cipher_ctx_final(
    block_cipher_ctx *ctx,
    uint8_t *output,
    size_t out_len) {
    int32_t written = 0;

    if (ctx->poisoned) {
        written = JO_CTX_POISONED;
        goto failed;
    }

    if (output == NULL) {
        written = JO_OUTPUT_IS_NULL;
        goto failed;
    }

    if (OPS_INT32_OVERFLOW_1 out_len > INT_MAX) {
        written = JO_OUTPUT_TOO_LONG_INT32;
        goto failed;
    }

    if (!ctx->initialized) {
        written = JO_NOT_INITIALIZED;
        goto failed;
    }

    /* out_len asserted less than int32 max */

    ERR_clear_error();

    if (ctx->op_mode == ENCRYPT_MODE) {
        int32_t min_out_len = internal_final_size(ctx);
        if (min_out_len < 0) {
            written = min_out_len;
            goto failed;
        }
        if (out_len < (size_t) min_out_len) {
            written = JO_OUTPUT_TOO_SMALL;
            goto failed;
        }

        if (OPS_OPENSSL_ERROR_4 1 != EVP_EncryptFinal_ex(ctx->evp, output, &written)) {
            ctx->poisoned = 1;
            written = JO_OPENSSL_ERROR;
            goto failed;
        }

        if (ctx->mode_id == GCM) {

            if ((size_t) written + ctx->tag_len > out_len) {
                ctx->poisoned = 1;
                written = JO_OUTPUT_TOO_SMALL;
                goto failed;
            }

            // Load tag into struct.

            uint8_t *tag = output + written;

            if (OPS_OPENSSL_ERROR_5 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_GET_TAG, (int) ctx->tag_len,
                                                             tag)) {
                // EncryptFinal already mutated the EVP ctx; tag retrieval
                // failed. Same nonce-reuse hazard if we auto-reset — poison.
                ctx->poisoned = 1;
                written = JO_OPENSSL_ERROR;
                goto failed;
            }

            written += ctx->tag_len;
        }
    } else if (ctx->op_mode == DECRYPT_MODE) {
        int32_t min_out_len = internal_final_size(ctx);
        if (min_out_len < 0) {
            written = min_out_len;
            goto failed;
        }
        if (out_len < (size_t) min_out_len) {
            written = JO_OUTPUT_TOO_SMALL;
            goto failed;
        }

        if (ctx->mode_id == GCM) {
            //
            // Roll in last tag
            //
            if (OPS_OPENSSL_ERROR_6 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_TAG, (int) ctx->tag_len,
                                                             ctx->tag_buffer)) {
                ctx->poisoned = 1;
                written = JO_OPENSSL_ERROR;
                goto failed;
            }
        }


        if (OPS_OPENSSL_ERROR_4 1 != EVP_DecryptFinal_ex(ctx->evp, output, &written)) {
            if (ctx->mode_id == GCM) {
                written = JO_TAG_INVALID;
            } else {
                written = JO_INVALID_CIPHER_TEXT;
            }
            // best effort cleanse of plain text on tag failure.
            if (out_len > 0) {
                OPENSSL_cleanse(output, out_len);
            }
        }
    } else {
        written = JO_INVALID_OP_MODE;
    }


    // Reset for next round, return any errors, reset failure will poison
    // the block cipher making it unusable and should not be able to happen.
    int32_t reset_rc = block_cipher_ctx_init(ctx, ctx->op_mode, ctx->last_key, ctx->key_len, ctx->last_iv, ctx->iv_len,
                                             ctx->tag_len);
    if (reset_rc < 0) {
        ctx->poisoned = 1;
        if (written >= 0) {
            written = reset_rc;
        }
    }

failed:
    return written;
}


int32_t block_cipher_ctx_get_block_size(block_cipher_ctx *ctx) {

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    if (ctx->cipher_block_size > INT_MAX) {
        return JO_VALUE_EXCEEDS_INT_MAX;
    }

    return (int32_t) ctx->cipher_block_size;
}


int32_t block_cipher_get_final_size(block_cipher_ctx *ctx, size_t len) {
    jo_assert(ctx != NULL);

    // final_size reads ctx->cipher_block_size in the PADDED branch; on a
    // never-init'd ctx that's 0 and the modulo / division are UB.
    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    return final_size(ctx, len);
}

int32_t block_cipher_get_update_size(block_cipher_ctx *ctx, size_t len) {
    jo_assert(ctx != NULL);


    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }


    if (len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    size_t result;

    // XTS with ciphertext stealing produces output of the same length as
    // input (regardless of block alignment), so size like a streaming mode.
    if (ctx->streaming || ctx->mode_id == XTS) {
        result = len;
    } else {
        size_t remaining = 0;
        if (ctx->padding == PADDED) {
            remaining = ctx->processed % ctx->cipher_block_size;
        }
        result = ctx->cipher_block_size * ((remaining + len) / ctx->cipher_block_size);
    }

    if (result > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }
    return (int32_t) result;
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
