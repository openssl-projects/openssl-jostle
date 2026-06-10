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


/**
 * AEAD-mode discriminator. GCM and OCB both:
 *   1. require EVP_CTRL_AEAD_SET_IVLEN (the unified OpenSSL control)
 *      before the key/IV are set,
 *   2. append a 16-byte authentication tag to the ciphertext, and
 *   3. expose AAD through EVP_EncryptUpdate(NULL, ...) /
 *      EVP_DecryptUpdate(NULL, ...).
 *
 * The rest of the file gates AEAD-specific code paths on this helper
 * instead of comparing `mode_id == GCM`, so adding a new AEAD mode
 * means (a) adding it here and (b) wiring the matching EVP_CIPHER_fetch
 * in the per-cipher switch.
 *
 * CCM is intentionally NOT here — CCM requires the total plaintext
 * length to be set BEFORE AAD is processed, which doesn't fit the
 * current streaming model. A separate code path is needed for CCM.
 */
static inline int is_aead_mode(uint32_t mode_id) {
    return mode_id == GCM || mode_id == OCB;
}


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
        case WRAP:
        case WRAP_PAD:
            // ECB takes no IV. AES key-wrap (RFC 3394) and key-wrap-with-padding
            // (RFC 5649) use a fixed default integrity check value, so no IV is
            // accepted here either.
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
        case OCB:
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

                case WRAP:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-WRAP",NULL);
                    break;
                case WRAP_PAD:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-WRAP-PAD",NULL);
                    break;

                // case CCM: Authenticated (requires upfront-length streaming model)
                case OCB:
                    // RFC 7253: OCB nonce MUST be 1..15 bytes (strictly
                    // less than the AES block size). OpenSSL enforces
                    // the same range.
                    if (iv_len < 1 || iv_len > 15) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-128-OCB",NULL);
                    break;
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
                case WRAP:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-WRAP",NULL);
                    break;
                case WRAP_PAD:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-WRAP-PAD",NULL);
                    break;

                // case CCM: Authenticated (requires upfront-length streaming model)
                case OCB:
                    // RFC 7253: OCB nonce MUST be 1..15 bytes.
                    if (iv_len < 1 || iv_len > 15) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-192-OCB",NULL);
                    break;
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

                case WRAP:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-WRAP",NULL);
                    break;
                case WRAP_PAD:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-WRAP-PAD",NULL);
                    break;

                // case CCM: Authenticated (requires upfront-length streaming model)
                case OCB:
                    // RFC 7253: OCB nonce MUST be 1..15 bytes.
                    if (iv_len < 1 || iv_len > 15) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "AES-256-OCB",NULL);
                    break;
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
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-128-GCM",NULL);
                    break;

                // case CCM: Authenticated
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
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-192-GCM",NULL);
                    break;

                // case CCM: Authenticated
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
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "ARIA-256-GCM",NULL);
                    break;

                // case CCM: Authenticated
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
        case DES_EDE3:
            // 3-key Triple DES (DES-EDE3). 24-byte key, 8-byte block.
            // Only ECB and CBC are in OpenSSL 3.5's default provider;
            // other DES-EDE3 modes (CFB*, OFB) live in legacy and are
            // intentionally not exposed here.
            ctx->cipher_block_size = BLOCK_SIZE_DES_EDE3;
            if (key_len != 24) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "DES-EDE3-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_DES_EDE3)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), "DES-EDE3-CBC",NULL);
                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // DES_EDE3
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

    // OpenSSL refuses to initialise a key-wrap cipher unless the context
    // explicitly opts in via EVP_CIPHER_CTX_FLAG_WRAP_ALLOW.
    if (ctx->mode_id == WRAP || ctx->mode_id == WRAP_PAD) {
        EVP_CIPHER_CTX_set_flags(ctx->evp, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    }


    switch (opp_mode) {
        case ENCRYPT_MODE:
            if (is_aead_mode(ctx->mode_id)) {

                if (OPS_FAILED_INIT_2 1 != EVP_EncryptInit_ex(ctx->evp, evp_cipher, NULL, NULL, NULL)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
                if (OPS_OPENSSL_ERROR_1 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_IVLEN, (int) ctx->iv_len,
                                                                 NULL)) {
                    ret_code = JO_OPENSSL_ERROR;
                    goto exit;
                }
                // OCB requires the tag length to be set BEFORE the key
                // (RFC 7253 permits non-default tag lengths; OpenSSL
                // defaults to 16 and applies EVP_CTRL_AEAD_SET_TAG with
                // a NULL buffer + the desired length to override).
                // GCM's tag length is enforced at doFinal-time by
                // Jostle's own buffer rather than via OpenSSL, so this
                // call is OCB-only.
                if (ctx->mode_id == OCB && ctx->tag_len > 0 && ctx->tag_len != 16) {
                    if (OPS_OPENSSL_ERROR_8 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_TAG, (int) ctx->tag_len, NULL)) {
                        ret_code = JO_OPENSSL_ERROR;
                        goto exit;
                    }
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
            if (is_aead_mode(ctx->mode_id)) {
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
                // See OCB tag-length note on the encrypt path above —
                // the same NULL-buffer SET_TAG call is needed on decrypt
                // so OpenSSL knows how many ciphertext bytes are the
                // payload vs. the tag.
                if (ctx->mode_id == OCB && ctx->tag_len > 0 && ctx->tag_len != 16) {
                    if (OPS_OPENSSL_ERROR_8 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_TAG, (int) ctx->tag_len, NULL)) {
                        ret_code = JO_OPENSSL_ERROR;
                        goto exit;
                    }
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


    if (!is_aead_mode(ctx->mode_id)) {
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

    if (ctx->mode_id == WRAP || ctx->mode_id == WRAP_PAD) {
        // Key-wrap output differs from the input by the 8-byte integrity block
        // in either direction. The output buffer is sized by get_update_size /
        // final_size, and OpenSSL fails closed on a short buffer.
    } else if (ctx->streaming == 0 && ctx->mode_id != XTS && ctx->tag_len == 0) {
        if (!ctx->initialized) {
            // cipher_block_size is unset (0) before init — the block-aware
            // check below would divide by zero. Keep the legacy in_len check
            // so the error-code precedence is unchanged; the
            // JO_NOT_INITIALIZED return below fires before any EVP call.
            if (out_len < in_len) {
                return JO_OUTPUT_TOO_SMALL;
            }
        } else {
            // Non-streaming block modes (ECB/CBC): EVP buffers partial blocks
            // across update calls, so a single update can emit MORE than
            // in_len (previously buffered bytes complete a block). Padded
            // decrypt additionally flushes the held-back final block and
            // writes the new candidate block before retracting it from the
            // reported count. Require the same bound
            // block_cipher_get_update_size advertises — a plain
            // `out_len < in_len` check let direct callers hand EVP a window
            // it writes past.
            size_t remaining = ctx->processed % ctx->cipher_block_size;
            size_t need = ctx->cipher_block_size * ((remaining + in_len) / ctx->cipher_block_size);
            if (ctx->op_mode == DECRYPT_MODE && ctx->padding == PADDED
                && ctx->processed >= ctx->cipher_block_size && remaining == 0) {
                // Held-back final block gets flushed ahead of the new data.
                need += ctx->cipher_block_size;
            }
            if (need < in_len) {
                need = in_len;
            }
            if (out_len < need) {
                return JO_OUTPUT_TOO_SMALL;
            }
        }
    } else if (ctx->op_mode == ENCRYPT_MODE || ctx->tag_len == 0) {
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
        if (ctx->mode_id == WRAP || ctx->mode_id == WRAP_PAD) {
            // RFC 3394 (KW) requires input that is a multiple of 8 bytes and at
            // least 16; RFC 5649 (KWP) accepts any length >= 1. OpenSSL enforces
            // these per-algorithm, so don't impose the 16-byte block alignment.
        } else if (ctx->mode_id == XTS) {
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
        if (is_aead_mode(ctx->mode_id)) {
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

    if (ctx->mode_id == WRAP || ctx->mode_id == WRAP_PAD) {
        // Key wrap is one-shot: the whole result is produced from the single
        // EVP update, so size the buffer for the complete operation here.
        size_t out;
        if (ctx->op_mode == ENCRYPT_MODE) {
            // KW appends one 8-byte integrity block; KWP first pads the
            // plaintext up to a multiple of 8, then appends the block.
            size_t padded = (ctx->mode_id == WRAP_PAD) ? (((len + 7u) / 8u) * 8u) : len;
            out = padded + 8u;
        } else {
            // Decrypt upper bound: strip the 8-byte integrity block. KWP may
            // remove a further 0-7 padding bytes; the Java SPI trims the buffer
            // to the actual decrypted length.
            out = (len >= 8u) ? (len - 8u) : 0u;
        }
        if (out > INT32_MAX) {
            return JO_OUTPUT_SIZE_INT_OVERFLOW;
        }
        return (int32_t) out;
    }

    if (ctx->streaming == 1) {
        switch (ctx->mode_id) {
            case GCM:
            case OCB:

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

        if (ctx->op_mode == DECRYPT_MODE) {
            // Padded decrypt: EVP retains the final ciphertext block across
            // update calls (released only by DecryptFinal after the padding
            // strip), and DecryptUpdate both flushes that held block to the
            // output AND writes the new candidate block before retracting it
            // from the reported count. The bytes the update+final pair may
            // touch are exactly `aligned` (whole blocks completed from
            // buffered + new input — written even when retracted from the
            // count) plus one block when a held-back block exists from a
            // prior update (processed a positive block multiple). The
            // encrypt-shaped formula said `total` and let EVP write past the
            // staged buffer (CBC_DECRYPT_UPDATE_BUFFERING_GAP.md). No
            // unconditional +block: one-shot callers legitimately size the
            // output at the ciphertext length, as SunJCE/BC permit.
            size_t aligned = total - left_over;
            size_t flush = (ctx->processed >= ctx->cipher_block_size && partial_block == 0)
                                   ? ctx->cipher_block_size : 0;
            len = aligned + flush;
        } else if (left_over == 0) {
            len = total + ctx->cipher_block_size;
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

        if (ctx->op_mode == DECRYPT_MODE) {
            // DecryptFinal releases the held-back final block (minus padding,
            // so up to block_size - 1 bytes) — but ONLY when the ciphertext
            // consumed so far is a whole number of blocks. A misaligned or
            // empty ciphertext makes DecryptFinal fail without writing, and
            // requiring capacity then would mask the JO_INVALID_CIPHER_TEXT
            // the caller should see.
            if (ctx->processed >= ctx->cipher_block_size && partial_block == 0) {
                len = ctx->cipher_block_size;
            }
        } else {
            // Encrypt: EncryptFinal emits the buffered partial block plus
            // padding — always exactly one block.
            len = ctx->cipher_block_size;
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

        if (is_aead_mode(ctx->mode_id)) {

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

        if (is_aead_mode(ctx->mode_id)) {
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
            if (is_aead_mode(ctx->mode_id)) {
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


    // Input overflow gate — `len` is a size_t from the caller, so on
    // 64-bit platforms it can exceed INT32_MAX. OPS_INT32_OVERFLOW_1
    // lets tests fault-inject the overflow path without having to
    // actually pass a 2GB+ value across the JNI/FFI boundary.
    if (OPS_INT32_OVERFLOW_1 len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    // Key wrap is one-shot — the entire wrapped/unwrapped result is written by
    // the single update call, so size it exactly as the final operation.
    if (ctx->mode_id == WRAP || ctx->mode_id == WRAP_PAD) {
        return final_size(ctx, len);
    }

    size_t result;

    // XTS with ciphertext stealing produces output of the same length as
    // input (regardless of block alignment), so size like a streaming mode.
    if (ctx->streaming || ctx->mode_id == XTS) {
        result = len;
    } else {
        // Block-cipher modes (padded or unpadded): the upper bound on
        // bytes that this update may write is one block per "completed"
        // block from buffered+new bytes. The buffered-bytes term applies
        // to BOTH padded and unpadded modes — unpadded mode also buffers
        // partial blocks at the EVP layer, even though Jostle currently
        // rejects sub-block update input via JO_NOT_BLOCK_ALIGNED.
        //
        // The auto-allocating Cipher.update(byte[], int, int) path
        // calls this with `len` and then invokes block_cipher_ctx_update
        // with the allocated buffer; that function's safety guard
        // `if (out_len < in_len) return JO_OUTPUT_TOO_SMALL` would
        // reject any sub-block update whose precise required output is
        // 0 bytes. Return max(aligned, len) so the auto-allocating
        // caller always passes the guard. The Java SPI trims the
        // returned buffer to the actually-written length.
        size_t remaining = ctx->processed % ctx->cipher_block_size;
        size_t aligned = ctx->cipher_block_size * ((remaining + len) / ctx->cipher_block_size);
        result = aligned > len ? aligned : len;

        if (ctx->op_mode == DECRYPT_MODE && ctx->padding == PADDED) {
            // Padded decrypt writes more than the encrypt-shaped `aligned`
            // bound: EVP flushes the held-back final block from a previous
            // update (one extra block at the head of the output, present
            // exactly when `processed` is a positive block multiple) and
            // writes the new candidate block before retracting it from the
            // reported count (covered by `aligned`). Without the flush term
            // EVP wrote past the staged buffer
            // (CBC_DECRYPT_UPDATE_BUFFERING_GAP.md).
            if (ctx->processed >= ctx->cipher_block_size && remaining == 0) {
                result = aligned + ctx->cipher_block_size;
            } else {
                result = aligned > len ? aligned : len;
            }
        }
    }

    // Output overflow gate — `aligned` is `block_size * ((remaining + len)
    // / block_size)`, which can in principle exceed `len` (and thus
    // INT32_MAX) when `remaining` is non-zero and `len` is close to the
    // limit. OPS_INT32_OVERFLOW_2 lets tests exercise this branch even
    // when the input passed the first gate.
    if (OPS_INT32_OVERFLOW_2 result > INT32_MAX) {
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
