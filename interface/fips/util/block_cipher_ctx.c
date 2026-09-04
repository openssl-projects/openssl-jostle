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
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include "ctr_u128_t.h"
#include "ops.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"



#define REQUIRE_IV_LEN(expected) if (iv_len != (expected)) return JO_INVALID_IV_LEN;


/**
 * AEAD-mode discriminator. GCM, OCB, and ChaCha20-Poly1305 (the synthetic
 * POLY1305 mode) all:
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
    return mode_id == GCM || mode_id == OCB || mode_id == POLY1305;
}


/*
 * Number of bytes a single update of `in_len` raw input bytes will actually
 * hand to the EVP layer, given the current tag-buffer fill. For AEAD decrypt
 * the trailing tag_len bytes of the ciphertext stream are withheld in
 * tag_buffer (they may still turn out to be the authentication tag), so only
 * the bytes that can no longer be the tag are fed. Encrypt and non-AEAD modes
 * feed every input byte.
 *
 * This is the pre-EVP feed count the OCB size accounting needs: OCB emits
 * whole blocks out of (buffered residue + fed), so `fed` — not the raw
 * in_len — is what drives how much OCB writes.
 */
/**
 * Modes whose EVP primitive is ONE-SHOT per message, so util accumulates the
 * whole message and hands OpenSSL a single call at the terminal operation
 * (the sanctioned exception in native-code.md's "One-shot EVP primitives
 * under a streaming JCA contract").
 *
 * Two modes, refusing chunked input for different reasons and with different
 * symptoms, both measured rather than assumed:
 *
 *   XTS  EVP re-derives the tweak from the head of every update call, so
 *        chunked delivery SILENTLY produced ciphertext matching a conforming
 *        implementation for the first chunk only.
 *   CTS  EVP accepts exactly one update, and only at >= one block; a second
 *        update is REFUSED, mutely (empty error queue). Ciphertext stealing
 *        needs the end of the message before any block can be emitted.
 *        Measured: fips-c-review/probes/cts_probe.c, Q5.
 *
 *   WRAP  RFC 3394 / RFC 5649 key wrap emits the ENTIRE result from one EVP
 *   KWP   update - there is no such thing as a partial wrap - so a chunked
 *   INV   caller got one independent wrap per update() call, concatenated.
 *         That output round-tripped through our own decrypt, which hid it from
 *         every roundtrip test; only comparison against an independent
 *         implementation showed it. Measured against BouncyCastle: one-shot
 *         byte-perfect, chunked garbage whose length grew with the number of
 *         update() calls.
 *
 * Everything downstream keys off this rather than naming a mode, so the four
 * obligations stay in one place: update emits nothing and needs no output
 * capacity, final_size reports the whole emission, the length minimum is
 * checked against the accumulated total, and the buffer is cleansed on init
 * and after the terminal call.
 *
 * The wrap modes satisfy those four differently from XTS/CTS, and each
 * difference is named at the site that cares: their emission is NOT the
 * accumulated length (final_size), their length rule is the RFCs' rather than
 * one cipher block (wrap_length_check), and an integrity failure is an
 * expected outcome that must leave the object reusable instead of poisoned,
 * and must be typed as a ciphertext failure (block_cipher_ctx_final).
 */

/* Defined below; needed by final_size's wrap sizing and the accum capacity guard. */
int32_t final_size(block_cipher_ctx *ctx, size_t len);

/*
 * The AES key-wrap modes: RFC 3394 (WRAP), RFC 5649 (WRAP_PAD), and RFC 3394
 * on the inverse cipher function (WRAP_INV, SP 800-38F 5.1).
 *
 * All three share what the call sites below care about: no IV (a fixed
 * default ICV), one-shot emission from a single EVP update, and an 8-byte
 * integrity block. Only the plaintext padding and the length rule differ, and
 * both differences are WRAP_PAD's alone, named where they matter (final_size
 * and wrap_length_check).
 */
static inline int is_wrap_mode(uint32_t mode_id) {
    return mode_id == WRAP || mode_id == WRAP_PAD || mode_id == WRAP_INV;
}


static inline int mode_accumulates(uint32_t mode_id) {
    return mode_id == XTS || mode_id == CTS || is_wrap_mode(mode_id);
}


/*
 * RFC 3394 / RFC 5649 length rules for the key-wrap modes, checked explicitly
 * at the terminal call rather than delegated to OpenSSL.
 *
 * Two reasons, and both must survive anyone tempted to "simplify" this back
 * into delegation:
 *
 *   1. EXCEPTION TYPE. OpenSSL refuses these lengths correctly, but as a
 *      generic error - the caller sees OpenSSLException where BouncyCastle
 *      raises IllegalBlockSizeException on the wrap side and
 *      BadPaddingException on the unwrap side. BC's types are the de facto
 *      standard callers catch on, so the length decisions have to be ours in
 *      order for the types to be ours.
 *   2. MEMORY SAFETY. Wraps were briefly exempted from the accumulating
 *      length minimum altogether, on the reasoning that OpenSSL enforced the
 *      real rules anyway. A zero-length total then reached EVP with no
 *      accumulator allocated at all and crashed the JVM.
 *
 * OpenSSL stays behind these as the backstop; nothing here replaces it.
 */
static int32_t wrap_length_check(block_cipher_ctx *ctx, size_t total) {
    if (ctx->op_mode == ENCRYPT_MODE) {
        if (ctx->mode_id == WRAP_PAD) {
            // RFC 5649: any length from one byte up.
            return total < 1 ? JO_WRAP_INPUT_LENGTH_INVALID : JO_SUCCESS;
        }
        // RFC 3394, also on the inverse cipher function (SP 800-38F 5.1):
        // n >= 2 semiblocks.
        //
        // BouncyCastle accepts a SINGLE semiblock here and returns 16 bytes;
        // OpenSSL refuses it. We adhere to OpenSSL (Megan, 2026-08-31), so an
        // 8-byte KW wrap is refused - typed, now, rather than opaquely.
        // AESKeyWrapTest pins the divergence in both directions so neither a
        // drift toward BC nor a future BC-parity sweep can erase it silently.
        if (total < 16 || (total % 8) != 0) {
            return JO_WRAP_INPUT_LENGTH_INVALID;
        }
        return JO_SUCCESS;
    }

    // Unwrap. The wrapped blob is semiblock-aligned and carries one extra
    // semiblock of integrity data, so KW's minimum ciphertext is three
    // semiblocks (its plaintext minimum being two) and KWP's is two (its
    // plaintext minimum of one byte padding up to a single semiblock).
    //
    // JO_INVALID_CIPHER_TEXT, not the wrap-side code: BouncyCastle answers the
    // unwrap side with BadPaddingException. An integrity failure at a LEGAL
    // length reaches the same code by a different route, in
    // block_cipher_ctx_final, so both unwrap failure modes present one type to
    // the caller.
    if (total < ((ctx->mode_id == WRAP_PAD) ? 16u : 24u) || (total % 8) != 0) {
        return JO_INVALID_CIPHER_TEXT;
    }
    return JO_SUCCESS;
}


static inline size_t evp_fed_bytes(block_cipher_ctx *ctx, size_t in_len) {
    if (ctx->op_mode == DECRYPT_MODE && is_aead_mode(ctx->mode_id) && ctx->tag_len > 0) {
        size_t have = (size_t) ctx->tag_index + in_len;
        return have > ctx->tag_len ? have - ctx->tag_len : 0;
    }
    return in_len;
}

/*
 * Maximum number of bytes OCB will write when `fed` bytes reach the EVP layer
 * on top of the currently-buffered residue: it emits only whole blocks and
 * keeps the remainder buffered. cipher_block_size is a power of two (16 for
 * AES-OCB) and non-zero once initialised.
 */
static inline size_t ocb_update_out(block_cipher_ctx *ctx, size_t fed) {
    return ctx->cipher_block_size * ((ctx->buffered + fed) / ctx->cipher_block_size);
}


/*
 * Drop whatever the XTS accumulation buffer holds, cleansing it first. Called
 * on every init (the JCA reset path reuses the ctx across data units) and on
 * the final path once the unit has been consumed, so a plaintext data unit
 * never outlives the operation that produced it. The allocation itself is
 * kept — the next data unit is usually the same size, and reusing it avoids a
 * malloc per sector.
 */
/** Bytes currently accumulated. NULL-safe: no buffer means nothing buffered. */
static inline size_t accum_len(const block_cipher_ctx *ctx) {
    return ctx->accum == NULL ? 0 : ctx->accum->length;
}


/**
 * Drop whatever is accumulated, cleansing it first.
 *
 * The explicit OPENSSL_cleanse is deliberate and is NOT redundant with
 * BUF_MEM_grow_clean's shrink path: that path zeroes with a plain memset,
 * which is the one thing native-code.md forbids for secret material. The risk
 * is remote here (the buffer outlives the call, so the store is not obviously
 * dead, and libcrypto is a separate compilation unit) — but "remote" is not a
 * reason to delegate the decision. Cleanse ourselves, then shrink.
 *
 * Capacity is retained: the JCA reset path reuses one ctx across messages, and
 * re-growing for every message would be pointless churn.
 */
static void accum_discard(block_cipher_ctx *ctx) {
    if (ctx->accum == NULL) {
        return;
    }
    if (ctx->accum->length > 0) {
        OPENSSL_cleanse(ctx->accum->data, ctx->accum->length);
    }
    BUF_MEM_grow_clean(ctx->accum, 0);
}


/*
 * Append a chunk to the XTS accumulation buffer, growing it if needed.
 *
 * Growth is malloc + copy + OPENSSL_clear_free of the old block rather than
 * OPENSSL_realloc: realloc would abandon the previous plaintext copy
 * uncleansed, while every other release of this buffer clear-frees. Capacity
 * doubles so a caller feeding a sector in small chunks does not pay a copy per
 * chunk.
 *
 * The total is bounded at INT32_MAX because the byte count returns to Java as
 * an int32_t. OpenSSL's own SP 800-38E data-unit cap (2^20 blocks) is left to
 * OpenSSL — pre-checking it here would duplicate a limit the provider already
 * enforces and names in its own error.
 */
static int32_t accum_append(block_cipher_ctx *ctx, uint8_t *input, size_t in_len) {
    if (in_len == 0) {
        return JO_SUCCESS;
    }

    // Our own bound, checked before BUF_MEM sees the length, so the typed code
    // is deterministic. BUF_MEM refuses at its own LIMIT_BEFORE_EXPANSION
    // (0x5ffffffc) and RAISES while doing so; without this check a message
    // between that limit and INT32_MAX would surface as JO_OPENSSL_ERROR
    // instead of the length-specific code.
    if (in_len > (size_t) INT32_MAX - accum_len(ctx)) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    if (ctx->accum == NULL) {
        ctx->accum = BUF_MEM_new();
        if (OPS_OPENSSL_ERROR_10 ctx->accum == NULL) {
            // Allocation failure. JO_OPENSSL_ERROR is what the util layer
            // returns for a failed allocation elsewhere (ec.c is the
            // precedent); nothing has been consumed, so a later call can retry.
            return JO_OPENSSL_ERROR;
        }
    }

    size_t offset = ctx->accum->length;
    size_t needed = offset + in_len;

    /*
     * Extend to `needed`. The accumulated bytes are PRESERVED, not just made
     * room for: when capacity has to grow, BUF_MEM_grow_clean reallocates via
     * OPENSSL_clear_realloc, which mallocs the new block, memcpy's the old
     * contents across, and then CLEANSES and frees the old block - so no
     * previous copy of the plaintext is left in freed heap. When capacity is
     * already sufficient it does not reallocate at all. Either way only the
     * newly exposed region [old length, needed) is zeroed, and the memcpy
     * below immediately overwrites exactly that region.
     *
     * On allocation failure it returns 0 with data/max/length all unchanged
     * (OPENSSL_clear_realloc does not free the old block when the new malloc
     * fails), so the accumulator is left intact and a later call can retry.
     */
    if (OPS_OPENSSL_ERROR_11 BUF_MEM_grow_clean(ctx->accum, needed) != needed) {
        return JO_OPENSSL_ERROR;
    }

    memcpy(ctx->accum->data + offset, input, in_len);
    return JO_SUCCESS;
}


/*
 * Diagnosis-on-failure for a refused Triple-DES ENCRYPT init.
 *
 * OpenSSL's FIPS module, configured with "tdes-encrypt-disabled", refuses TDES
 * encryption at EVP_EncryptInit_ex and returns 0 WITHOUT raising - the error
 * queue is left empty, so a generic JO_OPENSSL_ERROR reaches Java as
 * "OpenSSL Error: null". That is the DSA-signing shape, not the PKCS#1 one
 * (whose refusal self-names "invalid padding mode"), so it earns a typed code.
 *
 * The property being named is "this provider decrypts Triple-DES but will not
 * encrypt it", and it is asked directly: the SAME cipher, key and IV are
 * re-driven on two fresh contexts, one per direction. Both halves are required.
 * Probing only decrypt would misreport any other encrypt-side failure as the
 * capability gate, and would also mis-classify an operations-test-injected
 * failure - the OPS macro lives at the call site, not here, so an injected
 * failure re-probes as "encrypt works" and correctly stays generic.
 *
 * Fresh contexts because the caller's ctx->evp may be left in an undefined
 * state by the failed init. ERR_set_mark / ERR_pop_to_mark so the probe's own
 * noise cannot disturb the primary error report.
 */
static int32_t classify_tdes_encrypt_init_failure(EVP_CIPHER *evp_cipher, uint8_t *key, uint8_t *iv) {
    EVP_CIPHER_CTX *enc_probe = NULL;
    EVP_CIPHER_CTX *dec_probe = NULL;
    int enc_ok = 0;
    int dec_ok = 0;

    ERR_set_mark();

    enc_probe = EVP_CIPHER_CTX_new();
    dec_probe = EVP_CIPHER_CTX_new();
    if (enc_probe == NULL || dec_probe == NULL) {
        EVP_CIPHER_CTX_free(enc_probe);
        EVP_CIPHER_CTX_free(dec_probe);
        ERR_pop_to_mark();
        return JO_OPENSSL_ERROR;
    }

    enc_ok = EVP_EncryptInit_ex(enc_probe, evp_cipher, NULL, key, iv);
    dec_ok = EVP_DecryptInit_ex(dec_probe, evp_cipher, NULL, key, iv);

    EVP_CIPHER_CTX_free(enc_probe);
    EVP_CIPHER_CTX_free(dec_probe);
    ERR_pop_to_mark();

    if (enc_ok != 1 && dec_ok == 1) {
        return JO_TDES_ENCRYPT_UNAVAILABLE;
    }
    return JO_OPENSSL_ERROR;
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

    /*
     * Ciphertext stealing IS the answer to a partial final block, so a padding
     * scheme on top is a contradiction, not a redundancy: padded plaintext is
     * always a block multiple, the stealing becomes a no-op, and the result is
     * ordinary CBC that no CTS peer can read. Refuse here so the NI surface is
     * closed too - the SPI refuses it at engineSetPadding, but that path is
     * only reached through JCE form-4 lookup.
     */
    if (mode_Id == CTS && padding == PADDED) {
        *err = JO_MODE_TAKES_NO_PADDING;
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
    ctx->buffered = 0;
    // Clear any tag bytes buffered from a previous decrypt session.
    OPENSSL_cleanse(ctx->tag_buffer, MAX_TAG_LEN);

    /*
     * Modes that do not take an iv
     */

    switch (ctx->mode_id) {
        case ECB:
        case WRAP:
        case WRAP_PAD:
        case WRAP_INV:
            // ECB takes no IV. AES key-wrap (RFC 3394), key-wrap-with-padding
            // (RFC 5649) and the inverse-cipher wrap (SP 800-38F 5.1) all use a
            // fixed default integrity check value, so no IV is accepted here
            // either.
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
        case POLY1305:
        case STREAM:
            // GCM/OCB/POLY1305 are AEAD streaming modes; STREAM is the raw
            // ChaCha20 stream cipher (block size 1). All skip the block-
            // accounting paths (which divide/modulo by cipher_block_size and
            // would misbehave for a block size of 1).
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-CBC",NULL);
                    break;
                case CTS:
                    // CBC with ciphertext stealing. The cts_mode variant is
                    // pinned to CS3 after init - see the block comment there.
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-CBC-CTS",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_AES) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-CTR",NULL);

                    break;
                case XTS:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-XTS",NULL);
                    break;

                case WRAP:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-WRAP",NULL);
                    break;
                case WRAP_PAD:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-WRAP-PAD",NULL);
                    break;
                case WRAP_INV:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-WRAP-INV",NULL);
                    break;

                // case CCM: Authenticated (requires upfront-length streaming model)
                case OCB:
                    // RFC 7253: OCB nonce MUST be 1..15 bytes (strictly
                    // less than the AES block size). OpenSSL enforces
                    // the same range.
                    if (iv_len < 1 || iv_len > 15) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-OCB",NULL);
                    break;
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-128-GCM",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-CBC",NULL);
                    break;
                case CTS:
                    // CBC with ciphertext stealing. The cts_mode variant is
                    // pinned to CS3 after init - see the block comment there.
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-CBC-CTS",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_AES) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-CTR",NULL);

                    break;
                case WRAP:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-WRAP",NULL);
                    break;
                case WRAP_PAD:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-WRAP-PAD",NULL);
                    break;
                case WRAP_INV:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-WRAP-INV",NULL);
                    break;

                // case CCM: Authenticated (requires upfront-length streaming model)
                case OCB:
                    // RFC 7253: OCB nonce MUST be 1..15 bytes.
                    if (iv_len < 1 || iv_len > 15) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-OCB",NULL);
                    break;
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-192-GCM",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-CBC",NULL);
                    break;
                case CTS:
                    // CBC with ciphertext stealing. The cts_mode variant is
                    // pinned to CS3 after init - see the block comment there.
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-CBC-CTS",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_AES) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-CTR",NULL);

                    break;
                case XTS:
                    REQUIRE_IV_LEN(BLOCK_SIZE_AES)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-XTS",NULL);
                    break;

                case WRAP:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-WRAP",NULL);
                    break;
                case WRAP_PAD:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-WRAP-PAD",NULL);
                    break;
                case WRAP_INV:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-WRAP-INV",NULL);
                    break;

                // case CCM: Authenticated (requires upfront-length streaming model)
                case OCB:
                    // RFC 7253: OCB nonce MUST be 1..15 bytes.
                    if (iv_len < 1 || iv_len > 15) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-OCB",NULL);
                    break;
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "AES-256-GCM",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-128-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-128-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-128-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-128-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-128-CFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_ARIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-128-CTR",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-128-OFB",NULL);
                    break;
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-128-GCM",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-192-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-192-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-192-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-192-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-192-CFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_ARIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-192-CTR",NULL);

                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-192-OFB",NULL);
                    break;
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-192-GCM",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-256-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-256-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-256-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-256-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-256-CFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_ARIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-256-CTR",NULL);

                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_ARIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-256-OFB",NULL);
                    break;
                case GCM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ARIA-256-GCM",NULL);
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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-128-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-128-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-128-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-128-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-128-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-128-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_CAMELLIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-128-CTR",NULL);

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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-192-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-192-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-192-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-192-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-192-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-192-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_CAMELLIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-192-CTR",NULL);

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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-256-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-256-CBC",NULL);
                    break;
                case CFB1:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-256-CFB1",NULL);
                    break;
                case CFB8:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-256-CFB8",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-256-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_CAMELLIA)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-256-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_CAMELLIA) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "CAMELLIA-256-CTR",NULL);

                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // CAMELLIA256

        case CHACHA20:
            // Raw ChaCha20 stream cipher (RFC 8439). Block size 1: no padding,
            // no block alignment — the STREAM mode set ctx->streaming above so
            // the block-accounting paths are skipped. 256-bit key. The caller
            // supplies a bare 12-byte nonce; the 16-byte EVP IV
            // (counter || nonce) is assembled just before EVP init below.
            ctx->cipher_block_size = 1;
            if (key_len != 32) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case STREAM:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    // Raw ChaCha20 is unauthenticated — it has no tag. Reject a
                    // non-zero tag at the NI surface so the contract is explicit
                    // and the tag-len-dependent size paths (internal_final_size
                    // gates on tag_len > 0) stay consistent with the AEAD arm
                    // below, which pins tag_len == 16.
                    if (ctx->tag_len != 0) {
                        return JO_INVALID_TAG_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ChaCha20",NULL);
                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // CHACHA20

        case CHACHA20_POLY1305:
            // ChaCha20-Poly1305 AEAD (RFC 8439). A stream cipher (block size 1)
            // with a built-in Poly1305 authenticator; rides the generic AEAD
            // streaming path (is_aead_mode includes POLY1305) so update()
            // processes incrementally with no buffering. 256-bit key, 96-bit
            // nonce, 128-bit tag. Unlike raw ChaCha20, OpenSSL's
            // "ChaCha20-Poly1305" takes the 12-byte nonce directly (no counter
            // prefix) — so this falls through to the generic iv_for_openssl = iv
            // path below, NOT the 16-byte-IV construction.
            ctx->cipher_block_size = 1;
            if (key_len != 32) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case POLY1305:
                    if (iv_len != 12) {
                        return JO_INVALID_IV_LEN;
                    }
                    // RFC 8439 fixes the tag at 128 bits and OpenSSL only
                    // produces 16. Pin it at the NI surface so a truncated-tag
                    // request cannot weaken authentication (the SPI enforces
                    // this too). tag_len was range-checked into [0, MAX_TAG_LEN]
                    // near the top of init.
                    if (ctx->tag_len != 16) {
                        return JO_INVALID_TAG_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "ChaCha20-Poly1305",NULL);
                    break;
                default:
                    return JO_INVALID_MODE;
            }
            break; // CHACHA20_POLY1305

        case SM4:
            ctx->cipher_block_size = BLOCK_SIZE_SM4;
            if (key_len != 16) {
                return JO_INVALID_KEY_LEN;
            }
            switch (ctx->mode_id) {
                case ECB:
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "SM4-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_SM4)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "SM4-CBC",NULL);
                    break;
                case CFB128:
                    REQUIRE_IV_LEN(BLOCK_SIZE_SM4)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "SM4-CFB",NULL);
                    break;
                case OFB:
                    REQUIRE_IV_LEN(BLOCK_SIZE_SM4)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "SM4-OFB",NULL);
                    break;
                case CTR:
                    if (valid_for_ctr(iv_len, BLOCK_SIZE_SM4) < JO_SUCCESS) {
                        return JO_INVALID_IV_LEN;
                    }
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "SM4-CTR",NULL);

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
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "DES-EDE3-ECB",NULL);
                    break;
                case CBC:
                    REQUIRE_IV_LEN(BLOCK_SIZE_DES_EDE3)
                    evp_cipher = EVP_CIPHER_fetch(get_global_jostle_fips_ossl_lib_ctx(), "DES-EDE3-CBC",NULL);
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

    uint8_t chacha_iv[16];
    uint8_t *iv_for_openssl = NULL;
    if (CTR == ctx->mode_id) {
        counter_init(ctx->counter, iv, iv_len);
        iv_for_openssl = ctx->counter->original_counter;
    } else if (CHACHA20 == ctx->cipher_id) {
        // OpenSSL's "ChaCha20" IV is 16 bytes: a 32-bit little-endian block
        // counter followed by the 96-bit nonce (RFC 8439 sec 2.4). The bridge
        // supplies the bare 12-byte nonce (validated == 12 above) with an
        // implicit counter of 0 — matching BouncyCastle's CHACHA7539 and
        // SunJCE's ChaCha20 — so prepend four zero counter bytes. last_iv still
        // holds the 12-byte nonce, so the reset path rebuilds this correctly.
        chacha_iv[0] = chacha_iv[1] = chacha_iv[2] = chacha_iv[3] = 0;
        memcpy(chacha_iv + 4, iv, 12);
        iv_for_openssl = chacha_iv;
    } else {
        // A zero-length IV is NO IV. block_cipher_ctx_final's reset re-inits
        // from ctx->last_iv, an array member and so never NULL, and the wrap
        // providers read a non-NULL IV as an explicit ICV - overwriting RFC
        // 3394's A6A6A6A6A6A6A6A6 with zeros. The first wrap on an instance
        // was then correct and every later one silently wrong, yet stable and
        // self-round-tripping: only a reuse test against an independent
        // implementation sees it (AESKeyWrapTest
        // .oneInstanceStaysCorrectAcrossOperationsAndAfterFailure).
        iv_for_openssl = (iv_len == 0) ? NULL : iv;
    }

    // OpenSSL refuses to initialise a key-wrap cipher unless the context
    // explicitly opts in via EVP_CIPHER_CTX_FLAG_WRAP_ALLOW.
    if (is_wrap_mode(ctx->mode_id)) {
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
                    if (ctx->cipher_id == DES_EDE3) {
                        // A FIPS module with tdes-encrypt-disabled refuses this
                        // call and raises nothing, so classify: the caller
                        // should learn the direction is gated rather than read
                        // "OpenSSL Error: null".
                        ret_code = classify_tdes_encrypt_init_failure(evp_cipher, key, iv_for_openssl);
                    }
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

    /*
     * Pin the CTS variant explicitly. SECURITY/INTEROP-CRITICAL — do not
     * change the value, and do not remove the set in favour of the default.
     *
     * OpenSSL's default cts_mode is CS1 on every environment measured
     * (mainline 3.5.7, FIPS 3.1.2, FIPS 3.5.7 default and -pedantic:
     * fips-c-review/probes/cts_probe.c). BouncyCastle's AES/CTS/NoPadding —
     * and its AES/CBC/CS3Padding, which agrees with it byte for byte — is
     * CS3. So unlike the usual application of the hard-code rule, this pin is
     * not defensive against a future default changing: inheriting today's
     * default would make every message with a partial final block
     * non-interoperable with BouncyCastle, Kerberos (RFC 3962) and anything
     * else speaking CS3, from the first line of ciphertext.
     *
     * The three variants relate as follows, which is why the parity test has
     * to cover BOTH shapes: on a PARTIAL final block CS2 and CS3 agree and
     * CS1 differs; on a FULL final block CS1 and CS2 agree and CS3 differs
     * (it swaps the last two blocks). A test that only ever feeds partial
     * final blocks cannot tell CS3 from CS2.
     *
     * Capability-probe before setting, per the fail-loud rule:
     * EVP_CIPHER_CTX_set_params SILENTLY IGNORES an unknown parameter and
     * still returns 1, so against a provider that did not implement cts_mode
     * the pin would be a no-op and the guard would never fire. Every
     * supported environment lists it as settable, so this branch does not
     * fire today — it exists so that a provider which cannot honour the
     * request is refused rather than served CS1 ciphertext under a CS3 name.
     */
    if (ctx->mode_id == CTS) {
        const OSSL_PARAM *settable = EVP_CIPHER_CTX_settable_params(ctx->evp);
        OSSL_PARAM cts_params[2];

        if (OPS_FAILED_SET_2 settable == NULL
                || OSSL_PARAM_locate_const(settable, OSSL_CIPHER_PARAM_CTS_MODE) == NULL) {
            ret_code = JO_CTS_MODE_UNAVAILABLE;
            goto exit;
        }

        cts_params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_CIPHER_PARAM_CTS_MODE, (char *) OSSL_CIPHER_CTS_MODE_CS3, 0);
        cts_params[1] = OSSL_PARAM_construct_end();

        if (OPS_FAILED_SET_1 1 != EVP_CIPHER_CTX_set_params(ctx->evp, cts_params)) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;
        }
    }


    ctx->processed = 0;
    // The JCA reset path reuses one ctx across messages, so a partially
    // accumulated XTS data unit or CTS message must not survive into the
    // next operation.
    accum_discard(ctx);
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


    if (OPS_INT32_OVERFLOW_1 in_len > INT32_MAX) {
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


/*
 * A one-shot key-wrap operation failed inside EVP. Recover rather than poison,
 * and leave the error queue alone.
 *
 * Poisoning suits a mid-stream EVP failure, where the cipher state is
 * undefined. A wrap is one update, and its real failure is the ordinary
 * integrity check - wrong KEK, damaged blob. Poisoning killed the Cipher for
 * good: block_cipher_ctx_init returns JO_CTX_POISONED before doing anything,
 * so even Cipher.init() could not revive it.
 *
 * Re-init in place, NOT via block_cipher_ctx_init: that opens with
 * ERR_clear_error() and would discard the failure the caller is about to be
 * told about, reporting it as "OpenSSL Error: null" - which elsewhere means an
 * OPS-injected failure. The mark/pop keeps the original error and drops only
 * the re-init's own noise; on re-init failure clear_last_mark keeps both.
 *
 * The wrap providers hold no per-update state, so the key re-schedule plus
 * processed = 0 is the whole reset; WRAP_ALLOW is a ctx flag and survives.
 */
/*
 * The ERR mark/pop discipline below is UNGUARDED BY TESTS since 2026-08-31.
 * Its only observable was the OpenSSL queue text reaching Java in the unwrap
 * failure message; that message is now the typed "invalid cipher text", so no
 * Java-side or OPS-side assertion can see a scrubbed queue any more. The two
 * ways to break it are dropping the mark/pop pair, and calling
 * block_cipher_ctx_init here (it opens with ERR_clear_error). Both are
 * review-visible and neither is caught by the suite: reviewer attention
 * required on any edit to this function.
 */
static int32_t wrap_recover_after_failure(block_cipher_ctx *ctx) {
    int ok;

    ERR_set_mark();
    if (ctx->op_mode == ENCRYPT_MODE) {
        ok = EVP_EncryptInit_ex(ctx->evp, NULL, NULL, ctx->last_key, NULL);
    } else {
        ok = EVP_DecryptInit_ex(ctx->evp, NULL, NULL, ctx->last_key, NULL);
    }

    if (1 != ok) {
        ERR_clear_last_mark();
        ctx->poisoned = 1;
        return JO_OPENSSL_ERROR;
    }

    ERR_pop_to_mark();
    ctx->processed = 0;
    return JO_OPENSSL_ERROR;
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

    if (OPS_INT32_OVERFLOW_1 in_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    if (OPS_INT32_OVERFLOW_2 out_len > INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    // Bytes this update will hand to EVP (tag-buffer withholding applied for
    // AEAD decrypt). Captured before the tag-buffer state is mutated below so
    // it also drives the OCB buffered-residue bookkeeping after the EVP call.
    const size_t evp_fed = evp_fed_bytes(ctx, in_len);

    // Wrap modes take NO output capacity here: they accumulate (see
    // mode_accumulates) and emit at final. The CVE-2026-63072 capacity guard
    // that used to live here MOVED to the accumulating branch of
    // block_cipher_ctx_final - it was not dropped. Leaving it here as well
    // would demand a window the correctly-sized caller allocates as zero.
    if (ctx->mode_id == OCB) {
        // OCB is an AEAD mode but NOT a pure stream: it buffers up to
        // (block-1) bytes internally and can flush a previously-buffered
        // partial block on this update, so a single update may emit MORE than
        // the bytes fed this call. EVP_{Encrypt,Decrypt}Update is handed
        // outsize = in_len + block_size by the EVP layer (not the caller's
        // real buffer), so OpenSSL's own short-buffer check does not protect
        // this window — the guard has to live here. Require exactly the
        // whole-block amount OCB will write, which is what
        // block_cipher_get_update_size advertises.
        if (!ctx->initialized) {
            // Preserve the legacy pre-init precedence (JO_OUTPUT_TOO_SMALL
            // ahead of the JO_NOT_INITIALIZED below); ocb_update_out needs a
            // non-zero cipher_block_size, unset until init.
            if (out_len < in_len) {
                return JO_OUTPUT_TOO_SMALL;
            }
        } else if (out_len < ocb_update_out(ctx, evp_fed)) {
            return JO_OUTPUT_TOO_SMALL;
        }
    } else if (mode_accumulates(ctx->mode_id)) {
        // Accumulating modes write nothing on update — the message is
        // buffered and emitted whole at final — so they need no output
        // capacity here. The ordering matters: this must precede the generic
        // `out_len < in_len` arm below, which would otherwise demand a
        // window the caller has correctly sized to zero.
    } else if (ctx->streaming == 0 && ctx->tag_len == 0) {
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

    // Accumulate instead of feeding EVP — see mode_accumulates. Emits
    // nothing here: the size functions report 0 for such an update and the
    // whole message at final. The length minimum is therefore checked at
    // final, once the total is known, not per chunk.
    if (mode_accumulates(ctx->mode_id)) {
        int32_t append_rc = accum_append(ctx, input, in_len);
        if (append_rc < 0) {
            return append_rc;
        }
        return 0;
    }

    // No per-chunk block-alignment check. EVP buffers a partial block across
    // update calls, so 8 bytes then 8 more is a legal 16-byte message that
    // this check used to refuse - a divergence from BouncyCastle and SunJCE,
    // both of which buffer (measured). The alignment requirement is real but
    // applies to the TOTAL, so it is checked in block_cipher_ctx_final once
    // the total is known. Wrap modes never reach here at all: they accumulate
    // and return above.

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
            // No wrap arm here: wrap modes accumulate and never reach this
            // call. Their recovery lives on the final path.
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
                // No wrap arm here: wrap modes accumulate and never reach
                // this call. Their recovery lives on the final path.
                ctx->poisoned = 1;
                return JO_OPENSSL_ERROR;
            }
        }
    } else {
        return JO_INVALID_OP_MODE;
    }

    // OCB keeps whatever did not complete a block buffered inside EVP; track
    // that residue so the size functions know how much a later update/final
    // will still emit. `evp_fed` is the pre-mutation feed count captured above
    // (the decrypt path mutates in_len). Other modes buffer via `processed`.
    if (ctx->mode_id == OCB) {
        ctx->buffered = (ctx->buffered + evp_fed) % ctx->cipher_block_size;
    }

    ctx->processed += in_len;
    return written;
}


int32_t final_size(block_cipher_ctx *ctx, size_t len) {
    if (len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    if (is_wrap_mode(ctx->mode_id)) {
        // Key wrap is one-shot: the whole result is produced from the single
        // EVP update at final, so size the buffer for the complete operation.
        //
        // Must precede the generic accumulating arm below, which reports the
        // accumulated length - right for XTS/CTS, wrong for a wrap, whose
        // output length differs from its input length in both directions.
        const size_t total = accum_len(ctx) + len;
        size_t out;
        if (ctx->op_mode == ENCRYPT_MODE) {
            // KW appends one 8-byte integrity block; KWP first pads the
            // plaintext up to a multiple of 8, then appends the block.
            size_t padded = (ctx->mode_id == WRAP_PAD) ? (((total + 7u) / 8u) * 8u) : total;
            out = padded + 8u;
        } else {
            // The whole input length, NOT (total - 8).
            //
            // On its integrity-failure path the AES key-unwrap primitive
            // writes and cleanses up to `total` bytes of the output buffer -
            // measured for WRAP_PAD on mainline 3.6.2 and FIPS 3.5.8
            // (fips-c-review/probes/wrap_unwrap_overflow_probe.c), and the
            // same behaviour behind CVE-2026-63072, whose OpenSSL fix sizes
            // its own buffer the same way. EVP_DecryptUpdate takes no output
            // capacity, so a (total - 8) buffer is simply overrun by 8 bytes -
            // and since the JNI bridge hands OpenSSL a critical pointer
            // straight into the caller's byte[], that is a write past the end
            // of a Java array.
            //
            // Over-reporting is safe: getOutputSize is an upper bound by
            // contract, and the SPI trims to the written length.
            out = total;
        }
        if (out > INT32_MAX) {
            return JO_OUTPUT_SIZE_INT_OVERFLOW;
        }
        return (int32_t) out;
    }

    // Accumulating modes emit everything at final: whatever previous updates
    // buffered, plus the bytes this doFinal call is about to append. Both XTS
    // and CTS steal ciphertext, so output length equals input length exactly.
    if (mode_accumulates(ctx->mode_id)) {
        size_t out = accum_len(ctx) + len;
        if (out > INT32_MAX) {
            return JO_OUTPUT_SIZE_INT_OVERFLOW;
        }
        return (int32_t) out;
    }


    if (ctx->streaming == 1) {
        switch (ctx->mode_id) {
            case GCM:
            case OCB:
            case POLY1305:

                if (ctx->tag_len > 0) {
                    if (ctx->op_mode == ENCRYPT_MODE) {
                        // All currently-buffered bytes (OCB residue; 0 for the
                        // stream AEADs) plus the new plaintext become
                        // ciphertext, and the tag is appended.
                        len = ctx->buffered + len + ctx->tag_len;
                    } else if (ctx->op_mode == DECRYPT_MODE) {
                        // Plaintext emitted over this doFinal = the EVP residue
                        // already buffered (OCB) plus the bytes this input will
                        // feed to EVP. evp_fed_bytes accounts for the tag_len
                        // bytes withheld in tag_buffer INCLUDING any held from
                        // prior update() calls (tag_index) — the previous
                        // `len - tag_len` ignored tag_index and under-sized the
                        // buffer whenever data had been streamed in first.
                        len = ctx->buffered + evp_fed_bytes(ctx, len);
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



    // NoPadding block modes retain a partial block across update() calls exactly
    // as padded ones do, but reached no arm above and reported `len` alone — so a
    // doFinal after a sub-block update was sized short and the write refused as
    // JO_OUTPUT_TOO_SMALL, surfacing to the caller as IllegalBlockSizeException
    // where BouncyCastle succeeds (MT-63; 10 registered names, both bridges).
    //
    // Written as an explicit case, not an else: it must not reach the wrap,
    // accumulating or streaming paths above, which size on different rules.
    // Over-reporting is the safe direction — getOutputSize is an upper bound by
    // contract and the SPI trims to the written length.
    if (ctx->padding == NO_PADDING && ctx->streaming == 0
        && ctx->cipher_block_size > 0) {
        size_t out = len + (ctx->processed % ctx->cipher_block_size);
        if (out > INT32_MAX) {
            return JO_OUTPUT_SIZE_INT_OVERFLOW;
        }
        return (int32_t) out;
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
            // EncryptFinal flushes the EVP residue (OCB; 0 for stream AEADs)
            // and the tag is appended.
            len = ctx->buffered + ctx->tag_len;
        } else if (ctx->op_mode == DECRYPT_MODE) {
            // DecryptFinal flushes the EVP residue. For the stream AEADs this
            // is 0 (nothing buffered); for OCB it is the buffered partial
            // block, which OpenSSL's OCB final writes WITHOUT honouring the
            // output size — the previous unconditional 0 left that flush
            // unguarded and let it write past a zero-capacity window.
            len = ctx->buffered;
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

    if (OPS_INT32_OVERFLOW_1 out_len > INT32_MAX) {
        written = JO_OUTPUT_TOO_LONG_INT32;
        goto failed;
    }

    if (!ctx->initialized) {
        written = JO_NOT_INITIALIZED;
        goto failed;
    }

    /* out_len asserted less than int32 max */

    ERR_clear_error();

    // Accumulating modes run here, not in update: the buffered message goes
    // to EVP in ONE call, which is the only form its primitive accepts.
    // Chunking is therefore invisible to the output — any split of the same
    // message yields the same ciphertext, which is what makes the streaming
    // JCA contract safe for a one-shot primitive.
    if (mode_accumulates(ctx->mode_id)) {
        // Neither mode defines output below one AES block — IEEE 1619 for
        // XTS, ciphertext stealing needing something to steal from for CTS
        // (OpenSSL refuses a sub-block CTS update outright). The check belongs
        // here rather than per-chunk: only now is the total known, so a caller
        // feeding 8 bytes then 8 more is correctly accepted while a single
        // 8-byte message is not. Covers the zero-length case too, which never
        // reaches update at all (the SPI skips the call when there is nothing
        // to feed).
        // Mode-aware minimum. XTS and CTS define no output below one cipher
        // block. A wrap's real minimum is RFC 5649's 1 byte (KWP); KW's own
        // multiple-of-8, at-least-16 rule is left to OpenSSL, which enforces
        // it per algorithm and whose refusals match BouncyCastle's accept and
        // reject decisions exactly (measured: KW 7/15/17 refused, 16/24 fine;
        // KWP 1 and 7 fine).
        //
        // The 1 is load-bearing, not a formality. Exempting wraps entirely was
        // tried and is wrong twice over: a zero-length total reached EVP with
        // no accumulator allocated at all and crashed, and once that pointer
        // was made safe OpenSSL treated a zero-length update as a no-op and
        // returned SUCCESS WITH AN EMPTY RESULT - a wrap that silently
        // produced nothing, where BouncyCastle raises. Refusing zero here is
        // what keeps delegation safe.
        int32_t len_rc = is_wrap_mode(ctx->mode_id)
                ? wrap_length_check(ctx, accum_len(ctx))
                : (accum_len(ctx) < ctx->cipher_block_size ? JO_NOT_BLOCK_ALIGNED : JO_SUCCESS);
        if (UNSUCCESSFUL(len_rc)) {
            // Discard before returning: a rejected data unit must not leave
            // bytes behind for the NEXT doFinal to silently absorb, which
            // would turn a refused 7-byte unit plus a later 9-byte one into an
            // accepted 16-byte unit the caller never asked for.
            accum_discard(ctx);
            written = len_rc;
            goto failed;
        }

        // Output capacity. NOT accum_len: a wrap's emission is LONGER than its
        // input (KW appends an 8-byte integrity block, KWP pads first), and on
        // the unwrap integrity-failure path the primitive writes up to the
        // whole input with no capacity argument to stop it - CVE-2026-63072,
        // whose guard used to sit on the update path and now sits here.
        // final_size answers both shapes, and reduces to accum_len for XTS/CTS
        // where output length equals input length.
        //
        // Recoverable by the caller re-calling with a large enough buffer, so
        // it must NOT discard: JCE's ShortBufferException contract is "retry
        // with a bigger buffer", and dropping the unit would make the retry
        // produce a different (shorter) result.
        const int32_t need = final_size(ctx, 0);
        if (need < 0) {
            written = need;
            goto failed;
        }
        if ((size_t) need > out_len) {
            written = JO_OUTPUT_TOO_SMALL;
            goto failed;
        }

        int evp_written = 0;
        int ok;
        // accum stays NULL until the first non-empty append, so an empty
        // message reaches here with no buffer at all. XTS and CTS can never
        // see that - their length minimum above rejects a zero total first -
        // The minimum check above now makes that unreachable for every mode.
        // Kept anyway: memory safety here should not depend on an invariant
        // established by a different check twenty lines up.
        uint8_t empty = 0;
        uint8_t *accum_data = (ctx->accum == NULL) ? &empty : (uint8_t *) ctx->accum->data;
        if (ctx->op_mode == ENCRYPT_MODE) {
            ok = EVP_EncryptUpdate(ctx->evp, output, &evp_written,
                                   accum_data, (int) accum_len(ctx));
        } else if (ctx->op_mode == DECRYPT_MODE) {
            ok = EVP_DecryptUpdate(ctx->evp, output, &evp_written,
                                   accum_data, (int) accum_len(ctx));
        } else {
            written = JO_INVALID_OP_MODE;
            goto failed;
        }

        // Cleanse the plaintext unit as soon as OpenSSL has consumed it,
        // whether or not the call succeeded.
        accum_discard(ctx);

        if (OPS_OPENSSL_ERROR_8 1 != ok) {
            if (is_wrap_mode(ctx->mode_id)) {
                // An unwrap integrity failure is an EXPECTED outcome on
                // attacker-supplied ciphertext, not a fatal one. Re-init from
                // the stored key so the object stays usable - exactly what the
                // update path did before wraps accumulated, and what
                // oneInstanceStaysCorrectAcrossOperationsAndAfterFailure pins.
                int32_t recovered = wrap_recover_after_failure(ctx);

                if (ctx->op_mode == DECRYPT_MODE) {
                    // Type it as a ciphertext failure, which is what it is, so
                    // the caller's BouncyCastle-shaped catch(BadPaddingException)
                    // fires. Leaving it generic surfaced OpenSSLException - a
                    // RuntimeException - so the standard handler caught NOTHING
                    // on the routine attacker-data path.
                    //
                    // Safe to attribute without inspecting the error queue:
                    // wrap_length_check has already rejected every illegal
                    // length, so the unwrap primitive has exactly one failure
                    // mode left, its RFC 3394 integrity check (measured: OpenSSL
                    // raises PROV_R_CIPHER_OPERATION_FAILED from
                    // aes_wrap_cipher_internal). This is the same attribution -
                    // and the same residual risk, that an internal error would
                    // read as bad ciphertext - that the EVP_DecryptFinal_ex arm
                    // below already makes for every padded and AEAD mode.
                    written = JO_INVALID_CIPHER_TEXT;
                } else {
                    written = recovered;
                }
            } else {
                ctx->poisoned = 1;
                written = JO_OPENSSL_ERROR;
            }
            goto failed;
        }

        ctx->processed += (size_t) evp_written;
        written = evp_written;
        goto reset;
    }

    // Unpadded block modes: the TOTAL must be block-aligned. Checked here, not
    // per update, because EVP buffers a partial block across update calls - so
    // 8 bytes then 8 more is a legal 16-byte message, which the old per-chunk
    // check refused while BouncyCastle and SunJCE both accepted it.
    //
    // Discard rather than poison. Measured: after refusing a misaligned total
    // both references leave the Cipher object REUSABLE and it then produces
    // correct output. `goto reset` re-inits from the stored key and IV, which
    // drops the residue EVP is still holding - without that the next doFinal
    // would silently absorb it and emit a wrong answer.
    if (ctx->streaming == 0 && ctx->padding == NO_PADDING
        && ctx->cipher_block_size > 0
        && (ctx->processed % ctx->cipher_block_size) != 0) {
        written = JO_NOT_BLOCK_ALIGNED;
        goto reset;
    }

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


reset:
    ;   // A label must precede a statement, not a declaration, before C23.

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

    // OCB is a block-buffering AEAD (unlike GCM/POLY1305, which stream): a
    // single update emits whole blocks out of (buffered residue + bytes fed
    // this call), which can exceed `len`. Size to exactly that amount — the
    // same value block_cipher_ctx_update's OCB guard requires and OCB writes.
    // Must precede the generic streaming branch below (OCB sets streaming=1).
    if (ctx->mode_id == OCB) {
        size_t ocb = ocb_update_out(ctx, evp_fed_bytes(ctx, len));
        if (ocb > INT32_MAX) {
            return JO_OUTPUT_SIZE_INT_OVERFLOW;
        }
        return (int32_t) ocb;
    }

    // Accumulating modes buffer the whole message and emit it all at final,
    // so an update writes nothing and needs no output capacity. Reporting
    // `len` here would make the auto-allocating Cipher.update path hand back a
    // zero-filled array of the input's length instead of an empty one.
    if (mode_accumulates(ctx->mode_id)) {
        return 0;
    }

    size_t result;

    if (ctx->streaming) {
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

    // Plaintext data-unit bytes — clear-free, never plain free.
    // Clear-frees the whole capacity, not just the used prefix.
    BUF_MEM_free(ctx->accum);

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}
