//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "ccm_ctx.h"

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"

#include <openssl/err.h>
#include <string.h>

// Per NIST SP 800-38C §6.1, CCM tag length t ∈ {4,6,8,10,12,14,16}.
// Non-static: the JNI/FFI bridges call this to validate the caller's
// tag length (declared in ccm_ctx.h); ccm_ctx_init asserts it.
int valid_ccm_tag_len(size_t tag_len) {
    switch (tag_len) {
        case 4:
        case 6:
        case 8:
        case 10:
        case 12:
        case 14:
        case 16:
            return 1;
        default:
            return 0;
    }
}

// Map cipher_id → fetched EVP_CIPHER. Caller frees with EVP_CIPHER_free.
// Sets *err and returns NULL on failure.
static EVP_CIPHER *ccm_fetch_evp_cipher(uint32_t cipher_id, size_t key_len, int32_t *err) {
    const char *name = NULL;
    switch (cipher_id) {
        case AES128:
            if (key_len != 16) { *err = JO_INVALID_KEY_LEN; return NULL; }
            name = "AES-128-CCM";
            break;
        case AES192:
            if (key_len != 24) { *err = JO_INVALID_KEY_LEN; return NULL; }
            name = "AES-192-CCM";
            break;
        case AES256:
            if (key_len != 32) { *err = JO_INVALID_KEY_LEN; return NULL; }
            name = "AES-256-CCM";
            break;
        case ARIA128:
            if (key_len != 16) { *err = JO_INVALID_KEY_LEN; return NULL; }
            name = "ARIA-128-CCM";
            break;
        case ARIA192:
            if (key_len != 24) { *err = JO_INVALID_KEY_LEN; return NULL; }
            name = "ARIA-192-CCM";
            break;
        case ARIA256:
            if (key_len != 32) { *err = JO_INVALID_KEY_LEN; return NULL; }
            name = "ARIA-256-CCM";
            break;
        case SM4:
            if (key_len != 16) { *err = JO_INVALID_KEY_LEN; return NULL; }
            name = "SM4-CCM";
            break;
        default:
            *err = JO_INVALID_CIPHER;
            return NULL;
    }
    EVP_CIPHER *evp = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), name, NULL);
    if (OPS_FAILED_CREATE_1 evp == NULL) {
        *err = JO_OPENSSL_ERROR OPS_OFFSET_FAILED_CREATE_1(4001);
        return NULL;
    }
    return evp;
}


ccm_ctx *ccm_ctx_create(uint32_t cipher_id, int32_t *err) {
    jo_assert(err != NULL);

    // Validate cipher_id up-front: anything we can't fetch a CCM cipher
    // for is a hard error before allocation.
    switch (cipher_id) {
        case AES128: case AES192: case AES256:
        case ARIA128: case ARIA192: case ARIA256:
        case SM4:
            break;
        default:
            *err = JO_INVALID_CIPHER;
            return NULL;
    }

    ccm_ctx *ctx = OPENSSL_zalloc(sizeof(ccm_ctx));
    if (ctx == NULL) {
        *err = JO_FAIL;
        return NULL;
    }
    ctx->cipher_id = cipher_id;
    ERR_clear_error();
    ctx->evp = EVP_CIPHER_CTX_new();
    if (OPS_FAILED_CREATE_2 ctx->evp == NULL) {
        EVP_CIPHER_CTX_free(ctx->evp); // NULL-safe; frees it if OPS forced this branch
        OPENSSL_free(ctx);
        *err = JO_OPENSSL_ERROR OPS_OFFSET_FAILED_CREATE_2(4017);
        return NULL;
    }
    ctx->initialized = 0;
    *err = JO_SUCCESS;
    return ctx;
}


void ccm_ctx_destroy(ccm_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->evp != NULL) {
        EVP_CIPHER_CTX_free(ctx->evp);
        ctx->evp = NULL;
    }
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
    OPENSSL_free(ctx);
}


int32_t ccm_ctx_init(ccm_ctx *ctx,
                     int32_t opp_mode,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *iv, size_t iv_len,
                     size_t tag_len) {
    jo_assert(ctx != NULL);
    jo_assert(key != NULL);
    jo_assert(iv != NULL);

    if (opp_mode != ENCRYPT_MODE && opp_mode != DECRYPT_MODE) {
        return JO_INVALID_OP_MODE;
    }
    // iv_len and tag_len are range/set validated by the bridge
    // (ccm_ni_jni.c / ccm_ni_ffi.c) and asserted here as invariants — a
    // firing assert means the bridge skipped a check (programmer error),
    // not a user-input error. The exact key_len-vs-cipher check is owned
    // by ccm_fetch_evp_cipher below (it holds the cipher→key-length
    // table); the key_len buffer-bound is asserted before the memcpy.
    jo_assert(iv_len >= CCM_MIN_NONCE_LEN && iv_len <= CCM_MAX_NONCE_LEN);
    jo_assert(valid_ccm_tag_len(tag_len));

    // Probe-fetch the cipher to catch cipher_id+key_len mismatches at
    // init-time rather than do_encrypt-time. Discard the result; the
    // do_* functions re-fetch.
    // Default to failure so a NULL return without a written err code
    // surfaces as a failure rather than a false success.
    int32_t err = JO_FAIL;
    EVP_CIPHER *probe = ccm_fetch_evp_cipher(ctx->cipher_id, key_len, &err);
    if (probe == NULL) {
        return err;
    }
    EVP_CIPHER_free(probe);

    ctx->op_mode = opp_mode;
    // The probe-fetch above validated key_len against the cipher
    // (∈ {16,24,32}), so it fits the fixed-size key buffer.
    jo_assert(key_len <= CCM_MAX_KEY_LEN);
    ctx->key_len = key_len;
    memcpy(ctx->key, key, key_len);
    ctx->iv_len = iv_len;
    memcpy(ctx->iv, iv, iv_len);
    ctx->tag_len = tag_len;
    ctx->initialized = 1;
    return JO_SUCCESS;
}


/**
 * Shared one-shot CCM operation. is_encrypt selects encrypt vs decrypt.
 *
 * For encrypt: input is plaintext (in_len bytes). Output is
 * ciphertext (in_len bytes) followed by tag (tag_len bytes). Total
 * out_len must be >= in_len + tag_len.
 *
 * For decrypt: input is ciphertext+tag (in_len bytes, where the last
 * tag_len bytes are the tag). Output is plaintext (in_len - tag_len
 * bytes). out_len must be >= in_len - tag_len. Tag mismatch → JO_INVALID_CIPHER_TEXT.
 */
static int32_t ccm_do_one_shot(ccm_ctx *ctx,
                               int is_encrypt,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t out_len) {
    jo_assert(ctx != NULL);
    // in_len and aad_len reach us as a Java int (jint / int32_t) with
    // negatives already rejected by the bridge, so they are in
    // [0, INT32_MAX]. Both are cast to (int) for the EVP_*Update calls
    // below; assert that invariant here — a firing assert means the bridge
    // skipped a check (programmer error), not a user-input error.
    jo_assert(in_len <= (size_t) INT32_MAX);
    jo_assert(aad_len <= (size_t) INT32_MAX);

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    // Two self-contained paths: each validates op-mode + lengths for its
    // direction, fetches the cipher, runs the full EVP CCM sequence, and
    // sets ret to a byte count on success. Shared cleanup at exit frees
    // the fetched EVP_CIPHER.
    //
    // CCM imposes a per-nonce-length max on plaintext (NIST SP 800-38C
    // §A.1: with nonce length n bytes, max plaintext is 2^(8*(15-n)) - 1
    // bytes). OpenSSL enforces this internally and Java inputs are
    // INT32_MAX-bounded, so we don't repeat the check here.

    EVP_CIPHER *evp_cipher = NULL;
    // Default to failure: every success path assigns ret a byte count
    // (>= 0) before reaching exit, so an accidental fall-through to exit
    // returns JO_FAIL rather than a false success.
    int32_t ret = JO_FAIL;
    int outl = 0;

    if (is_encrypt) {
        // ---- encrypt: plaintext (in) -> ciphertext || tag (out) ----
        if (ctx->op_mode != ENCRYPT_MODE) {
            return JO_INVALID_OP_MODE;
        }
        if (out_len < in_len + ctx->tag_len) {
            return JO_OUTPUT_TOO_SMALL;
        }
        const size_t pt_len = in_len;
        int final_len = 0;

        ERR_clear_error();

        // Default to failure so a NULL return without a written err code
        // surfaces as a failure rather than a false success.
        int32_t fetch_err = JO_FAIL;
        evp_cipher = ccm_fetch_evp_cipher(ctx->cipher_id, ctx->key_len, &fetch_err);
        if (evp_cipher == NULL) {
            return fetch_err;
        }

        // Step 1: bind cipher (NULL key/iv at this point).
        if (OPS_OPENSSL_ERROR_1 1 != EVP_EncryptInit_ex(ctx->evp, evp_cipher, NULL, NULL, NULL)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(4002);
            goto exit;
        }
        // Step 2: set IV length.
        if (OPS_OPENSSL_ERROR_2 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_IVLEN,
                                                        (int) ctx->iv_len, NULL)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(4004);
            goto exit;
        }
        // Step 3: set tag length only (NULL buffer) — tells OpenSSL the
        //         eventual tag length.
        if (OPS_OPENSSL_ERROR_3 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_TAG,
                                                        (int) ctx->tag_len, NULL)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(4005);
            goto exit;
        }
        // Step 4: set key and IV.
        if (OPS_OPENSSL_ERROR_4 1 != EVP_EncryptInit_ex(ctx->evp, NULL, NULL,
                                                       ctx->key, ctx->iv)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(4007);
            goto exit;
        }
        // Step 5: declare the total plaintext length to OpenSSL (NULL output).
        if (OPS_OPENSSL_ERROR_5 1 != EVP_EncryptUpdate(ctx->evp, NULL, &outl, NULL, (int) pt_len)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(4009);
            goto exit;
        }
        // Step 6: AAD (single call). Skip if aad_len == 0.
        if (aad_len > 0) {
            if (OPS_OPENSSL_ERROR_6 1 != EVP_EncryptUpdate(ctx->evp, NULL, &outl, aad, (int) aad_len)) {
                ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(4011);
                goto exit;
            }
        }
        // Step 7: process payload — in -> out (ciphertext).
        if (OPS_OPENSSL_ERROR_7 1 != EVP_EncryptUpdate(ctx->evp, out, &outl, in, (int) pt_len)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(4013);
            goto exit;
        }
        // Step 8: finalise.
        if (OPS_OPENSSL_ERROR_8 1 != EVP_EncryptFinal_ex(ctx->evp, out + outl, &final_len)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(4014);
            goto exit;
        }
        // Step 9: pull the tag out and append it to the ciphertext.
        if (OPS_OPENSSL_ERROR_9 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_GET_TAG,
                                                        (int) ctx->tag_len,
                                                        out + pt_len)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(4015);
            goto exit;
        }
        ret = (int32_t) (pt_len + ctx->tag_len);
    } else {
        // ---- decrypt: ciphertext || tag (in) -> plaintext (out) ----
        if (ctx->op_mode != DECRYPT_MODE) {
            return JO_INVALID_OP_MODE;
        }
        if (in_len < ctx->tag_len) {
            return JO_INVALID_CIPHER_TEXT; // can't carry a tag
        }
        const size_t ct_len = in_len - ctx->tag_len;
        const size_t pt_len = ct_len;
        if (out_len < ct_len) {
            return JO_OUTPUT_TOO_SMALL;
        }

        ERR_clear_error();

        // Default to failure so a NULL return without a written err code
        // surfaces as a failure rather than a false success.
        int32_t fetch_err = JO_FAIL;
        evp_cipher = ccm_fetch_evp_cipher(ctx->cipher_id, ctx->key_len, &fetch_err);
        if (evp_cipher == NULL) {
            return fetch_err;
        }

        // Step 1: bind cipher (NULL key/iv at this point).
        if (OPS_OPENSSL_ERROR_1 1 != EVP_DecryptInit_ex(ctx->evp, evp_cipher, NULL, NULL, NULL)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(4003);
            goto exit;
        }
        // Step 2: set IV length.
        if (OPS_OPENSSL_ERROR_2 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_IVLEN,
                                                        (int) ctx->iv_len, NULL)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(4016);
            goto exit;
        }
        // Step 3: set the actual tag bytes (last tag_len of input) so
        //         OpenSSL can verify during the data step.
        if (OPS_OPENSSL_ERROR_3 1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_AEAD_SET_TAG,
                                                        (int) ctx->tag_len,
                                                        (void *) (in + ct_len))) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(4006);
            goto exit;
        }
        // Step 4: set key and IV.
        if (OPS_OPENSSL_ERROR_4 1 != EVP_DecryptInit_ex(ctx->evp, NULL, NULL,
                                                       ctx->key, ctx->iv)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(4008);
            goto exit;
        }
        // Step 5: declare the total plaintext length to OpenSSL (NULL output).
        if (OPS_OPENSSL_ERROR_5 1 != EVP_DecryptUpdate(ctx->evp, NULL, &outl, NULL, (int) pt_len)) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(4010);
            goto exit;
        }
        // Step 6: AAD (single call). Skip if aad_len == 0.
        if (aad_len > 0) {
            if (OPS_OPENSSL_ERROR_6 1 != EVP_DecryptUpdate(ctx->evp, NULL, &outl, aad, (int) aad_len)) {
                ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(4012);
                goto exit;
            }
        }
        // Step 7: process payload — in (without trailing tag) -> out.
        //   The tag verification happens inside DecryptUpdate; OpenSSL
        //   returns 0 on tag mismatch. Some builds also queue a generic
        //   EVP error for that case, so a non-empty queue is not a
        //   reliable "real error vs tag fail" signal. Inputs were already
        //   validated by the SPI / bridge, so treat any DecryptUpdate
        //   failure here as a tag-check fail (JO_INVALID_CIPHER_TEXT) and
        //   let the SPI surface it as AEADBadTagException.
        if (1 != EVP_DecryptUpdate(ctx->evp, out, &outl, in, (int) pt_len)) {
            // Tag check failed. OpenSSL's CCM may have written unverified
            // plaintext into out before detecting the MAC mismatch;
            // cleanse it best-effort so unverified plaintext is not
            // released to the caller's buffer (defence in depth — the SPI
            // also discards its buffer on this path).
            if (pt_len > 0) {
                OPENSSL_cleanse(out, pt_len);
            }
            ret = JO_INVALID_CIPHER_TEXT;
            goto exit;
        }
        ret = (int32_t) pt_len;
    }

exit:
    EVP_CIPHER_free(evp_cipher);
    return ret;
}


int32_t ccm_ctx_do_encrypt(ccm_ctx *ctx,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt,  size_t pt_len,
                           uint8_t *out,       size_t out_len) {
    return ccm_do_one_shot(ctx, 1, aad, aad_len, pt, pt_len, out, out_len);
}


int32_t ccm_ctx_do_decrypt(ccm_ctx *ctx,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct,  size_t ct_len,
                           uint8_t *out,       size_t out_len) {
    return ccm_do_one_shot(ctx, 0, aad, aad_len, ct, ct_len, out, out_len);
}


int32_t ccm_ctx_get_output_size(ccm_ctx *ctx, int32_t op_mode, size_t input_len) {
    jo_assert(ctx != NULL);
    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }
    // input_len reaches us as a non-negative Java int (the bridge rejects
    // negatives), so it is in [0, INT32_MAX]. Assert that invariant — both
    // branches cast a value derived from it back to int32_t. A firing
    // assert means the bridge skipped its check (programmer error).
    jo_assert(input_len <= (size_t) INT32_MAX);
    if (op_mode == ENCRYPT_MODE) {
        // pt → ct||tag
        if (input_len > (size_t) INT32_MAX - ctx->tag_len) {
            return JO_OUTPUT_TOO_LONG_INT32;
        }
        return (int32_t) (input_len + ctx->tag_len);
    } else if (op_mode == DECRYPT_MODE) {
        // ct||tag → pt: subtract the tag, flooring at 0 when the input is
        // too short to carry one. input_len <= INT32_MAX (asserted above),
        // so the subtraction fits int32_t.
        if (input_len < ctx->tag_len) {
            return 0;
        }
        return (int32_t) (input_len - ctx->tag_len);
    }
    return JO_INVALID_OP_MODE;
}
