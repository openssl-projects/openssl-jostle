//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//
//   JNI bridge for the CCM authenticated-encryption SPI. CCM has its
//   own bridge (rather than going through block_cipher_ni_jni.c)
//   because CCM is fundamentally one-shot — the Java SPI buffers all
//   AAD and plaintext / ciphertext, then hands the complete buffers
//   to ni_doFinal in a single call.
//


#include <string.h>

#include "bytearrays.h"
#include "org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/bc_err_codes.h"
#include "../util/ccm_ctx.h"
#include "../util/ops.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI
 * Method:    ni_makeInstance
 * Signature: (I[I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1makeInstance
(JNIEnv *env, jobject jo, jint cipher_id, jintArray err_arr) {
    UNUSED(jo);
    jo_assert(err_arr != NULL);

    int32_t err = JO_FAIL;
    ccm_ctx *ctx = ccm_ctx_create((uint32_t) cipher_id, &err);
    (*env)->SetIntArrayRegion(env, err_arr, 0, 1, &err);
    return (jlong) ctx;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI
 * Method:    ni_dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1dispose
(JNIEnv *env, jobject jo, jlong ref) {
    UNUSED(env);
    UNUSED(jo);
    ccm_ctx_destroy((ccm_ctx *) ref);
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI
 * Method:    ni_init
 * Signature: (JI[B[BI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1init
(JNIEnv *env, jobject jo, jlong ref, jint op_mode,
 jbyteArray _key, jbyteArray _iv, jint tag_len) {
    UNUSED(jo);

    ccm_ctx *ctx = (ccm_ctx *) ref;
    if (ctx == NULL) {
        return JO_FAIL;
    }
    if (_key == NULL) {
        return JO_KEY_IS_NULL;
    }
    if (_iv == NULL) {
        return JO_IV_IS_NULL;
    }
    if (tag_len < 0) {
        return JO_INVALID_TAG_LEN;
    }
    // CCM tag-length set membership ({4,6,8,10,12,14,16}). Validated in
    // the bridge so util can assert it as an invariant.
    if (!valid_ccm_tag_len((size_t) tag_len)) {
        return JO_INVALID_TAG_LEN;
    }

    java_bytearray_ctx key_ctx;
    java_bytearray_ctx iv_ctx;
    init_bytearray_ctx(&key_ctx);
    init_bytearray_ctx(&iv_ctx);
    int32_t ret = JO_FAIL;

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&key_ctx, env, _key)) {
        ret = JO_FAILED_ACCESS_KEY;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&iv_ctx, env, _iv)) {
        ret = JO_FAILED_ACCESS_IV;
        goto exit;
    }
    // CCM nonce length range [7,13] (NIST SP 800-38C §6.1). Validated in
    // the bridge so util can assert it as an invariant.
    if (iv_ctx.size < CCM_MIN_NONCE_LEN || iv_ctx.size > CCM_MAX_NONCE_LEN) {
        ret = JO_INVALID_IV_LEN;
        goto exit;
    }

    ret = ccm_ctx_init(ctx, op_mode,
                       key_ctx.bytearray, key_ctx.size,
                       iv_ctx.bytearray, iv_ctx.size,
                       (size_t) tag_len);

exit:
    release_bytearray_ctx(&key_ctx);
    release_bytearray_ctx(&iv_ctx);
    return ret;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI
 * Method:    ni_doFinal
 * Signature: (J[BI[BII[BI)I
 *
 * Layout:
 *   ref       — native ccm_ctx ptr
 *   _aad      — full AAD buffer (or null when aad_len == 0)
 *   aad_len   — number of valid AAD bytes at start of _aad
 *   _input    — buffered plaintext (encrypt) or ciphertext+tag (decrypt)
 *   in_off    — start offset within _input
 *   in_len    — valid bytes in _input from in_off
 *   _output   — destination buffer (must be non-null and large enough)
 *   out_off   — start offset within _output
 *
 * The SPI is responsible for sizing _output appropriately (encrypt
 * needs in_len + tag_len; decrypt needs in_len - tag_len).
 *
 * Returns bytes written on success, JO_* error code on failure
 * (JO_INVALID_CIPHER_TEXT on tag-check failure for decrypt).
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1doFinal
(JNIEnv *env, jobject jo, jlong ref,
 jbyteArray _aad, jint aad_len,
 jbyteArray _input, jint in_off, jint in_len,
 jbyteArray _output, jint out_off) {
    UNUSED(jo);

    ccm_ctx *ctx = (ccm_ctx *) ref;
    if (ctx == NULL) {
        return JO_FAIL;
    }

    // _aad may be null when aad_len == 0; aad_len must not be negative.
    if (aad_len < 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (_aad == NULL && aad_len != 0) {
        return JO_INPUT_IS_NULL;
    }
    if (_input == NULL) {
        return JO_INPUT_IS_NULL;
    }
    if (in_off < 0) {
        return JO_INPUT_OFFSET_IS_NEGATIVE;
    }
    if (in_len < 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (_output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }
    if (out_off < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }

    java_bytearray_ctx aad_ctx;
    java_bytearray_ctx in_ctx;
    java_bytearray_ctx out_ctx;
    init_bytearray_ctx(&aad_ctx);
    init_bytearray_ctx(&in_ctx);
    init_bytearray_ctx(&out_ctx);
    int32_t ret = JO_FAIL;

    if (_aad != NULL) {
        if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&aad_ctx, env, _aad)) {
            ret = JO_FAILED_ACCESS_INPUT;
            goto exit;
        }
        if (!check_bytearray_in_range(&aad_ctx, 0, (size_t) aad_len)) {
            ret = JO_INPUT_OUT_OF_RANGE;
            goto exit;
        }
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&in_ctx, env, _input)) {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (!check_bytearray_in_range(&in_ctx, (size_t) in_off, (size_t) in_len)) {
        ret = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&out_ctx, env, _output)) {
        ret = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    if ((size_t) out_off > out_ctx.size) {
        ret = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    const uint8_t *aad_bytes = (_aad != NULL) ? aad_ctx.bytearray : NULL;
    const uint8_t *in_bytes  = in_ctx.bytearray + (size_t) in_off;
    uint8_t *out_bytes       = out_ctx.bytearray + (size_t) out_off;
    size_t out_avail         = out_ctx.size - (size_t) out_off;

    if (ctx->op_mode == ENCRYPT_MODE) {
        ret = ccm_ctx_do_encrypt(ctx,
                                 aad_bytes, (size_t) aad_len,
                                 in_bytes, (size_t) in_len,
                                 out_bytes, out_avail);
    } else if (ctx->op_mode == DECRYPT_MODE) {
        ret = ccm_ctx_do_decrypt(ctx,
                                 aad_bytes, (size_t) aad_len,
                                 in_bytes, (size_t) in_len,
                                 out_bytes, out_avail);
    } else {
        ret = JO_NOT_INITIALIZED;
    }

exit:
    release_bytearray_ctx(&aad_ctx);
    release_bytearray_ctx(&in_ctx);
    release_bytearray_ctx(&out_ctx);
    return ret;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI
 * Method:    ni_getOutputSize
 * Signature: (JII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1getOutputSize
(JNIEnv *env, jobject jo, jlong ref, jint op_mode, jint input_len) {
    UNUSED(env);
    UNUSED(jo);
    ccm_ctx *ctx = (ccm_ctx *) ref;
    if (ctx == NULL) {
        return JO_FAIL;
    }
    if (input_len < 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    return ccm_ctx_get_output_size(ctx, op_mode, (size_t) input_len);
}
