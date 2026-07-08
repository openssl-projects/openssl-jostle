//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//


#include <string.h>

#include "bytearrays.h"
#include "byte_array_critical.h"
#include "org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/dsa.h"
#include "../util/ops.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_generateParameters
 * Signature: (II[ILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1generateParameters
(JNIEnv *env, jobject jo, jint p_bits, jint q_bits, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;

    // Bridge backstop on the bit sizes — the util layer's precondition
    // is bits > 0 (the Java SPI applies the FIPS 186-4 policy bounds).
    if (p_bits <= 0 || q_bits <= 0) {
        ret_val = JO_DSA_BITS_OUT_OF_RANGE;
        goto exit;
    }
    if (rnd_src == NULL) {
        ret_val = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    spec = create_spec();
    ret_val = dsa_generate_parameters(spec, p_bits, q_bits, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_makeParamsFromComponents
 * Signature: ([B[B[B[I)J
 *
 * Constructs a parameters-only DSA key_spec from explicit (p, q, g)
 * big-endian unsigned magnitudes.
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1makeParamsFromComponents
(JNIEnv *env, jobject jo, jbyteArray _p, jbyteArray _q, jbyteArray _g,
 jintArray err_out) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    java_bytearray_ctx p_ctx;
    java_bytearray_ctx q_ctx;
    java_bytearray_ctx g_ctx;
    init_bytearray_ctx(&p_ctx);
    init_bytearray_ctx(&q_ctx);
    init_bytearray_ctx(&g_ctx);

    if (_p == NULL || _q == NULL || _g == NULL) {
        ret_val = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&p_ctx, env, _p)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&q_ctx, env, _q)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&g_ctx, env, _g)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    // Empty arrays are meaningless FFC components — surface the same
    // typed code the EC scalar path uses for a zero-length input.
    // (jsize is int32_t, so > INT32_MAX is structurally impossible
    // from JNI; the FFI bridge additionally guards against it.)
    if (p_ctx.size == 0 || q_ctx.size == 0 || g_ctx.size == 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    spec = create_spec();
    ret_val = dsa_make_params_from_components(spec,
                                              p_ctx.bytearray, p_ctx.size,
                                              q_ctx.bytearray, q_ctx.size,
                                              g_ctx.bytearray, g_ctx.size);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    release_bytearray_ctx(&g_ctx);
    release_bytearray_ctx(&q_ctx);
    release_bytearray_ctx(&p_ctx);
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_generateKeyPair
 * Signature: (J[ILorg/openssl/jostle/rand/RandSource;)J
 *
 * Generates a DSA keypair from an established domain-parameter spec
 * (produced by ni_generateParameters or ni_makeParamsFromComponents).
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1generateKeyPair
(JNIEnv *env, jobject jo, jlong params_ref, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;

    key_spec *params = (key_spec *) params_ref;
    if (params == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }
    if (rnd_src == NULL) {
        ret_val = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    spec = create_spec();
    ret_val = dsa_generate_key(spec, params, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_makePrivateFromComponents
 * Signature: ([B[B[B[B[ILorg/openssl/jostle/rand/RandSource;)J
 *
 * Constructs a Jostle key_spec for a DSA private key from explicit
 * (p, q, g, x) big-endian unsigned magnitudes. The public value
 * y = g^x mod p is computed on the C side. Non-critical bytearray
 * access — the RAND upcall must be allowed during the underlying
 * dsa_make_private_from_components.
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1makePrivateFromComponents
(JNIEnv *env, jobject jo, jbyteArray _p, jbyteArray _q, jbyteArray _g,
 jbyteArray _x, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    java_bytearray_ctx p_ctx;
    java_bytearray_ctx q_ctx;
    java_bytearray_ctx g_ctx;
    java_bytearray_ctx x_ctx;
    init_bytearray_ctx(&p_ctx);
    init_bytearray_ctx(&q_ctx);
    init_bytearray_ctx(&g_ctx);
    init_bytearray_ctx(&x_ctx);

    if (_p == NULL || _q == NULL || _g == NULL || _x == NULL) {
        ret_val = JO_INPUT_IS_NULL;
        goto exit;
    }
    if (rnd_src == NULL) {
        ret_val = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&p_ctx, env, _p)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&q_ctx, env, _q)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&g_ctx, env, _g)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_4 !load_bytearray_ctx(&x_ctx, env, _x)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (p_ctx.size == 0 || q_ctx.size == 0
        || g_ctx.size == 0 || x_ctx.size == 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    spec = create_spec();
    ret_val = dsa_make_private_from_components(spec,
                                               p_ctx.bytearray, p_ctx.size,
                                               q_ctx.bytearray, q_ctx.size,
                                               g_ctx.bytearray, g_ctx.size,
                                               x_ctx.bytearray, x_ctx.size,
                                               rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    release_bytearray_ctx(&x_ctx);
    release_bytearray_ctx(&g_ctx);
    release_bytearray_ctx(&q_ctx);
    release_bytearray_ctx(&p_ctx);
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_makePublicFromComponents
 * Signature: ([B[B[B[B[I)J
 *
 * Constructs a Jostle key_spec for a DSA public key from explicit
 * (p, q, g, y) big-endian unsigned magnitudes.
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1makePublicFromComponents
(JNIEnv *env, jobject jo, jbyteArray _p, jbyteArray _q, jbyteArray _g,
 jbyteArray _y, jintArray err_out) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    java_bytearray_ctx p_ctx;
    java_bytearray_ctx q_ctx;
    java_bytearray_ctx g_ctx;
    java_bytearray_ctx y_ctx;
    init_bytearray_ctx(&p_ctx);
    init_bytearray_ctx(&q_ctx);
    init_bytearray_ctx(&g_ctx);
    init_bytearray_ctx(&y_ctx);

    if (_p == NULL || _q == NULL || _g == NULL || _y == NULL) {
        ret_val = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&p_ctx, env, _p)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&q_ctx, env, _q)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&g_ctx, env, _g)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_4 !load_bytearray_ctx(&y_ctx, env, _y)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (p_ctx.size == 0 || q_ctx.size == 0
        || g_ctx.size == 0 || y_ctx.size == 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    spec = create_spec();
    ret_val = dsa_make_public_from_components(spec,
                                              p_ctx.bytearray, p_ctx.size,
                                              q_ctx.bytearray, q_ctx.size,
                                              g_ctx.bytearray, g_ctx.size,
                                              y_ctx.bytearray, y_ctx.size);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    release_bytearray_ctx(&y_ctx);
    release_bytearray_ctx(&g_ctx);
    release_bytearray_ctx(&q_ctx);
    release_bytearray_ctx(&p_ctx);
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_getComponent
 * Signature: (JI[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1getComponent
(JNIEnv *env, jobject jo, jlong spec_ref, jint component, jbyteArray _out) {
    UNUSED(jo);

    key_spec *spec = (key_spec *) spec_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx out_ctx;
    init_bytearray_ctx(&out_ctx);

    if (_out == NULL) {
        // Caller wants required size.
        ret_code = dsa_get_component(spec, component, NULL, 0);
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&out_ctx, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = dsa_get_component(spec, component, out_ctx.bytearray, out_ctx.size);

exit:
    release_bytearray_ctx(&out_ctx);
    return ret_code;
}


// =================================================================
// Sign / verify session
// =================================================================

/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_allocateSigner
 * Signature: ([I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1allocateSigner
(JNIEnv *env, jobject jo, jintArray err) {
    UNUSED(jo);
    jo_assert(err != NULL);

    int rc = 0;
    void *ref = dsa_ctx_create(&rc);
    (*env)->SetIntArrayRegion(env, err, 0, 1, &rc);
    return (jlong) ref;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_disposeSigner
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1disposeSigner
(JNIEnv *env, jobject o, jlong ref) {
    UNUSED(env);
    UNUSED(o);
    dsa_ctx_destroy((dsa_ctx *) ref);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_initSign
 * Signature: (JJLjava/lang/String;Lorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1initSign
(JNIEnv *env, jobject jo, jlong dsa_ref, jlong key_ref,
 jstring _digest, jobject rnd_src) {
    UNUSED(jo);

    dsa_ctx *ctx = (dsa_ctx *) dsa_ref;
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (_digest == NULL) {
        return JO_NAME_IS_NULL;
    }

    const char *digest = (*env)->GetStringUTFChars(env, _digest, NULL);
    if (OPS_FAILED_ACCESS_1 digest == NULL) {
        return JO_UNABLE_TO_ACCESS_NAME;
    }

    int32_t ret_code = dsa_ctx_init_sign(ctx, spec, digest, rnd_src);
    (*env)->ReleaseStringUTFChars(env, _digest, digest);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_initVerify
 * Signature: (JJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1initVerify
(JNIEnv *env, jobject jo, jlong dsa_ref, jlong key_ref, jstring _digest) {
    UNUSED(jo);

    dsa_ctx *ctx = (dsa_ctx *) dsa_ref;
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (_digest == NULL) {
        return JO_NAME_IS_NULL;
    }

    const char *digest = (*env)->GetStringUTFChars(env, _digest, NULL);
    if (OPS_FAILED_ACCESS_1 digest == NULL) {
        return JO_UNABLE_TO_ACCESS_NAME;
    }

    int32_t ret_code = dsa_ctx_init_verify(ctx, spec, digest);
    (*env)->ReleaseStringUTFChars(env, _digest, digest);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1update
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(jo);

    dsa_ctx *ctx = (dsa_ctx *) ref;
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }

    int32_t ret_code = JO_FAIL;
    critical_bytearray_ctx input;
    init_critical_ctx(&input, env, _input);

    if (input.array == NULL) {
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
    if (!check_critical_in_range(&input, in_off, in_len)) {
        ret_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&input)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    const uint8_t *in = input.critical + in_off;
    ret_code = dsa_ctx_update(ctx, in, in_len);

exit:
    release_critical_ctx(&input);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_sign
 * Signature: (J[BILorg/openssl/jostle/rand/RandSource;)I
 *
 * Non-critical bytearray access — DSA signing consumes RAND for the
 * per-signature nonce, and the upcall into the Java RandSource is
 * forbidden inside JNI critical regions.
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1sign
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _output, jint out_off, jobject rnd_src) {
    UNUSED(jo);

    dsa_ctx *ctx = (dsa_ctx *) ref;
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (_output == NULL) {
        return dsa_ctx_sign(ctx, NULL, 0, rnd_src);
    }

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx output;
    init_bytearray_ctx(&output);

    if (out_off < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    if ((size_t) out_off > output.size) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }
    size_t out_len = output.size - (size_t) out_off;
    uint8_t *out = output.bytearray + (size_t) out_off;

    ret_code = dsa_ctx_sign(ctx, out, out_len, rnd_src);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI
 * Method:    ni_verify
 * Signature: (J[BILorg/openssl/jostle/rand/RandSource;)I
 *
 * DSA verify takes a RandSource for parity with the EC bridge — the
 * upcall is bound before EVP_DigestVerifyFinal so any future OpenSSL
 * RAND consumption on the verify path resolves to fresh Java entropy.
 * This bridge therefore uses the non-critical bytearray helper (not
 * critical_bytearray_ctx); upcalls are forbidden inside JNI critical
 * regions.
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dsa_DSAServiceJNI_ni_1verify
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _sig, jint sig_len, jobject rnd_src) {
    UNUSED(jo);

    dsa_ctx *ctx = (dsa_ctx *) ref;
    if (ctx == NULL) {
        return JO_SIGNER_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (_sig == NULL) {
        return JO_SIG_IS_NULL;
    }
    if (sig_len < 0) {
        return JO_SIG_LENGTH_IS_NEGATIVE;
    }

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx sig;
    init_bytearray_ctx(&sig);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&sig, env, _sig)) {
        ret_code = JO_FAILED_ACCESS_SIG;
        goto exit;
    }
    if (!check_bytearray_in_range(&sig, 0, sig_len)) {
        ret_code = JO_SIG_OUT_OF_RANGE;
        goto exit;
    }

    ret_code = dsa_ctx_verify(ctx, sig.bytearray, sig_len, rnd_src);

exit:
    release_bytearray_ctx(&sig);
    return ret_code;
}
