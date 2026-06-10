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
#include "org_openssl_jostle_jcajce_provider_dh_DHServiceJNI.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/dh.h"
#include "../util/ops.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_groupSupported
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1groupSupported
(JNIEnv *env, jobject jo, jstring _groupName) {
    UNUSED(jo);

    // Bridge surfaces null/access failures as typed error codes —
    // the Java boolean wrapper (`code == 1`) collapses every negative
    // value to `false` (ec_ni_jni.c ni_curveSupported rationale).
    if (_groupName == NULL) {
        return JO_NAME_IS_NULL;
    }

    const char *group_name = (*env)->GetStringUTFChars(env, _groupName, NULL);
    if (OPS_FAILED_ACCESS_1 group_name == NULL) {
        return JO_UNABLE_TO_ACCESS_NAME;
    }

    int32_t result = dh_group_supported(group_name);

    (*env)->ReleaseStringUTFChars(env, _groupName, group_name);
    return result;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_generateKeyPairByGroup
 * Signature: (Ljava/lang/String;[ILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1generateKeyPairByGroup
(JNIEnv *env, jobject jo, jstring _groupName, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    const char *group_name = NULL;

    if (_groupName == NULL) {
        ret_val = JO_NAME_IS_NULL;
        goto exit;
    }
    if (rnd_src == NULL) {
        ret_val = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    group_name = (*env)->GetStringUTFChars(env, _groupName, NULL);
    if (OPS_FAILED_ACCESS_1 group_name == NULL) {
        ret_val = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    spec = create_spec();
    ret_val = dh_generate_key_by_group(spec, group_name, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    if (group_name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _groupName, group_name);
    }
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_generateParameters
 * Signature: (I[ILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1generateParameters
(JNIEnv *env, jobject jo, jint p_bits, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;

    // Bridge backstop on the bit size — the util layer's precondition
    // is bits > 0 (the Java SPI applies the 512..8192 policy bounds).
    if (p_bits <= 0) {
        ret_val = JO_DH_BITS_OUT_OF_RANGE;
        goto exit;
    }
    if (rnd_src == NULL) {
        ret_val = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    spec = create_spec();
    ret_val = dh_generate_parameters(spec, p_bits, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_makeParamsFromComponents
 * Signature: ([B[B[I)J
 *
 * Constructs a parameters-only DH key_spec from explicit (p, g)
 * big-endian unsigned magnitudes. PKCS#3 DH has no q.
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1makeParamsFromComponents
(JNIEnv *env, jobject jo, jbyteArray _p, jbyteArray _g, jintArray err_out) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    java_bytearray_ctx p_ctx;
    java_bytearray_ctx g_ctx;
    init_bytearray_ctx(&p_ctx);
    init_bytearray_ctx(&g_ctx);

    if (_p == NULL || _g == NULL) {
        ret_val = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&p_ctx, env, _p)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&g_ctx, env, _g)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    // Empty arrays are meaningless FFC components (dsa_ni_jni.c
    // rationale; jsize is int32_t so > INT32_MAX is impossible from JNI).
    if (p_ctx.size == 0 || g_ctx.size == 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    spec = create_spec();
    ret_val = dh_make_params_from_components(spec,
                                             p_ctx.bytearray, p_ctx.size,
                                             g_ctx.bytearray, g_ctx.size);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    release_bytearray_ctx(&g_ctx);
    release_bytearray_ctx(&p_ctx);
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_generateKeyPair
 * Signature: (J[ILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1generateKeyPair
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
    ret_val = dh_generate_key(spec, params, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_makePrivateFromComponents
 * Signature: ([B[B[B[ILorg/openssl/jostle/rand/RandSource;)J
 *
 * Constructs a Jostle key_spec for a DH private key from explicit
 * (p, g, x) big-endian unsigned magnitudes. The public value
 * y = g^x mod p is computed on the C side.
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1makePrivateFromComponents
(JNIEnv *env, jobject jo, jbyteArray _p, jbyteArray _g, jbyteArray _x,
 jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    java_bytearray_ctx p_ctx;
    java_bytearray_ctx g_ctx;
    java_bytearray_ctx x_ctx;
    init_bytearray_ctx(&p_ctx);
    init_bytearray_ctx(&g_ctx);
    init_bytearray_ctx(&x_ctx);

    if (_p == NULL || _g == NULL || _x == NULL) {
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
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&g_ctx, env, _g)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&x_ctx, env, _x)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (p_ctx.size == 0 || g_ctx.size == 0 || x_ctx.size == 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    spec = create_spec();
    ret_val = dh_make_private_from_components(spec,
                                              p_ctx.bytearray, p_ctx.size,
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
    release_bytearray_ctx(&p_ctx);
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_makePublicFromComponents
 * Signature: ([B[B[B[I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1makePublicFromComponents
(JNIEnv *env, jobject jo, jbyteArray _p, jbyteArray _g, jbyteArray _y,
 jintArray err_out) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    java_bytearray_ctx p_ctx;
    java_bytearray_ctx g_ctx;
    java_bytearray_ctx y_ctx;
    init_bytearray_ctx(&p_ctx);
    init_bytearray_ctx(&g_ctx);
    init_bytearray_ctx(&y_ctx);

    if (_p == NULL || _g == NULL || _y == NULL) {
        ret_val = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&p_ctx, env, _p)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&g_ctx, env, _g)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&y_ctx, env, _y)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (p_ctx.size == 0 || g_ctx.size == 0 || y_ctx.size == 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    spec = create_spec();
    ret_val = dh_make_public_from_components(spec,
                                             p_ctx.bytearray, p_ctx.size,
                                             g_ctx.bytearray, g_ctx.size,
                                             y_ctx.bytearray, y_ctx.size);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    release_bytearray_ctx(&y_ctx);
    release_bytearray_ctx(&g_ctx);
    release_bytearray_ctx(&p_ctx);
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_getComponent
 * Signature: (JI[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1getComponent
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
        ret_code = dh_get_component(spec, component, NULL, 0);
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&out_ctx, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = dh_get_component(spec, component, out_ctx.bytearray, out_ctx.size);

exit:
    release_bytearray_ctx(&out_ctx);
    return ret_code;
}


// =================================================================
// Key agreement session
// =================================================================

/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_allocateKex
 * Signature: ([I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1allocateKex
(JNIEnv *env, jobject jo, jintArray err) {
    UNUSED(jo);
    jo_assert(err != NULL);

    int rc = 0;
    void *ref = dh_kex_create(&rc);
    (*env)->SetIntArrayRegion(env, err, 0, 1, &rc);
    return (jlong) ref;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_disposeKex
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1disposeKex
(JNIEnv *env, jobject jo, jlong ref) {
    UNUSED(env);
    UNUSED(jo);
    dh_kex_destroy((dh_kex_ctx *) ref);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_kexInit
 * Signature: (JJLorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1kexInit
(JNIEnv *env, jobject jo, jlong kex_ref, jlong key_ref, jobject rnd_src) {
    UNUSED(env);
    UNUSED(jo);

    dh_kex_ctx *ctx = (dh_kex_ctx *) kex_ref;
    if (ctx == NULL) {
        return JO_KEX_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    return dh_kex_init(ctx, spec, rnd_src);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_kexSetPeer
 * Signature: (JJLorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1kexSetPeer
(JNIEnv *env, jobject jo, jlong kex_ref, jlong key_ref, jobject rnd_src) {
    UNUSED(env);
    UNUSED(jo);

    dh_kex_ctx *ctx = (dh_kex_ctx *) kex_ref;
    if (ctx == NULL) {
        return JO_KEX_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    return dh_kex_set_peer(ctx, spec, rnd_src);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_dh_DHServiceJNI
 * Method:    ni_kexDerive
 * Signature: (J[BILorg/openssl/jostle/rand/RandSource;)I
 *
 * Non-critical bytearray helper — the RAND upcall must be allowed
 * during the underlying EVP_PKEY_derive (ec kex bridge rationale).
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1kexDerive
(JNIEnv *env, jobject jo, jlong kex_ref, jbyteArray _out, jint out_off, jobject rnd_src) {
    UNUSED(jo);

    dh_kex_ctx *ctx = (dh_kex_ctx *) kex_ref;
    if (ctx == NULL) {
        return JO_KEX_CTX_IS_NULL;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (_out == NULL) {
        // Two-call protocol: caller wants the required length.
        return dh_kex_derive(ctx, NULL, 0, rnd_src);
    }

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx output;
    init_bytearray_ctx(&output);

    if (out_off < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    if ((size_t) out_off > output.size) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }
    size_t out_len = output.size - (size_t) out_off;
    uint8_t *out = output.bytearray + (size_t) out_off;

    ret_code = dh_kex_derive(ctx, out, out_len, rnd_src);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}
