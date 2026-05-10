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
#include "org_openssl_jostle_jcajce_provider_ec_ECServiceJNI.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/ec.h"
#include "../util/ops.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_curveSupported
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1curveSupported
(JNIEnv *env, jobject jo, jstring _curveName) {
    UNUSED(jo);

    if (_curveName == NULL) {
        return 0;
    }

    const char *curve_name = (*env)->GetStringUTFChars(env, _curveName, NULL);
    if (curve_name == NULL) {
        return 0;
    }

    int32_t result = ec_curve_supported(curve_name);

    (*env)->ReleaseStringUTFChars(env, _curveName, curve_name);
    return result;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_generateKeyPair
 * Signature: (Ljava/lang/String;[ILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1generateKeyPair
(JNIEnv *env, jobject jo, jstring _curveName, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    const char *curve_name = NULL;

    if (_curveName == NULL) {
        ret_val = JO_NAME_IS_NULL;
        goto exit;
    }

    curve_name = (*env)->GetStringUTFChars(env, _curveName, NULL);
    if (curve_name == NULL) {
        ret_val = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    spec = create_spec();
    ret_val = ec_generate_key(spec, curve_name, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    if (curve_name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _curveName, curve_name);
    }
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_makePrivateFromComponents
 * Signature: (Ljava/lang/String;[B[ILorg/openssl/jostle/rand/RandSource;)J
 *
 * Constructs a Jostle key_spec for an EC private key from a curve name
 * plus the private scalar (big-endian). OpenSSL re-derives the public
 * point internally with point-blinded multiplication, so the bridge
 * uses non-critical bytearray access — upcalls into the Java RAND
 * source must be allowed during the underlying ec_make_private_from_components.
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1makePrivateFromComponents
(JNIEnv *env, jobject jo, jstring _curveName, jbyteArray _scalar,
 jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    const char *curve_name = NULL;
    java_bytearray_ctx scalar;
    init_bytearray_ctx(&scalar);

    if (_curveName == NULL) {
        ret_val = JO_NAME_IS_NULL;
        goto exit;
    }
    if (_scalar == NULL) {
        ret_val = JO_INPUT_IS_NULL;
        goto exit;
    }

    curve_name = (*env)->GetStringUTFChars(env, _curveName, NULL);
    if (curve_name == NULL) {
        ret_val = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&scalar, env, _scalar)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    spec = create_spec();
    ret_val = ec_make_private_from_components(spec, curve_name,
                                              scalar.bytearray, scalar.size,
                                              rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    release_bytearray_ctx(&scalar);
    if (curve_name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _curveName, curve_name);
    }
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_getComponent
 * Signature: (JI[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1getComponent
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
        ret_code = ec_get_component(spec, component, NULL, 0);
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&out_ctx, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = ec_get_component(spec, component, out_ctx.bytearray, out_ctx.size);

exit:
    release_bytearray_ctx(&out_ctx);
    return ret_code;
}


// =================================================================
// Sign / verify session
// =================================================================

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_allocateSigner
 * Signature: ([I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1allocateSigner
(JNIEnv *env, jobject jo, jintArray err) {
    UNUSED(jo);
    jo_assert(err != NULL);

    int rc = 0;
    void *ref = ec_ctx_create(&rc);
    (*env)->SetIntArrayRegion(env, err, 0, 1, &rc);
    return (jlong) ref;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_disposeSigner
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1disposeSigner
(JNIEnv *env, jobject o, jlong ref) {
    UNUSED(env);
    UNUSED(o);
    ec_ctx_destroy((ec_ctx *) ref);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_initSign
 * Signature: (JJLjava/lang/String;Lorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1initSign
(JNIEnv *env, jobject jo, jlong ec_ref, jlong key_ref,
 jstring _digest, jobject rnd_src) {
    UNUSED(jo);

    ec_ctx *ctx = (ec_ctx *) ec_ref;
    jo_assert(ctx != NULL);

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (_digest == NULL) {
        return JO_NAME_IS_NULL;
    }

    const char *digest = (*env)->GetStringUTFChars(env, _digest, NULL);
    if (digest == NULL) {
        return JO_UNABLE_TO_ACCESS_NAME;
    }

    int32_t ret_code = ec_ctx_init_sign(ctx, spec, digest, rnd_src);
    (*env)->ReleaseStringUTFChars(env, _digest, digest);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_initVerify
 * Signature: (JJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1initVerify
(JNIEnv *env, jobject jo, jlong ec_ref, jlong key_ref, jstring _digest) {
    UNUSED(jo);

    ec_ctx *ctx = (ec_ctx *) ec_ref;
    jo_assert(ctx != NULL);

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (_digest == NULL) {
        return JO_NAME_IS_NULL;
    }

    const char *digest = (*env)->GetStringUTFChars(env, _digest, NULL);
    if (digest == NULL) {
        return JO_UNABLE_TO_ACCESS_NAME;
    }

    int32_t ret_code = ec_ctx_init_verify(ctx, spec, digest);
    (*env)->ReleaseStringUTFChars(env, _digest, digest);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1update
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(jo);

    ec_ctx *ctx = (ec_ctx *) ref;
    jo_assert(ctx != NULL);

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
    ret_code = ec_ctx_update(ctx, in, in_len);

exit:
    release_critical_ctx(&input);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_sign
 * Signature: (J[BILorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1sign
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _output, jint out_off, jobject rnd_src) {
    UNUSED(jo);

    ec_ctx *ctx = (ec_ctx *) ref;
    jo_assert(ctx != NULL);

    if (_output == NULL) {
        return ec_ctx_sign(ctx, NULL, 0, rnd_src);
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

    ret_code = ec_ctx_sign(ctx, out, out_len, rnd_src);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_verify
 * Signature: (J[BILorg/openssl/jostle/rand/RandSource;)I
 *
 * EC verify needs a RandSource — OpenSSL's EC implementation uses RAND
 * internally for point-blinding (a side-channel mitigation), and that
 * RAND consumption flows through Jostle's lib-ctx-bound RAND provider.
 * This bridge MUST use the non-critical bytearray helper (not
 * critical_bytearray_ctx) because the C path makes a Java upcall, and
 * upcalls are forbidden inside JNI critical regions.
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1verify
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _sig, jint sig_len, jobject rnd_src) {
    UNUSED(jo);

    ec_ctx *ctx = (ec_ctx *) ref;
    jo_assert(ctx != NULL);

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

    ret_code = ec_ctx_verify(ctx, sig.bytearray, sig_len, rnd_src);

exit:
    release_bytearray_ctx(&sig);
    return ret_code;
}


// =================================================================
// Key agreement (ECDH) session
// =================================================================

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_allocateKex
 * Signature: ([I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1allocateKex
(JNIEnv *env, jobject jo, jintArray err) {
    UNUSED(jo);
    jo_assert(err != NULL);

    int rc = 0;
    void *ref = ec_kex_create(&rc);
    (*env)->SetIntArrayRegion(env, err, 0, 1, &rc);
    return (jlong) ref;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_disposeKex
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1disposeKex
(JNIEnv *env, jobject jo, jlong ref) {
    UNUSED(env);
    UNUSED(jo);
    ec_kex_destroy((ec_kex_ctx *) ref);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_kexInit
 * Signature: (JJLorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1kexInit
(JNIEnv *env, jobject jo, jlong kex_ref, jlong key_ref, jobject rnd_src) {
    UNUSED(env);
    UNUSED(jo);

    ec_kex_ctx *ctx = (ec_kex_ctx *) kex_ref;
    jo_assert(ctx != NULL);

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    return ec_kex_init(ctx, spec, rnd_src);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_kexSetPeer
 * Signature: (JJLorg/openssl/jostle/rand/RandSource;)I
 *
 * RandSource is required because for binary-field curves
 * EVP_PKEY_derive_set_peer triggers an internal point-blinded
 * scalar-multiplication via EVP_PKEY_public_check; the lib-ctx-bound
 * RAND provider has to be able to upcall into Java for entropy.
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1kexSetPeer
(JNIEnv *env, jobject jo, jlong kex_ref, jlong key_ref, jobject rnd_src) {
    UNUSED(env);
    UNUSED(jo);

    ec_kex_ctx *ctx = (ec_kex_ctx *) kex_ref;
    jo_assert(ctx != NULL);

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    return ec_kex_set_peer(ctx, spec, rnd_src);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ec_ECServiceJNI
 * Method:    ni_kexDerive
 * Signature: (J[BILorg/openssl/jostle/rand/RandSource;)I
 *
 * Like the verify path, derive must use the non-critical bytearray
 * helper because EC point-blinding inside EVP_PKEY_derive draws from
 * the Java RAND upcall.
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1kexDerive
(JNIEnv *env, jobject jo, jlong kex_ref, jbyteArray _out, jint out_off, jobject rnd_src) {
    UNUSED(jo);

    ec_kex_ctx *ctx = (ec_kex_ctx *) kex_ref;
    jo_assert(ctx != NULL);

    if (_out == NULL) {
        // Two-call protocol: caller wants the required length.
        return ec_kex_derive(ctx, NULL, 0, rnd_src);
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

    ret_code = ec_kex_derive(ctx, out, out_len, rnd_src);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}
