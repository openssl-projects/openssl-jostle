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
#include "org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/rsa.h"
#include "../util/ops.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_allocateSigner
 * Signature: ([I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1allocateSigner
(JNIEnv *env, jobject jo, jintArray err) {
    UNUSED(jo);
    jo_assert(err != NULL);

    int rc = 0;
    void *ref = rsa_ctx_create(&rc);

    (*env)->SetIntArrayRegion(env, err, 0, 1, &rc);

    return (jlong) ref;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_disposeSigner
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1disposeSigner
(JNIEnv *env, jobject o, jlong ref) {
    UNUSED(env);
    UNUSED(o);

    rsa_ctx *ctx = (void *) ref;
    if (ctx == NULL) {
        return;
    }
    rsa_ctx_destroy(ctx);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_generateKeyPair
 * Signature: (I[B[ILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1generateKeyPair
(JNIEnv *env, jobject jo, jint bits, jbyteArray _pubexp, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    java_bytearray_ctx pubexp;
    init_bytearray_ctx(&pubexp);

    if (_pubexp == NULL) {
        ret_val = JO_RSA_PUB_EXP_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&pubexp, env, _pubexp)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    spec = create_spec();
    ret_val = rsa_generate_key(spec, bits, pubexp.bytearray, pubexp.size, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    release_bytearray_ctx(&pubexp);
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_decodePublicComponents
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1decodePublicComponents
(JNIEnv *env, jobject jo, jlong spec_ref, jbyteArray _n, jbyteArray _e) {
    UNUSED(jo);

    key_spec *spec = (key_spec *) spec_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (_n == NULL) {
        return JO_RSA_MODULUS_IS_NULL;
    }
    if (_e == NULL) {
        return JO_RSA_PUB_EXP_IS_NULL;
    }

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx n_ctx;
    java_bytearray_ctx e_ctx;
    init_bytearray_ctx(&n_ctx);
    init_bytearray_ctx(&e_ctx);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&n_ctx, env, _n)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&e_ctx, env, _e)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    ret_code = rsa_decode_public_components(spec,
                                            n_ctx.bytearray, n_ctx.size,
                                            e_ctx.bytearray, e_ctx.size);

exit:
    release_bytearray_ctx(&n_ctx);
    release_bytearray_ctx(&e_ctx);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_decodePrivateComponents
 * Signature: (J[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1decodePrivateComponents
(JNIEnv *env, jobject jo, jlong spec_ref, jbyteArray _n, jbyteArray _e, jbyteArray _d) {
    UNUSED(jo);

    key_spec *spec = (key_spec *) spec_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (_n == NULL) {
        return JO_RSA_MODULUS_IS_NULL;
    }
    if (_e == NULL) {
        return JO_RSA_PUB_EXP_IS_NULL;
    }
    if (_d == NULL) {
        return JO_RSA_PRIV_EXP_IS_NULL;
    }

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx n_ctx, e_ctx, d_ctx;
    init_bytearray_ctx(&n_ctx);
    init_bytearray_ctx(&e_ctx);
    init_bytearray_ctx(&d_ctx);

    // Each access call gets its own OPS slot so tests can isolate
    // which array's GetByteArrayElements failed. The natural
    // (non-OPS) failure path still short-circuits at the first
    // failing call thanks to operator-||.
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&n_ctx, env, _n)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&e_ctx, env, _e)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&d_ctx, env, _d)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    ret_code = rsa_decode_private_components(spec,
                                             n_ctx.bytearray, n_ctx.size,
                                             e_ctx.bytearray, e_ctx.size,
                                             d_ctx.bytearray, d_ctx.size);

exit:
    release_bytearray_ctx(&n_ctx);
    release_bytearray_ctx(&e_ctx);
    release_bytearray_ctx(&d_ctx);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_decodePrivateComponentsCrt
 * Signature: (J[B[B[B[B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1decodePrivateComponentsCrt
(JNIEnv *env, jobject jo, jlong spec_ref,
 jbyteArray _n, jbyteArray _e, jbyteArray _d,
 jbyteArray _p, jbyteArray _q,
 jbyteArray _dp, jbyteArray _dq, jbyteArray _qinv) {
    UNUSED(jo);

    key_spec *spec = (key_spec *) spec_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (_n == NULL) {
        return JO_RSA_MODULUS_IS_NULL;
    }
    if (_e == NULL) {
        return JO_RSA_PUB_EXP_IS_NULL;
    }
    if (_d == NULL) {
        return JO_RSA_PRIV_EXP_IS_NULL;
    }
    if (_p == NULL) {
        return JO_RSA_PRIME_P_IS_NULL;
    }
    if (_q == NULL) {
        return JO_RSA_PRIME_Q_IS_NULL;
    }
    if (_dp == NULL) {
        return JO_RSA_PRIME_EXP_P_IS_NULL;
    }
    if (_dq == NULL) {
        return JO_RSA_PRIME_EXP_Q_IS_NULL;
    }
    if (_qinv == NULL) {
        return JO_RSA_CRT_COEFFICIENT_IS_NULL;
    }

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx n_ctx, e_ctx, d_ctx, p_ctx, q_ctx, dp_ctx, dq_ctx, qi_ctx;
    init_bytearray_ctx(&n_ctx);  init_bytearray_ctx(&e_ctx);
    init_bytearray_ctx(&d_ctx);  init_bytearray_ctx(&p_ctx);
    init_bytearray_ctx(&q_ctx);  init_bytearray_ctx(&dp_ctx);
    init_bytearray_ctx(&dq_ctx); init_bytearray_ctx(&qi_ctx);

    // First four access calls get distinct OPS slots so each can be
    // selectively fault-injected. The remaining four reuse the same
    // pattern (load_bytearray_ctx is structurally identical for every
    // array argument) but stay un-fault-injected — there are only four
    // OPS_FAILED_ACCESS_* slots and the four already covered exercise
    // the full helper code path.
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&n_ctx, env, _n)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&e_ctx, env, _e)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&d_ctx, env, _d)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_4 !load_bytearray_ctx(&p_ctx, env, _p)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (!load_bytearray_ctx(&q_ctx, env, _q) ||
        !load_bytearray_ctx(&dp_ctx, env, _dp) ||
        !load_bytearray_ctx(&dq_ctx, env, _dq) ||
        !load_bytearray_ctx(&qi_ctx, env, _qinv)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    ret_code = rsa_decode_private_components_crt(spec,
                                                 n_ctx.bytearray, n_ctx.size,
                                                 e_ctx.bytearray, e_ctx.size,
                                                 d_ctx.bytearray, d_ctx.size,
                                                 p_ctx.bytearray, p_ctx.size,
                                                 q_ctx.bytearray, q_ctx.size,
                                                 dp_ctx.bytearray, dp_ctx.size,
                                                 dq_ctx.bytearray, dq_ctx.size,
                                                 qi_ctx.bytearray, qi_ctx.size);

exit:
    release_bytearray_ctx(&n_ctx);
    release_bytearray_ctx(&e_ctx);
    release_bytearray_ctx(&d_ctx);
    release_bytearray_ctx(&p_ctx);
    release_bytearray_ctx(&q_ctx);
    release_bytearray_ctx(&dp_ctx);
    release_bytearray_ctx(&dq_ctx);
    release_bytearray_ctx(&qi_ctx);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_getComponent
 * Signature: (JI[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1getComponent
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
        ret_code = rsa_get_component(spec, component, NULL, 0);
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&out_ctx, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = rsa_get_component(spec, component, out_ctx.bytearray, out_ctx.size);

exit:
    release_bytearray_ctx(&out_ctx);
    return ret_code;
}


/*
 * Helper for init_sign / init_verify: extracts the digest name and
 * (optionally) the MGF1 hash name. Caller must release them via
 * the matching cleanup helper below.
 */
typedef struct {
    const char *digest;
    const char *mgf1;
    jstring digest_jstr;
    jstring mgf1_jstr;
} rsa_init_strings;

static int32_t rsa_init_strings_load(JNIEnv *env, jstring digest_str, jstring mgf1_str,
                                     rsa_init_strings *out) {
    out->digest = NULL;
    out->mgf1 = NULL;
    out->digest_jstr = digest_str;
    out->mgf1_jstr = mgf1_str;

    if (digest_str == NULL) {
        return JO_NAME_IS_NULL;
    }

    out->digest = (*env)->GetStringUTFChars(env, digest_str, NULL);
    if (OPS_FAILED_ACCESS_1 out->digest == NULL) {
        return JO_UNABLE_TO_ACCESS_NAME;
    }

    if (mgf1_str != NULL) {
        out->mgf1 = (*env)->GetStringUTFChars(env, mgf1_str, NULL);
        if (OPS_FAILED_ACCESS_2 out->mgf1 == NULL) {
            return JO_UNABLE_TO_ACCESS_NAME;
        }
    }
    return JO_SUCCESS;
}

static void rsa_init_strings_release(JNIEnv *env, rsa_init_strings *s) {
    if (s->digest != NULL && s->digest_jstr != NULL) {
        (*env)->ReleaseStringUTFChars(env, s->digest_jstr, s->digest);
    }
    if (s->mgf1 != NULL && s->mgf1_jstr != NULL) {
        (*env)->ReleaseStringUTFChars(env, s->mgf1_jstr, s->mgf1);
    }
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_initSign
 * Signature: (JJLjava/lang/String;ILjava/lang/String;ILorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1initSign
(JNIEnv *env, jobject jo, jlong rsa_ref, jlong key_ref,
 jstring _digest, jint padding_mode, jstring _mgf1, jint salt_len, jobject rnd_src) {
    UNUSED(jo);

    rsa_ctx *ctx = (rsa_ctx *) rsa_ref;
    jo_assert(ctx != NULL);

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    rsa_init_strings names;
    int32_t load = rsa_init_strings_load(env, _digest, _mgf1, &names);
    if (load != JO_SUCCESS) {
        rsa_init_strings_release(env, &names);
        return load;
    }

    int32_t ret_code = rsa_ctx_init_sign(ctx, spec, names.digest,
                                         padding_mode, names.mgf1, salt_len,
                                         rnd_src);

    rsa_init_strings_release(env, &names);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_initVerify
 * Signature: (JJLjava/lang/String;ILjava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1initVerify
(JNIEnv *env, jobject jo, jlong rsa_ref, jlong key_ref,
 jstring _digest, jint padding_mode, jstring _mgf1, jint salt_len) {
    UNUSED(jo);

    rsa_ctx *ctx = (rsa_ctx *) rsa_ref;
    jo_assert(ctx != NULL);

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    rsa_init_strings names;
    int32_t load = rsa_init_strings_load(env, _digest, _mgf1, &names);
    if (load != JO_SUCCESS) {
        rsa_init_strings_release(env, &names);
        return load;
    }

    int32_t ret_code = rsa_ctx_init_verify(ctx, spec, names.digest,
                                           padding_mode, names.mgf1, salt_len);

    rsa_init_strings_release(env, &names);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1update
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(jo);

    rsa_ctx *ctx = (rsa_ctx *) ref;
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
    ret_code = rsa_ctx_update(ctx, in, in_len);

exit:
    release_critical_ctx(&input);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_sign
 * Signature: (J[BILorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1sign
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _output, jint out_off, jobject rnd_src) {
    UNUSED(jo);

    rsa_ctx *ctx = (rsa_ctx *) ref;
    jo_assert(ctx != NULL);

    if (_output == NULL) {
        // Caller wants length.
        return rsa_ctx_sign(ctx, NULL, 0, rnd_src);
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

    ret_code = rsa_ctx_sign(ctx, out, out_len, rnd_src);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI
 * Method:    ni_verify
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1verify
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _sig, jint sig_len) {
    UNUSED(jo);

    rsa_ctx *ctx = (rsa_ctx *) ref;
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

    ret_code = rsa_ctx_verify(ctx, sig.bytearray, sig_len);

exit:
    release_bytearray_ctx(&sig);
    return ret_code;
}
