//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <openssl/asn1.h>

#include "bytearrays.h"
#include "byte_array_critical.h"
#include "secret_bytearrays.h"
#include "org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/key_spec.h"
#include "../util/mldsa.h"
#include "../util/ops.h"
#include "../util/jo_assert.h"

/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    generateKeyPair
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL
Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1generateKeyPair__I_3ILorg_openssl_jostle_rand_RandSource_2
(JNIEnv *env, jobject jo, jint type, jintArray _err, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(_err != NULL);

    jint ret_val = JO_FAIL;
    key_spec *key_spec = NULL;

    if (rnd_src == NULL) {
        ret_val = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    key_spec = create_spec();
    ret_val = mldsa_generate_key_pair(key_spec, type, NULL, 0, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(key_spec);
        key_spec = NULL;
    }

exit:
    (*env)->SetIntArrayRegion(env, _err, 0, 1, &ret_val);
    return (jlong) key_spec;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    generateKeyPair
 * Signature: (I[BI)J
 */
JNIEXPORT jlong JNICALL
Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1generateKeyPair__I_3I_3BILorg_openssl_jostle_rand_RandSource_2
(JNIEnv *env, jobject jo, jint type, jintArray _err, jbyteArray _seed, jint seed_len, jobject rnd_src) {
    UNUSED(jo);
    UNUSED(env);
    jo_assert(_err != NULL);

    key_spec *key_spec = NULL;

    // The seed is the private key: cleansed before release.
    java_secret_bytearray_ctx seed;
    init_secret_bytearray_ctx(&seed);

    int32_t ret_code = JO_FAIL;

    if (rnd_src == NULL) {
        ret_code = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    if (_seed == NULL) {
        ret_code = JO_SEED_IS_NULL;
        goto exit;
    }

    if (seed_len < 0) {
        ret_code = JO_SEED_LEN_IS_NEGATIVE;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_secret_input_ctx(&seed, env, _seed)) {
        ret_code = JO_FAILED_ACCESS_SEED;
        goto exit;
    }

    if ((size_t) seed_len > seed.size) {
        ret_code = JO_INVALID_SEED_LEN_OUT_OF_RANGE;
        goto exit;
    }


    key_spec = create_spec();
    ret_code = mldsa_generate_key_pair(key_spec, type, seed.bytearray, seed_len, rnd_src);

    if (ret_code != JO_SUCCESS) {
        free_key_spec(key_spec);
        key_spec = NULL;
    }

exit:
    release_secret_bytearray_ctx(&seed);
    (*env)->SetIntArrayRegion(env, _err, 0, 1, &ret_code);
    return (jlong) key_spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    getPublicKey
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1getPublicKey(
    JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;

    int32_t ret_code = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    java_bytearray_ctx output; // Non critical access
    init_bytearray_ctx(&output);

    if (_output == NULL) {
        ret_code = mldsa_get_public_encoded(key_spec,NULL, 0);
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = mldsa_get_public_encoded(key_spec, output.bytearray, output.size);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    getPrivateKey
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1getPrivateKey(
    JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;

    int32_t ret_code = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    if (_output == NULL) {
        return mldsa_get_private_encoded(key_spec, NULL, 0);
    }

    // The private key goes through the secret helper: cleansed, and written back only on success.
    java_secret_bytearray_ctx output;
    init_secret_bytearray_ctx(&output);
    if (OPS_FAILED_ACCESS_1 !load_secret_output_ctx(&output, env, _output)) {
        discard_secret_bytearray_ctx(&output);
        return JO_FAILED_ACCESS_OUTPUT;
    }

    ret_code = mldsa_get_private_encoded(key_spec, output.bytearray, output.size);
    if (SUCCESSFUL(ret_code)) {
        release_secret_bytearray_ctx(&output);
    } else {
        discard_secret_bytearray_ctx(&output);
    }
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    getSeed
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1getSeed
(JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;

    int32_t ret_code = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    if (key_spec->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    if (_output == NULL) {
        return mldsa_get_private_seed(key_spec, NULL, 0);
    }

    // The seed is the private key: cleansed, and written back only on success.
    java_secret_bytearray_ctx output;
    init_secret_bytearray_ctx(&output);
    if (OPS_FAILED_ACCESS_1 !load_secret_output_ctx(&output, env, _output)) {
        discard_secret_bytearray_ctx(&output);
        return JO_FAILED_ACCESS_OUTPUT;
    }

    ret_code = mldsa_get_private_seed(key_spec, output.bytearray, output.size);
    if (SUCCESSFUL(ret_code)) {
        release_secret_bytearray_ctx(&output);
    } else {
        discard_secret_bytearray_ctx(&output);
    }
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    decode_publicKey
 * Signature: (JI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1decode_1publicKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);

    key_spec *key_spec = (void *) ref;

    jint ret_val = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_val)) {
        return ret_val;
    }

    java_bytearray_ctx input; // Non critical access
    init_bytearray_ctx(&input);

    if (_input == NULL) {
        ret_val = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }


    if (in_off < 0) {
        ret_val = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_bytearray_in_range(&input, in_off, in_len)) {
        ret_val = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }


    uint8_t *start = input.bytearray + in_off;
    ret_val = mldsa_decode_public_key(key_spec, key_type, start, in_len);


exit:
    release_bytearray_ctx(&input);
    return ret_val;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    decode_privateKey
 * Signature: (JI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1decode_1privateKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);

    key_spec *key_spec = (void *) ref;

    jint ret_val = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_val)) {
        return ret_val;
    }

    // The private key goes through the secret helper: cleansed before release.
    java_secret_bytearray_ctx input;
    init_secret_bytearray_ctx(&input);

    if (_input == NULL) {
        ret_val = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_secret_input_ctx(&input, env, _input)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (in_off < 0) {
        ret_val = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_secret_in_range(&input, in_off, in_len)) {
        ret_val = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }


    uint8_t *start = input.bytearray + in_off;
    ret_val = mldsa_decode_private_key(key_spec, key_type, start, in_len);


exit:
    release_secret_bytearray_ctx(&input);
    return ret_val;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    disposeSigner
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1disposeSigner
(JNIEnv *env, jobject o, jlong ref) {
    UNUSED(env);
    UNUSED(o);

    mldsa_ctx *ctx = (void *) ref;
    if (ctx == NULL) {
        return;
    }
    mldsa_ctx_destroy(ctx);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    allocateSigner
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1allocateSigner
(JNIEnv *env, jobject jo, jintArray err) {
    UNUSED(env);
    UNUSED(jo);
    jo_assert(err != NULL);

    int rc = 0;
    void *ref = mldsa_ctx_create(&rc);

    (*env)->SetIntArrayRegion(env, err, 0, 1, &rc);

    return (jlong) ref;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    initVerify
 * Signature: (JIJ)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1initVerify
(JNIEnv *env, jobject jo, jlong mldsa_ref, jlong key_ref, jbyteArray _context, jint context_len, jint mu_mode) {

    UNUSED(jo);

    mldsa_ctx *mldsa = (mldsa_ctx *) mldsa_ref;
    int32_t ret_code = mldsa_ctx_check(mldsa);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }
    key_spec *spec = (key_spec *) key_ref;
    ret_code = key_spec_check(spec);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    java_bytearray_ctx context;
    init_bytearray_ctx(&context);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&context, env, _context)) {
        ret_code = JO_FAILED_ACCESS_CONTEXT;
        goto exit;
    }

    if (context_len >= 0) {
        if (context.bytearray == NULL) {
            ret_code = JO_CONTEXT_BYTES_NULL;
            goto exit;
        }


        if ((size_t) context_len > context.size) {
            ret_code = JO_CONTEXT_LEN_PAST_END;
            goto exit;
        }
    }


    ret_code = mldsa_ctx_init_verify(mldsa, spec, context.bytearray, context_len, mu_mode);

exit:
    release_bytearray_ctx(&context);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    initSign
 * Signature: (JIJ)J
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1initSign
(JNIEnv *env, jobject jo, jlong mldsa_ref, jlong key_ref, jbyteArray _context, jint context_len, jint mu_mode,
 jobject rnd_src) {
    UNUSED(env);
    UNUSED(jo);

    mldsa_ctx *mldsa = (mldsa_ctx *) mldsa_ref;
    int32_t ret_code = mldsa_ctx_check(mldsa);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }
    key_spec *spec = (key_spec *) key_ref;
    ret_code = key_spec_check(spec);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    java_bytearray_ctx context;
    init_bytearray_ctx(&context);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&context, env, _context)) {
        ret_code = JO_FAILED_ACCESS_CONTEXT;
        goto exit;
    }

    if (context_len >= 0) {
        if (context.bytearray == NULL) {
            ret_code = JO_CONTEXT_BYTES_NULL;
            goto exit;
        }

        if ((size_t) context_len > context.size) {
            ret_code = JO_CONTEXT_LEN_PAST_END;
            goto exit;
        }
    }

    ret_code = mldsa_ctx_init_sign(mldsa, spec, context.bytearray, context_len, mu_mode, rnd_src);

exit:
    release_bytearray_ctx(&context);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1update
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(jo);
    mldsa_ctx *mldsa = (mldsa_ctx *) ref;
    int32_t ret_code = mldsa_ctx_check(mldsa);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

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
    ret_code = mldsa_update(mldsa, in, in_len);

exit:
    release_critical_ctx(&input);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    sign
 * Signature: (J[BI[BI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1sign
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _output, jint out_off, jobject rnd_src) {
    UNUSED(env);
    UNUSED(jo);
    mldsa_ctx *mldsa = (mldsa_ctx *) ref;
    int32_t ret_code = mldsa_ctx_check(mldsa);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (_output == NULL) {
        /* Caller wants length */
        return mldsa_ctx_sign(mldsa, NULL, 0, rnd_src);
    }

    size_t out_len = 0;


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

    /* out_off asserted as non-negative by this point */

    out_len = output.size - (size_t) out_off;

    if (!check_bytearray_in_range(&output, out_off, out_len)) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }


    uint8_t *output_data = output.bytearray + (size_t) out_off;

    ret_code = mldsa_ctx_sign(mldsa, output_data, out_len, rnd_src);

exit:
    release_bytearray_ctx(&output);

    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI
 * Method:    verify
 * Signature: (J[BI[BI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mldsa_MLDSAServiceJNI_ni_1verify
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _sig, jint sig_len) {
    UNUSED(jo);

    mldsa_ctx *mldsa = (mldsa_ctx *) ref;
    int32_t ret_code = mldsa_ctx_check(mldsa);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    java_bytearray_ctx sig;
    init_bytearray_ctx(&sig);

    if (_sig == NULL) {
        ret_code = JO_SIG_IS_NULL;
        goto exit;
    }

    if (sig_len < 0) {
        ret_code = JO_SIG_LENGTH_IS_NEGATIVE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&sig, env, _sig)) {
        ret_code = JO_FAILED_ACCESS_SIG;
        goto exit;
    }

    if (!check_bytearray_in_range(&sig, 0, sig_len)) {
        ret_code = JO_SIG_OUT_OF_RANGE;
        goto exit;
    }


    ret_code = mldsa_ctx_verify(mldsa, sig.bytearray, sig_len);


exit:
    release_bytearray_ctx(&sig);

    return ret_code;
}
