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
#include "secret_bytearrays.h"
#include "org_openssl_jostle_jcajce_provider_ed_EDServiceJNI.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/edec.h"
#include "../util/ops.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_allocateSigner
 * Signature: ([I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1allocateSigner
(JNIEnv *env, jobject jo, jintArray err) {
    UNUSED(jo);

    jo_assert(err != NULL);

    int rc = 0;
    void *ref = edec_ctx_create(&rc);

    (*env)->SetIntArrayRegion(env, err, 0, 1, &rc);

    return (jlong) ref;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_disposeSigner
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1disposeSigner
(JNIEnv *env, jobject o, jlong ref) {
    UNUSED(env);
    UNUSED(o);

    edec_ctx *ctx = (void *) ref;
    if (ctx == NULL) {
        return;
    }
    edec_ctx_destroy(ctx);
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_generateKeyPair
 * Signature: (I[ILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1generateKeyPair
(JNIEnv *env, jobject jo, jint type, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *key_spec = create_spec();

    ret_val = edec_generate_key(key_spec, type, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(key_spec);
        key_spec = NULL;
    }

    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) key_spec;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_decode_publicKey
 * Signature: (JI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1decode_1publicKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);

    key_spec *key_spec = (void *) ref;


    jint ret_val = JO_FAIL;
    java_bytearray_ctx input; // Non critical access
    init_bytearray_ctx(&input);

    ret_val = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_val)) {
        goto exit;
    }

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
    ret_val = edec_decode_public_key(key_spec, key_type, start, in_len);


exit:
    release_bytearray_ctx(&input);
    return ret_val;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_decode_privateKey
 * Signature: (JI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1decode_1privateKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);

    key_spec *key_spec = (void *) ref;


    jint ret_val = JO_FAIL;
    // The private key goes through the secret helper: cleansed before release.
    java_secret_bytearray_ctx input;
    init_secret_bytearray_ctx(&input);

    ret_val = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_val)) {
        goto exit;
    }

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
    ret_val = edec_decode_private_key(key_spec, key_type, start, in_len);


exit:
    release_secret_bytearray_ctx(&input);
    return ret_val;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_getPublicKey
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1getPublicKey
(JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;

    int32_t check_rc = key_spec_check(key_spec);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }


    java_bytearray_ctx output; // Non critical access
    init_bytearray_ctx(&output);

    int32_t ret_code = JO_FAIL;

    if (_output == NULL) {
        ret_code = edec_get_public_encoded(key_spec,NULL, 0);
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = edec_get_public_encoded(key_spec, output.bytearray, output.size);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_getPrivateKey
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1getPrivateKey
(JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;

    int32_t ret_code = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    if (_output == NULL) {
        return edec_get_private_encoded(key_spec, NULL, 0);
    }

    // The private key goes through the secret helper: cleansed, and written back only on success.
    java_secret_bytearray_ctx output;
    init_secret_bytearray_ctx(&output);
    if (OPS_FAILED_ACCESS_1 !load_secret_output_ctx(&output, env, _output)) {
        discard_secret_bytearray_ctx(&output);
        return JO_FAILED_ACCESS_OUTPUT;
    }

    ret_code = edec_get_private_encoded(key_spec, output.bytearray, output.size);
    if (SUCCESSFUL(ret_code)) {
        release_secret_bytearray_ctx(&output);
    } else {
        discard_secret_bytearray_ctx(&output);
    }
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_initSign
 * Signature: (JJLorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1initSign
(JNIEnv *env, jobject jo, jlong edec_ref, jlong key_ref, jstring _name, jbyteArray _context, jint context_len,
 jobject rnd_src) {
    UNUSED(jo);
    edec_ctx *eddsa = (edec_ctx *) edec_ref;
    int32_t check_rc = edec_ctx_check(eddsa);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (_name == NULL) {
        return JO_NAME_IS_NULL;
    }

    int32_t ret_code = JO_FAIL;

    java_bytearray_ctx context;
    init_bytearray_ctx(&context);

    const char *name = (*env)->GetStringUTFChars(env, _name, NULL);
    if (OPS_FAILED_ACCESS_2 name == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }
    // GetStringUTFLength returns the byte length of the UTF-8 encoding (modified UTF-8).
    // OSSL_PARAM_utf8_string in edec_ctx_init_sign expects byte length, not UTF-16 char count.
    const int name_len = (*env)->GetStringUTFLength(env, _name);

    if (name_len <= 0) {
        ret_code = JO_NAME_IS_NULL;
        goto exit;
    }

    // An embedded NUL names no instance, as the FFM bridge's length check finds.
    if (modified_utf8_names_nothing(name)) {
        ret_code = JO_EDEC_INSTANCE_NOT_SUPPORTED;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&context, env, _context)) {
        ret_code = JO_FAILED_ACCESS_CONTEXT;
        goto exit;
    }

    key_spec *spec = (key_spec *) key_ref;
    ret_code = key_spec_check(spec);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }

    if (context.bytearray != NULL) {
        if ((size_t) context_len > context.size) {
            ret_code = JO_CONTEXT_LEN_PAST_END;
            goto exit;
        }
    }


    ret_code = edec_ctx_init_sign(eddsa, spec, name, name_len, context.bytearray, context_len, rnd_src);

exit:
    // name is NULL if GetStringUTFChars failed above — ReleaseStringUTFChars
    // with a NULL pointer is undefined (matches the EC bridge's guard).
    if (name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _name, name);
    }
    release_bytearray_ctx(&context);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_sign
 * Signature: (J[BILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1sign
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _output, jint out_off, jobject rnd_src) {
    UNUSED(env);
    UNUSED(jo);
    edec_ctx *edec = (edec_ctx *) ref;
    int32_t ret_code = edec_ctx_check(edec);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    // One order on both bridges: ctx, rnd, offset, then the output.
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (out_off < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }

    if (_output == NULL) {
        /* Caller wants length */
        return edec_ctx_sign(edec, NULL, 0, rnd_src);
    }

    size_t out_len = 0;

    java_bytearray_ctx output;
    init_bytearray_ctx(&output);

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

    ret_code = edec_ctx_sign(edec, output_data, out_len, rnd_src);

exit:
    release_bytearray_ctx(&output);

    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_initVerify
 * Signature: (JJLorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1initVerify
(JNIEnv *env, jobject jo, jlong edec_ref, jlong key_ref, jstring _name, jbyteArray _context, jint context_len) {
    UNUSED(jo);

    edec_ctx *eddsa = (edec_ctx *) edec_ref;
    int32_t check_rc = edec_ctx_check(eddsa);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    if (_name == NULL) {
        return JO_NAME_IS_NULL;
    }

    int32_t ret_code = JO_FAIL;

    java_bytearray_ctx context;
    init_bytearray_ctx(&context);

    const char *name = (*env)->GetStringUTFChars(env, _name, NULL);
    if (OPS_FAILED_ACCESS_2 name == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }
    // GetStringUTFLength returns the byte length of the UTF-8 encoding (modified UTF-8).
    // OSSL_PARAM_utf8_string in edec_ctx_init_verify expects byte length, not UTF-16 char count.
    const int name_len = (*env)->GetStringUTFLength(env, _name);

    if (name_len <= 0) {
        ret_code = JO_NAME_IS_NULL;
        goto exit;
    }

    // An embedded NUL names no instance, as the FFM bridge's length check finds.
    if (modified_utf8_names_nothing(name)) {
        ret_code = JO_EDEC_INSTANCE_NOT_SUPPORTED;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&context, env, _context)
    ) {
        ret_code = JO_FAILED_ACCESS_CONTEXT;
        goto exit;
    }


    key_spec *spec = (key_spec *) key_ref;
    ret_code = key_spec_check(spec);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }


    if (context.bytearray != NULL) {
        if ((size_t) context_len > context.size) {
            ret_code = JO_CONTEXT_LEN_PAST_END;
            goto exit;
        }
    }

    ret_code = edec_ctx_init_verify(eddsa, spec, name, name_len, context.bytearray, context_len);

exit:
    // name is NULL if GetStringUTFChars failed above — ReleaseStringUTFChars
    // with a NULL pointer is undefined (matches the EC bridge's guard).
    if (name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _name, name);
    }
    release_bytearray_ctx(&context);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_verify
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1verify
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _sig, jint sig_len) {
    UNUSED(jo);

    edec_ctx *ctx = (edec_ctx *) ref;
    int32_t check_rc = edec_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    java_bytearray_ctx sig;
    init_bytearray_ctx(&sig);


    int32_t ret_code = JO_FAIL;

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


    ret_code = edec_ctx_verify(ctx, sig.bytearray, sig_len);


exit:
    release_bytearray_ctx(&sig);

    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1update
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(jo);
    edec_ctx *ctx = (edec_ctx *) ref;
    int32_t ret_code = edec_ctx_check(ctx);
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
    ret_code = edec_ctx_update(ctx, in, in_len);

exit:
    release_critical_ctx(&input);
    return ret_code;
}
