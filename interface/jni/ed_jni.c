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
 * Method:    ni_initSign
 * Signature: (JJLorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1initSign
(JNIEnv *env, jobject jo, jlong edec_ref, jlong key_ref, jstring _name, jbyteArray _context, jint context_len,
 jobject rnd_src) {
    UNUSED(jo);
    edec_ctx *eddsa = (edec_ctx *) edec_ref;
    jo_assert(eddsa !=NULL);
    jo_assert(_name != NULL); // jostle control this

    int32_t ret_code = JO_FAIL;

    java_bytearray_ctx context;
    init_bytearray_ctx(&context);

    const char *name = (*env)->GetStringUTFChars(env, _name, NULL);
    const int name_len = (*env)->GetStringLength(env, _name);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&context, env, _context)) {
        ret_code = JO_FAILED_ACCESS_CONTEXT;
        goto exit;
    }

    key_spec *spec = (key_spec *) key_ref;
    if (spec == NULL) {
        ret_code = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (context_len >= 0) {
        if ((size_t) context_len > context.size) {
            ret_code = JO_CONTEXT_LEN_PAST_END;
            goto exit;
        }
    }

    ret_code = edec_ctx_init_sign(eddsa, spec, name, name_len, context.bytearray, context_len, rnd_src);

exit:
    (*env)->ReleaseStringUTFChars(env, _name, name);
    release_bytearray_ctx(&context);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_sign
 * Signature: (J[BILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1sign
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _output, jint out_off, jobject rnd_src) {
    UNUSED(env);
    UNUSED(jo);
    edec_ctx *edec = (edec_ctx *) ref;
    jo_assert(edec);

    if (_output == NULL) {
        /* Caller wants length */
        return edec_ctx_sign(edec, NULL, 0, rnd_src);
    }

    int32_t ret_code = JO_FAIL;
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
    jo_assert(eddsa !=NULL);
    jo_assert(_name != NULL); // jostle control this

    int32_t ret_code = JO_FAIL;

    java_bytearray_ctx context;
    init_bytearray_ctx(&context);

    const char *name = (*env)->GetStringUTFChars(env, _name, NULL);
    const int name_len = (*env)->GetStringLength(env, _name);


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&context, env, _context)
    ) {
        ret_code = JO_FAILED_ACCESS_CONTEXT;
        goto exit;
    }


    key_spec *spec = (key_spec *) key_ref;

    if (spec == NULL) {
        ret_code = JO_KEY_SPEC_IS_NULL;
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

    ret_code = edec_ctx_init_verify(eddsa, spec, name, name_len, context.bytearray, context_len);

exit:
    (*env)->ReleaseStringUTFChars(env, _name, name);
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
    jo_assert(ctx);

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
    ret_code = edec_ctx_update(ctx, in, in_len);

exit:
    release_critical_ctx(&input);
    return ret_code;
}
