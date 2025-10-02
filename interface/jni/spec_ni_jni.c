//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/types.h>

#include "bytearrays.h"
#include "org_openssl_jostle_jcajce_spec_SpecJNI.h"
#include "types.h"
#include "../util/encapdecap.h"
#include "../util/key_spec.h"
#include "../util/ops.h"

/*
 * Class:     org_openssl_jostle_jcajce_spec_SpecJNI
 * Method:    disposePkey
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_spec_SpecJNI_dispose
(JNIEnv *env, jobject jo, jlong ref) {
    UNUSED(env);
    UNUSED(jo);
    key_spec *ks = (key_spec *) ((void *) ref);
    if (ks != NULL) {
        free_key_spec(ks);
    }
}


/*
 * Class:     org_openssl_jostle_jcajce_spec_SpecJNI
 * Method:    allocateKeySpec
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_spec_SpecJNI_allocate(JNIEnv *env, jobject jo) {
    UNUSED(env);
    UNUSED(jo);
    key_spec *spec = OPENSSL_zalloc(sizeof(key_spec));
    assert(spec != NULL);
    return (jlong) spec;
}



/*
 * Class:     org_openssl_jostle_jcajce_spec_SpecJNI
 * Method:    getName
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_openssl_jostle_jcajce_spec_SpecJNI_getName
(JNIEnv *env, jobject jo, jlong ref) {
    UNUSED(jo);

    const key_spec *ks = (key_spec *) (void *) ref;
    if (ks == NULL || ks->key == NULL) {
        return NULL;
    }

    const char *name = EVP_PKEY_get0_type_name(ks->key);

    if (name == NULL) {
        return NULL;
    }

    // will return null if the string cannot be constructed
    // String owned by JVM at this point
    return (*env)->NewStringUTF(env, name);
}


/*
 * Class:     org_openssl_jostle_jcajce_spec_SpecJNI
 * Method:    encap
 * Signature: (JLjava/lang/String;[BII[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_spec_SpecJNI_encap
(JNIEnv *env, jobject jo, jlong ref, jstring _opp, jbyteArray _input, jint in_off, jint in_len, jbyteArray _output,
 jint out_off, jint out_len) {
    UNUSED(jo);

    key_spec *ks = (key_spec *) ((void *) ref);
    if (ks == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    if (ks->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }


    java_bytearray_ctx input, output;
    int32_t ret = 0;
    char *opp = NULL;

    init_bytearray_ctx(&input);
    init_bytearray_ctx(&output);


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (in_off < 0) {
        ret = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_bytearray_in_range(&input, in_off, in_len)) {
        ret = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&output, env, _output)) {
        ret = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    uint8_t *out = NULL;

    if (output.bytearray != NULL) {
        if (out_off < 0) {
            ret = JO_OUTPUT_OFFSET_IS_NEGATIVE;
            goto exit;
        }

        if (out_len < 0) {
            ret = JO_OUTPUT_LEN_IS_NEGATIVE;
            goto exit;
        }

        if (!check_bytearray_in_range(&output, out_off, out_len)) {
            ret = JO_OUTPUT_OUT_OF_RANGE;
            goto exit;
        }
        out = (uint8_t *) output.bytearray + out_off;
    }


    if (_opp != NULL) {
        opp = (char *) (*env)->GetStringUTFChars(env, _opp, NULL);
        if (OPS_FAILED_ACCESS_3 opp == NULL) {
            ret = JO_FAILED_ACCESS_ENCAP_OPP;
            goto exit;
        }
    }

    uint8_t *in = input.bytearray + in_off;

    ret = encap(ks, (const char *) opp, in, in_len, out, out_len);

exit:
    if (opp != NULL) {
        (*env)->ReleaseStringUTFChars(env, _opp, opp);
    }

    release_bytearray_ctx(&output);
    release_bytearray_ctx(&input);


    return ret;
}

/*
 * Class:     org_openssl_jostle_jcajce_spec_SpecJNI
 * Method:    decap
 * Signature: (JLjava/lang/String;[BII[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_spec_SpecJNI_decap
(JNIEnv *env, jobject jo, jlong ref, jstring _opp, jbyteArray _input, jint int_off, jint in_len, jbyteArray _output,
 jint out_off, jint out_len) {
    UNUSED(jo);

    key_spec *ks = (key_spec *) ((void *) ref);
    if (ks == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    if (ks->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }


    java_bytearray_ctx input, output;
    int32_t ret = 0;
    char *opp = NULL;

    init_bytearray_ctx(&input);
    init_bytearray_ctx(&output);


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (int_off < 0) {
        ret = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_bytearray_in_range(&input, int_off, in_len)) {
        ret = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&output, env, _output)) {
        ret = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    uint8_t *out = NULL;

    if (output.bytearray != NULL) {
        if (out_off < 0) {
            ret = JO_OUTPUT_OFFSET_IS_NEGATIVE;
            goto exit;
        }

        if (out_len < 0) {
            ret = JO_OUTPUT_LEN_IS_NEGATIVE;
            goto exit;
        }

        if (!check_bytearray_in_range(&output, out_off, out_len)) {
            ret = JO_OUTPUT_OUT_OF_RANGE;
            goto exit;
        }
        out = (uint8_t *) output.bytearray + out_off;
    }


    if (_opp != NULL) {
        opp = (char *) (*env)->GetStringUTFChars(env, _opp, NULL);
        if (OPS_FAILED_ACCESS_3 opp == NULL) {
            ret = JO_FAILED_ACCESS_ENCAP_OPP;
            goto exit;
        }
    }

    uint8_t *in = input.bytearray + int_off;

    ret = decap(ks, (const char *) opp, in, in_len, out, out_len);

exit:
    if (opp != NULL) {
        (*env)->ReleaseStringUTFChars(env, _opp, opp);
    }

    release_bytearray_ctx(&output);
    release_bytearray_ctx(&input);

    return ret;
}
