//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <string.h>

#include "bytearrays.h"
#include "org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI.h"
#include "types.h"
#include "../util/kdf.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI
 * Method:    scrypt
 * Signature: ([B[BIII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI_scrypt
(JNIEnv *env, jobject jo, jbyteArray _password, jbyteArray _salt, jint n, jint r, jint p, jbyteArray _out,
 jint out_offset, jint out_len) {
    UNUSED(env);
    UNUSED(jo);

    int ret_code = JO_FAIL;

    java_bytearray_ctx password;
    java_bytearray_ctx salt;
    java_bytearray_ctx output;

    init_bytearray_ctx(&password);
    init_bytearray_ctx(&salt);
    init_bytearray_ctx(&output);

    if (!load_bytearray_ctx(&password, env, _password)) {
        ret_code = JO_KDF_PASSWORD_FAILED_ACCESS;
        goto exit;
    }

    if (password.array == NULL) {
        ret_code = JO_KDF_PASSWORD_NULL;
        goto exit;
    }


    if (!load_bytearray_ctx(&salt, env, _salt)) {
        ret_code = JO_KDF_SALT_FAILED_ACCESS;
    }

    if (salt.array == NULL) {
        ret_code = JO_KDF_SALT_NULL;
        goto exit;
    }

    if (salt.size == 0) {
        ret_code = JO_KDF_SALT_EMPTY;
        goto exit;
    }

    if (n < 0) {
        ret_code = JO_KDF_SCRYPT_N_NEGATIVE;
        goto exit;
    }

    if (r < 0) {
        ret_code = JO_KDF_SCRYPT_R_NEGATIVE;
        goto exit;
    }

    if (!load_bytearray_ctx(&output, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    if (output.array == NULL) {
        ret_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (out_offset < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (out_len < 0) {
        ret_code = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_bytearray_in_range(&output, out_offset, out_len)) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }


    // out_offset is not negative by this point
    uint8_t *out = output.bytearray + out_offset;

    ret_code = scrypt(
        password.bytearray, password.size,
        salt.bytearray, salt.size,
        n,
        r,
        p,
        out, out_len);


exit:
    release_bytearray_ctx(&salt);
    release_bytearray_ctx(&password);
    release_bytearray_ctx(&output);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI
 * Method:    pbe2
 * Signature: ([B[BILjava/lang/String;[BI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI_pbkdf2
(JNIEnv *env, jobject jo, jbyteArray _password, jbyteArray _salt, jint iter, jstring digest, jbyteArray _out,
 jint out_offset, jint out_len) {
    UNUSED(env);
    UNUSED(jo);

    UNUSED(env);
    UNUSED(jo);

    int ret_code = JO_FAIL;
    const char *digest_str = NULL;

    java_bytearray_ctx password;
    java_bytearray_ctx salt;
    java_bytearray_ctx output;

    init_bytearray_ctx(&password);
    init_bytearray_ctx(&salt);
    init_bytearray_ctx(&output);

    if (!load_bytearray_ctx(&password, env, _password)) {
        ret_code = JO_KDF_PASSWORD_FAILED_ACCESS;
        goto exit;
    }

    if (password.array == NULL) {
        ret_code = JO_KDF_PASSWORD_NULL;
        goto exit;
    }


    if (!load_bytearray_ctx(&salt, env, _salt)) {
        ret_code = JO_KDF_SALT_FAILED_ACCESS;
    }

    if (salt.array == NULL) {
        ret_code = JO_KDF_SALT_NULL;
        goto exit;
    }

    if (salt.size == 0) {
        ret_code = JO_KDF_SALT_EMPTY;
        goto exit;
    }

    if (iter < 0) {
        ret_code = JO_KDF_PBE_ITER_NEGATIVE;
        goto exit;
    }


    if (!load_bytearray_ctx(&output, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    if (output.array == NULL) {
        ret_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (out_offset < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (out_len < 0) {
        ret_code = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_bytearray_in_range(&output, out_offset, out_len)) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (digest == NULL) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    jsize digest_str_len = (*env)->GetStringUTFLength(env, digest);
    if (digest_str_len <= 0) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }
    digest_str = (*env)->GetStringUTFChars(env, digest,NULL);


    // out_offset is not negative by this point
    uint8_t *out = output.bytearray + out_offset;

    ret_code = pbkdf2(
        password.bytearray, password.size,
        salt.bytearray, salt.size,
        iter,
        (uint8_t *) digest_str,
        digest_str_len,
        out, out_len);


exit:
    release_bytearray_ctx(&salt);
    release_bytearray_ctx(&password);
    release_bytearray_ctx(&output);

    if (digest_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, digest, digest_str);
    }


    return ret_code;
}
