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
#include "../util/ops.h"


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

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&password, env, _password)) {
        ret_code = JO_KDF_PASSWORD_FAILED_ACCESS;
        goto exit;
    }

    if (password.array == NULL) {
        ret_code = JO_KDF_PASSWORD_NULL;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&salt, env, _salt)) {
        ret_code = JO_KDF_SALT_FAILED_ACCESS;
        goto exit;
    }

    if (salt.array == NULL) {
        ret_code = JO_KDF_SALT_NULL;
        goto exit;
    }

    if (salt.size == 0) {
        ret_code = JO_KDF_SALT_EMPTY;
        goto exit;
    }

    if (n < 2) {
        ret_code = JO_KDF_SCRYPT_N_TOO_SMALL;
        goto exit;
    }

    if ((n & (n - 1)) != 0) {
        ret_code = JO_KDF_SCRYPT_N_NOT_POW2;
        goto exit;
    }

    if (r < 0) {
        ret_code = JO_KDF_SCRYPT_R_NEGATIVE;
        goto exit;
    }

    if (p < 0) {
        ret_code = JO_KDF_SCRYPT_P_NEGATIVE;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&output, env, _out)) {
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
    UNUSED(jo);

    int ret_code = JO_FAIL;
    const char *digest_str = NULL;
    jsize digest_str_len = 0;

    java_bytearray_ctx password;
    java_bytearray_ctx salt;
    java_bytearray_ctx output;

    init_bytearray_ctx(&password);
    init_bytearray_ctx(&salt);
    init_bytearray_ctx(&output);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&password, env, _password)) {
        ret_code = JO_KDF_PASSWORD_FAILED_ACCESS;
        goto exit;
    }

    if (password.array == NULL) {
        ret_code = JO_KDF_PASSWORD_NULL;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&salt, env, _salt)) {
        ret_code = JO_KDF_SALT_FAILED_ACCESS;
        goto exit;
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


    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&output, env, _out)) {
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

    digest_str_len = (*env)->GetStringUTFLength(env, digest);
    if (digest_str_len <= 0) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    digest_str = (*env)->GetStringUTFChars(env, digest, NULL);
    if (OPS_FAILED_ACCESS_4 digest_str == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

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


/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI
 * Method:    hkdf
 * Signature: ([B[B[BLjava/lang/String;[BII)I
 *
 * HKDF (RFC 5869) extract-then-expand. IKM is mandatory; salt and info
 * are optional and may be passed as null / empty arrays.
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI_hkdf
(JNIEnv *env, jobject jo, jbyteArray _ikm, jbyteArray _salt, jbyteArray _info, jstring digest,
 jbyteArray _out, jint out_offset, jint out_len) {
    UNUSED(jo);

    int ret_code = JO_FAIL;
    const char *digest_str = NULL;
    jsize digest_str_len = 0;

    java_bytearray_ctx ikm;
    java_bytearray_ctx salt;
    java_bytearray_ctx info;
    java_bytearray_ctx output;

    init_bytearray_ctx(&ikm);
    init_bytearray_ctx(&salt);
    init_bytearray_ctx(&info);
    init_bytearray_ctx(&output);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&ikm, env, _ikm)) {
        ret_code = JO_KDF_HKDF_IKM_FAILED_ACCESS;
        goto exit;
    }
    if (ikm.array == NULL) {
        ret_code = JO_KDF_HKDF_IKM_NULL;
        goto exit;
    }

    // Salt is optional per RFC 5869; treat NULL or empty as "absent"
    // (OpenSSL HKDF accepts a zero-length salt and substitutes a
    // hash-length zero block as per the RFC).
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&salt, env, _salt)) {
        ret_code = JO_KDF_SALT_FAILED_ACCESS;
        goto exit;
    }

    // Info is optional per RFC 5869; same handling as salt.
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&info, env, _info)) {
        ret_code = JO_KDF_HKDF_INFO_FAILED_ACCESS;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_4 !load_bytearray_ctx(&output, env, _out)) {
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
    digest_str_len = (*env)->GetStringUTFLength(env, digest);
    if (digest_str_len <= 0) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }
    digest_str = (*env)->GetStringUTFChars(env, digest, NULL);
    if (digest_str == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    uint8_t *out = output.bytearray + out_offset;

    ret_code = hkdf(
        ikm.bytearray, ikm.size,
        salt.bytearray, salt.size,
        info.bytearray, info.size,
        (uint8_t *) digest_str, digest_str_len,
        out, out_len);

exit:
    release_bytearray_ctx(&ikm);
    release_bytearray_ctx(&salt);
    release_bytearray_ctx(&info);
    release_bytearray_ctx(&output);
    if (digest_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, digest, digest_str);
    }
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI
 * Method:    x963kdf
 * Signature: ([B[BLjava/lang/String;[BII)I
 *
 * ANSI X9.63 KDF. Z is mandatory (the raw shared-secret bytes from
 * an upstream key agreement); shared-info is optional and may be null
 * or empty.
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI_x963kdf
(JNIEnv *env, jobject jo, jbyteArray _z, jbyteArray _shared_info, jstring digest,
 jbyteArray _out, jint out_offset, jint out_len) {
    UNUSED(jo);

    int ret_code = JO_FAIL;
    const char *digest_str = NULL;
    jsize digest_str_len = 0;

    java_bytearray_ctx z;
    java_bytearray_ctx shared_info;
    java_bytearray_ctx output;

    init_bytearray_ctx(&z);
    init_bytearray_ctx(&shared_info);
    init_bytearray_ctx(&output);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&z, env, _z)) {
        ret_code = JO_KDF_X963KDF_Z_FAILED_ACCESS;
        goto exit;
    }
    if (z.array == NULL) {
        ret_code = JO_KDF_X963KDF_Z_NULL;
        goto exit;
    }

    // Shared info is optional per X9.63 §3.6 — accept NULL or empty.
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&shared_info, env, _shared_info)) {
        ret_code = JO_KDF_X963KDF_INFO_FAILED_ACCESS;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&output, env, _out)) {
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
    digest_str_len = (*env)->GetStringUTFLength(env, digest);
    if (digest_str_len <= 0) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }
    digest_str = (*env)->GetStringUTFChars(env, digest, NULL);
    if (digest_str == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    uint8_t *out = output.bytearray + out_offset;

    ret_code = x963kdf(
        z.bytearray, z.size,
        shared_info.bytearray, shared_info.size,
        (uint8_t *) digest_str, digest_str_len,
        out, out_len);

exit:
    release_bytearray_ctx(&z);
    release_bytearray_ctx(&shared_info);
    release_bytearray_ctx(&output);
    if (digest_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, digest, digest_str);
    }
    return ret_code;
}
