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

    ret_code = jo_pbkdf2(
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
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI_hkdf
(JNIEnv *env, jobject jo, jbyteArray _ikm, jbyteArray _salt, jbyteArray _info, jstring digest, jbyteArray _out,
 jint out_offset, jint out_len) {
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


    // salt is optional; a null array means "use HashLen zeros" (RFC 5869).
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&salt, env, _salt)) {
        ret_code = JO_KDF_SALT_FAILED_ACCESS;
        goto exit;
    }


    // info is optional; a null array means "no context info".
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
    if (OPS_FAILED_ACCESS_5 digest_str == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    // out_offset is not negative by this point
    uint8_t *out = output.bytearray + out_offset;

    ret_code = jo_hkdf(
        ikm.bytearray, ikm.size,
        salt.bytearray, salt.size,
        info.bytearray, info.size,
        (uint8_t *) digest_str,
        digest_str_len,
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
 * Output-buffer checks shared by the three WI-4 KDF entry points, mirroring
 * kdf_check_output in kdf_ffi.c one for one. The two bridges MUST return
 * identical codes for identical inputs; keeping each side's checks in one
 * function is what makes that reviewable.
 */
static int32_t kdf_check_output_jni(java_bytearray_ctx *output,
                                    jint out_offset, jint out_len)
{
    if (output->array == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    if (out_offset < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }

    if (out_len < 0) {
        return JO_OUTPUT_LEN_IS_NEGATIVE;
    }

    if (out_len == 0) {
        return JO_OUTPUT_LEN_IS_ZERO;
    }

    if (!check_bytearray_in_range(output, out_offset, out_len)) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    return JO_SUCCESS;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI
 * Method:    kbkdf
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[B[B[B[BIII[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI_kbkdf
(JNIEnv *env, jobject jo, jstring mode, jstring mac, jstring digest, jstring cipher,
 jbyteArray _key, jbyteArray _label, jbyteArray _context, jbyteArray _seed,
 jint r, jint use_l, jint use_separator,
 jbyteArray _out, jint out_offset, jint out_len) {
    UNUSED(jo);

    int ret_code = JO_FAIL;
    const char *mode_str = NULL;
    const char *mac_str = NULL;
    const char *digest_str = NULL;
    const char *cipher_str = NULL;
    jsize mode_str_len = 0;
    jsize mac_str_len = 0;
    jsize digest_str_len = 0;
    jsize cipher_str_len = 0;

    java_bytearray_ctx key;
    java_bytearray_ctx label;
    java_bytearray_ctx context;
    java_bytearray_ctx seed;
    java_bytearray_ctx output;

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&label);
    init_bytearray_ctx(&context);
    init_bytearray_ctx(&seed);
    init_bytearray_ctx(&output);

    if (mode == NULL) {
        ret_code = JO_KDF_UNKNOWN_MODE;
        goto exit;
    }

    mode_str_len = (*env)->GetStringUTFLength(env, mode);
    if (mode_str_len <= 0) {
        ret_code = JO_KDF_UNKNOWN_MODE;
        goto exit;
    }

    mode_str = (*env)->GetStringUTFChars(env, mode, NULL);
    if (OPS_FAILED_ACCESS_5 mode_str == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    if (mac == NULL) {
        ret_code = JO_KDF_UNKNOWN_MAC;
        goto exit;
    }

    mac_str_len = (*env)->GetStringUTFLength(env, mac);
    if (mac_str_len <= 0) {
        ret_code = JO_KDF_UNKNOWN_MAC;
        goto exit;
    }

    mac_str = (*env)->GetStringUTFChars(env, mac, NULL);
    if (OPS_FAILED_ACCESS_6 mac_str == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    // digest and cipher are alternatives selected by the MAC, so each is
    // optional on its own - but neither being supplied can never be right.
    if (digest != NULL) {
        digest_str_len = (*env)->GetStringUTFLength(env, digest);
        if (digest_str_len > 0) {
            digest_str = (*env)->GetStringUTFChars(env, digest, NULL);
            if (OPS_FAILED_ACCESS_7 digest_str == NULL) {
                ret_code = JO_UNABLE_TO_ACCESS_NAME;
                goto exit;
            }
        }
    }

    if (cipher != NULL) {
        cipher_str_len = (*env)->GetStringUTFLength(env, cipher);
        if (cipher_str_len > 0) {
            cipher_str = (*env)->GetStringUTFChars(env, cipher, NULL);
            if (OPS_FAILED_ACCESS_8 cipher_str == NULL) {
                ret_code = JO_UNABLE_TO_ACCESS_NAME;
                goto exit;
            }
        }
    }

    if (digest_str == NULL && cipher_str == NULL) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&key, env, _key)) {
        ret_code = JO_KDF_SECRET_FAILED_ACCESS;
        goto exit;
    }

    if (key.array == NULL) {
        ret_code = JO_KDF_SECRET_NULL;
        goto exit;
    }

    // label is optional; SP 800-108 permits an empty Label.
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&label, env, _label)) {
        ret_code = JO_KDF_SALT_FAILED_ACCESS;
        goto exit;
    }

    // context is optional; SP 800-108 permits an empty Context.
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&context, env, _context)) {
        ret_code = JO_KDF_INFO_FAILED_ACCESS;
        goto exit;
    }

    // seed is the feedback IV, K(0); optional and ignored in counter mode.
    if (OPS_FAILED_ACCESS_9 !load_bytearray_ctx(&seed, env, _seed)) {
        ret_code = JO_KDF_SEED_FAILED_ACCESS;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_4 !load_bytearray_ctx(&output, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = kdf_check_output_jni(&output, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }

    ret_code = jo_kbkdf(
        (uint8_t *) mode_str, mode_str_len,
        (uint8_t *) mac_str, mac_str_len,
        (uint8_t *) digest_str, digest_str_len,
        (uint8_t *) cipher_str, cipher_str_len,
        key.bytearray, key.size,
        label.bytearray, label.size,
        context.bytearray, context.size,
        seed.bytearray, seed.size,
        r, use_l, use_separator,
        output.bytearray + out_offset, out_len);

exit:
    release_bytearray_ctx(&key);
    release_bytearray_ctx(&label);
    release_bytearray_ctx(&context);
    release_bytearray_ctx(&seed);
    release_bytearray_ctx(&output);

    if (mode_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, mode, mode_str);
    }
    if (mac_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, mac, mac_str);
    }
    if (digest_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, digest, digest_str);
    }
    if (cipher_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, cipher, cipher_str);
    }

    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI
 * Method:    sskdf
 * Signature: (Ljava/lang/String;[B[B[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI_sskdf
(JNIEnv *env, jobject jo, jstring digest, jbyteArray _secret, jbyteArray _info,
 jbyteArray _out, jint out_offset, jint out_len) {
    UNUSED(jo);

    int ret_code = JO_FAIL;
    const char *digest_str = NULL;
    jsize digest_str_len = 0;

    java_bytearray_ctx secret;
    java_bytearray_ctx info;
    java_bytearray_ctx output;

    init_bytearray_ctx(&secret);
    init_bytearray_ctx(&info);
    init_bytearray_ctx(&output);

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
    if (OPS_FAILED_ACCESS_1 digest_str == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&secret, env, _secret)) {
        ret_code = JO_KDF_SECRET_FAILED_ACCESS;
        goto exit;
    }

    if (secret.array == NULL) {
        ret_code = JO_KDF_SECRET_NULL;
        goto exit;
    }

    // info (SP 800-56C FixedInfo) is optional; absent == empty (measured).
    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&info, env, _info)) {
        ret_code = JO_KDF_INFO_FAILED_ACCESS;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_4 !load_bytearray_ctx(&output, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = kdf_check_output_jni(&output, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }

    ret_code = jo_sskdf(
        (uint8_t *) digest_str, digest_str_len,
        secret.bytearray, secret.size,
        info.bytearray, info.size,
        output.bytearray + out_offset, out_len);

exit:
    release_bytearray_ctx(&secret);
    release_bytearray_ctx(&info);
    release_bytearray_ctx(&output);

    if (digest_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, digest, digest_str);
    }

    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI
 * Method:    sshkdf
 * Signature: (Ljava/lang/String;[B[B[BLjava/lang/String;[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_KdfNIJNI_sshkdf
(JNIEnv *env, jobject jo, jstring digest, jbyteArray _key, jbyteArray _xcghash,
 jbyteArray _session_id, jstring type, jbyteArray _out, jint out_offset, jint out_len) {
    UNUSED(jo);

    int ret_code = JO_FAIL;
    const char *digest_str = NULL;
    const char *type_str = NULL;
    jsize digest_str_len = 0;
    jsize type_str_len = 0;

    java_bytearray_ctx key;
    java_bytearray_ctx xcghash;
    java_bytearray_ctx session_id;
    java_bytearray_ctx output;

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&xcghash);
    init_bytearray_ctx(&session_id);
    init_bytearray_ctx(&output);

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
    if (OPS_FAILED_ACCESS_5 digest_str == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    if (type == NULL) {
        ret_code = JO_KDF_SSHKDF_TYPE_INVALID;
        goto exit;
    }

    type_str_len = (*env)->GetStringUTFLength(env, type);
    if (type_str_len <= 0) {
        ret_code = JO_KDF_SSHKDF_TYPE_INVALID;
        goto exit;
    }

    type_str = (*env)->GetStringUTFChars(env, type, NULL);
    if (OPS_FAILED_ACCESS_6 type_str == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&key, env, _key)) {
        ret_code = JO_KDF_SECRET_FAILED_ACCESS;
        goto exit;
    }

    if (key.array == NULL) {
        ret_code = JO_KDF_SECRET_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&xcghash, env, _xcghash)) {
        ret_code = JO_KDF_SSHKDF_XCGHASH_FAILED_ACCESS;
        goto exit;
    }

    if (xcghash.array == NULL) {
        ret_code = JO_KDF_SSHKDF_XCGHASH_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&session_id, env, _session_id)) {
        ret_code = JO_KDF_SSHKDF_SESSION_ID_FAILED_ACCESS;
        goto exit;
    }

    if (session_id.array == NULL) {
        ret_code = JO_KDF_SSHKDF_SESSION_ID_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_4 !load_bytearray_ctx(&output, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = kdf_check_output_jni(&output, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }

    ret_code = jo_sshkdf(
        (uint8_t *) digest_str, digest_str_len,
        key.bytearray, key.size,
        xcghash.bytearray, xcghash.size,
        session_id.bytearray, session_id.size,
        (uint8_t *) type_str, type_str_len,
        output.bytearray + out_offset, out_len);

exit:
    release_bytearray_ctx(&key);
    release_bytearray_ctx(&xcghash);
    release_bytearray_ctx(&session_id);
    release_bytearray_ctx(&output);

    if (digest_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, digest, digest_str);
    }
    if (type_str != NULL) {
        (*env)->ReleaseStringUTFChars(env, type, type_str);
    }

    return ret_code;
}
