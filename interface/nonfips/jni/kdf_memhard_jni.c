//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// JNI bridge for the memory-hard password KDFs (scrypt, Argon2).
//
// Nonfips tree only, with no fips twin and no _fips_jni rename wrapper: the
// FIPS interface library deliberately exports no memory-hard KDF entry points.
// See util/kdf_memhard.c for the rationale.
//

#include <stdint.h>
#include <string.h>

#include "bytearrays.h"
#include "secret_bytearrays.h"
#include "org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI.h"
#include "types.h"
#include "../util/kdf_memhard.h"
#include "../util/ops.h"


/* Output checks in the order kdf_check_output_jni (kdf_jni.c) uses, so the KDF family answers alike. */
static int32_t memhard_check_output_jni(java_secret_bytearray_ctx *output, jint out_offset, jint out_len)
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

    if (!check_secret_in_range(output, (size_t) out_offset, (size_t) out_len)) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    return JO_SUCCESS;
}

/* The caller's output array is written only when the derive succeeded. */
static void memhard_release_output_jni(java_secret_bytearray_ctx *output, int32_t ret_code)
{
    if (ret_code == JO_SUCCESS) {
        release_secret_bytearray_ctx(output);
    } else {
        discard_secret_bytearray_ctx(output);
    }
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI
 * Method:    scrypt
 * Signature: ([B[BIII[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI_scrypt
(JNIEnv *env, jobject jo, jbyteArray _password, jbyteArray _salt, jint n, jint r, jint p, jbyteArray _out,
 jint out_offset, jint out_len) {
    UNUSED(jo);

    int ret_code = JO_FAIL;

    java_secret_bytearray_ctx password;
    java_bytearray_ctx salt;
    java_secret_bytearray_ctx output;

    init_secret_bytearray_ctx(&password);
    init_bytearray_ctx(&salt);
    init_secret_bytearray_ctx(&output);

    if (OPS_FAILED_ACCESS_1 !load_secret_input_ctx(&password, env, _password)) {
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

    if (r < 1) {
        ret_code = JO_KDF_SCRYPT_R_TOO_SMALL;
        goto exit;
    }

    if (p < 1) {
        ret_code = JO_KDF_SCRYPT_P_TOO_SMALL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_3 !load_secret_output_ctx(&output, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = memhard_check_output_jni(&output, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }

    ret_code = jo_scrypt(
        password.bytearray, password.size,
        salt.bytearray, salt.size,
        (uint64_t) n,
        (uint32_t) r,
        (uint32_t) p,
        output.bytearray + out_offset, (size_t) out_len);

exit:
    release_bytearray_ctx(&salt);
    release_secret_bytearray_ctx(&password);
    memhard_release_output_jni(&output, ret_code);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI
 * Method:    argon2
 * Signature: ([B[BIIIII[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI_argon2
(JNIEnv *env, jobject jo, jbyteArray _password, jbyteArray _salt, jint type, jint version, jint iterations,
 jint memory_kib, jint lanes, jbyteArray _out, jint out_offset, jint out_len) {
    UNUSED(jo);

    int ret_code = JO_FAIL;

    java_secret_bytearray_ctx password;
    java_bytearray_ctx salt;
    java_secret_bytearray_ctx output;

    init_secret_bytearray_ctx(&password);
    init_bytearray_ctx(&salt);
    init_secret_bytearray_ctx(&output);

    if (OPS_FAILED_ACCESS_1 !load_secret_input_ctx(&password, env, _password)) {
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

    if (salt.size < JO_ARGON2_MIN_SALT_LEN) {
        ret_code = JO_KDF_ARGON2_SALT_TOO_SHORT;
        goto exit;
    }

    if (type < 0 || type > 2) {
        ret_code = JO_KDF_ARGON2_TYPE_INVALID;
        goto exit;
    }

    if (version != 0x10 && version != 0x13) {
        ret_code = JO_KDF_ARGON2_VERSION_INVALID;
        goto exit;
    }

    if (iterations < 1) {
        ret_code = JO_KDF_ARGON2_ITER_TOO_SMALL;
        goto exit;
    }

    if (lanes < 1) {
        ret_code = JO_KDF_ARGON2_LANES_TOO_SMALL;
        goto exit;
    }

    // RFC 9106 floor: 8 * lanes KiB, compared in 64 bits so the multiply cannot overflow.
    if (memory_kib < 1 || (int64_t) memory_kib < (int64_t) 8 * (int64_t) lanes) {
        ret_code = JO_KDF_ARGON2_MEMORY_TOO_SMALL;
        goto exit;
    }

    if (memory_kib > JO_ARGON2_MAX_MEMORY_KIB) {
        ret_code = JO_KDF_ARGON2_MEMORY_TOO_LARGE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_3 !load_secret_output_ctx(&output, env, _out)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = memhard_check_output_jni(&output, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }

    if (out_len < JO_ARGON2_MIN_OUT_LEN) {
        ret_code = JO_KDF_ARGON2_OUTPUT_TOO_SHORT;
        goto exit;
    }

    ret_code = jo_argon2(
        type,
        (uint32_t) version,
        password.bytearray, password.size,
        salt.bytearray, salt.size,
        (uint32_t) iterations,
        (uint32_t) memory_kib,
        (uint32_t) lanes,
        output.bytearray + out_offset, (size_t) out_len);

exit:
    release_bytearray_ctx(&salt);
    release_secret_bytearray_ctx(&password);
    memhard_release_output_jni(&output, ret_code);
    return ret_code;
}
