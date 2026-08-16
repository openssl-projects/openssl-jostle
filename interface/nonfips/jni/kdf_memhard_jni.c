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
#include "org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI.h"
#include "types.h"
#include "../util/kdf_memhard.h"
#include "../util/ops.h"

/*
 * Class:     org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI
 * Method:    scrypt
 * Signature: ([B[BIII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI_scrypt
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

    if (r < 1) {
        ret_code = JO_KDF_SCRYPT_R_TOO_SMALL;
        goto exit;
    }

    if (p < 1) {
        ret_code = JO_KDF_SCRYPT_P_TOO_SMALL;
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

    ret_code = jo_scrypt(
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
 * Class:     org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI
 * Method:    argon2
 * Signature: ([B[BIIIII[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_kdf_MemoryHardKdfNIJNI_argon2
(JNIEnv *env, jobject jo, jbyteArray _password, jbyteArray _salt, jint type, jint version, jint iterations,
 jint memory_kib, jint lanes, jbyteArray _out, jint out_offset, jint out_len) {
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

    //
    // RFC 9106 floor: 8 * lanes KiB. Compared in 64-bit so the multiply cannot
    // overflow for lanes up to INT32_MAX.
    //
    if (memory_kib < 1 || (int64_t) memory_kib < (int64_t) 8 * (int64_t) lanes) {
        ret_code = JO_KDF_ARGON2_MEMORY_TOO_SMALL;
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

    ret_code = jo_argon2(
        type,
        (uint32_t) version,
        password.bytearray, password.size,
        salt.bytearray, salt.size,
        (uint32_t) iterations,
        (uint32_t) memory_kib,
        (uint32_t) lanes,
        out, out_len);

exit:
    release_bytearray_ctx(&salt);
    release_bytearray_ctx(&password);
    release_bytearray_ctx(&output);
    return ret_code;
}
