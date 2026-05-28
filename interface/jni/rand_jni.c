//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "bytearrays.h"
#include "org_openssl_jostle_jcajce_provider_rand_RandServiceJNI.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/ops.h"
#include "../util/rand.h"

/*
 * Class:     org_openssl_jostle_jcajce_provider_rand_RandServiceJNI
 * Method:    ni_randomBytes
 * Signature: ([BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1randomBytes
(JNIEnv *env, jobject jo, jbyteArray _output, jint output_len, jint strength) {
    UNUSED(jo);

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx output;
    init_bytearray_ctx(&output);

    if (_output == NULL) {
        ret_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (output_len < 0) {
        ret_code = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (strength < 0) {
        ret_code = JO_RAND_INSUFFICIENT_STRENGTH;
        goto exit;
    }

    if (output_len == 0) {
        ret_code = JO_SUCCESS;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    if ((size_t) output_len > output.size) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    ret_code = rand_random_bytes(output.bytearray, output_len, strength);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}
