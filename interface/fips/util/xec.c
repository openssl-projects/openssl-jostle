//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "xec.h"


#include <openssl/evp.h>
#include <openssl/err.h>

#include "bc_err_codes.h"
#include "key_spec.h"
#include "ops.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"


/*
 * X25519 / X448 keypair generation. Mirrors ec_generate_key, but for these
 * Montgomery key types the EVP_PKEY type name fully determines the key, so
 * there is no OSSL_PKEY_PARAM_GROUP_NAME to set.
 *
 * OPS offsets use the 3300 block (ec.c uses 3000-3199); each fallible
 * OpenSSL call has a unique offset within the file.
 */
int32_t xec_generate_key(key_spec *spec, const char *name, void *rnd_src) {
    // Bridge-validated invariants (the JNI / FFI bridge null-checks these
    // and surfaces JO_NAME_IS_NULL / JO_RAND_NO_RAND_UP_CALL itself).
    jo_assert(spec != NULL);
    jo_assert(name != NULL);
    jo_assert(rnd_src != NULL);

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                     name, NULL);
    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        // Unknown type name lands here too (EVP_PKEY_CTX_new_from_name
        // returns NULL); the Java SPI only ever passes "X25519" / "X448".
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3300);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(3301);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(3302);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(3303);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}
