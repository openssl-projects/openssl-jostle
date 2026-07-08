//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "rsa_pkcs1.h"

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"


rsa_pkcs1_ctx *rsa_pkcs1_ctx_create(int32_t *err) {
    jo_assert(err != NULL);

    rsa_pkcs1_ctx *ctx = (rsa_pkcs1_ctx *) OPENSSL_zalloc(sizeof(rsa_pkcs1_ctx));
    jo_assert(ctx != NULL);

    *err = JO_SUCCESS;
    return ctx;
}


void rsa_pkcs1_ctx_destroy(rsa_pkcs1_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
    }
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}


/*
 * Verify the supplied EVP_PKEY is RSA. Encrypt uses the public part,
 * decrypt uses the private part; OpenSSL chooses based on init.
 */
static int32_t check_is_rsa(const EVP_PKEY *pkey) {
    const char *algo = EVP_PKEY_get0_type_name(pkey);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }
    if (strcmp(algo, "RSA") != 0) {
        return JO_INCORRECT_KEY_TYPE;
    }
    return JO_SUCCESS;
}


int32_t rsa_pkcs1_init(rsa_pkcs1_ctx *ctx, const key_spec *key,
                       int32_t op_mode,
                       void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(key != NULL);

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }
    if (op_mode != RSA_PKCS1_OP_ENCRYPT && op_mode != RSA_PKCS1_OP_DECRYPT) {
        return JO_INVALID_OP_MODE;
    }
    // Both directions need a RAND source: encrypt for the PS bytes,
    // decrypt for RSA blinding (timing-channel countermeasure).
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    int32_t check = check_is_rsa(key->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;

    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
        ctx->pctx = NULL;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key->key, NULL);
    if (OPS_OPENSSL_ERROR_1 pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(2100);
        goto exit;
    }

    int init_rc;
    if (op_mode == RSA_PKCS1_OP_ENCRYPT) {
        init_rc = EVP_PKEY_encrypt_init(pctx);
    } else {
        init_rc = EVP_PKEY_decrypt_init(pctx);
    }
    if (OPS_OPENSSL_ERROR_2 init_rc != 1) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(2101);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(2110);
        goto exit;
    }

    // ============================================================
    // BLEICHENBACHER MITIGATION — explicit implicit-rejection = 1
    // ============================================================
    // OpenSSL 3.x's RSA provider enables implicit rejection by default
    // (provider-asym_cipher(7) documents
    // OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION as "Set by default in
    // OpenSSL providers"). With it on, EVP_PKEY_decrypt on malformed
    // PKCS#1 v1.5 padding returns a deterministic synthetic plaintext
    // instead of signalling failure — directly mitigating
    // Bleichenbacher-style padding oracle attacks.
    //
    // We set it EXPLICITLY to 1 here even though the default agrees,
    // so the security property is unambiguous in our source rather
    // than implicit in OpenSSL's defaults. If a future OpenSSL release
    // ever changed the default, or this code linked against a custom
    // provider with different defaults, the protection would still be
    // in place.
    //
    // DO NOT change the value to 0 or remove this block. Doing so
    // re-opens the Bleichenbacher oracle. The Java test
    // RSAPKCS1CipherTest.testPKCS1_ImplicitRejection_HardGuard
    // asserts the runtime behaviour and will fail loudly if the
    // oracle is reopened.
    // ============================================================
    {
        unsigned int implicit_rejection = 1;
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_uint(
                OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, &implicit_rejection);
        params[1] = OSSL_PARAM_construct_end();
        if (OPS_OPENSSL_ERROR_4 1 != EVP_PKEY_CTX_set_params(pctx, params)) {
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(2111);
            goto exit;
        }
    }

    ctx->pctx = pctx;
    ctx->op_mode = op_mode;
    pctx = NULL; // ownership transferred
    ret_code = JO_SUCCESS;

exit:
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    return ret_code;
}


int32_t rsa_pkcs1_dofinal(rsa_pkcs1_ctx *ctx,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_len,
                          void *rnd_src) {
    jo_assert(ctx != NULL);

    if (ctx->pctx == NULL) {
        return JO_NOT_INITIALIZED;
    }
    if (in == NULL && in_len != 0) {
        return JO_INPUT_IS_NULL;
    }
    if (in_len > (size_t) INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    size_t out_required = 0;

    int rc;
    if (ctx->op_mode == RSA_PKCS1_OP_ENCRYPT) {
        rc = EVP_PKEY_encrypt(ctx->pctx, NULL, &out_required, in, in_len);
    } else {
        rc = EVP_PKEY_decrypt(ctx->pctx, NULL, &out_required, in, in_len);
    }
    if (OPS_OPENSSL_ERROR_1 rc != 1) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(2102);
    }

    if (OPS_INT32_OVERFLOW_1 out_required > (size_t) INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    if (out == NULL) {
        return (int32_t) out_required;
    }

    if (out_len < out_required) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t actual = out_len;
    if (ctx->op_mode == RSA_PKCS1_OP_ENCRYPT) {
        rc = EVP_PKEY_encrypt(ctx->pctx, out, &actual, in, in_len);
    } else {
        rc = EVP_PKEY_decrypt(ctx->pctx, out, &actual, in, in_len);
    }
    if (OPS_OPENSSL_ERROR_2 rc != 1) {
        // Decrypt failure surfaces here. With OpenSSL 3.x's default
        // implicit-rejection enabled, this branch should NOT fire on
        // mere padding failures — OpenSSL emits a synthetic plaintext
        // and returns success. Genuine errors (e.g. ciphertext > n)
        // still surface here.
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(2103);
    }

    if (actual > (size_t) INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    return (int32_t) actual;
}
