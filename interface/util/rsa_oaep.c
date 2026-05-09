//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "rsa_oaep.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"


/*
 * Lifecycle. The EVP_PKEY_CTX is owned by the rsa_oaep_ctx; init may
 * replace it (re-init across operations is permitted) and destroy
 * frees it.
 */

rsa_oaep_ctx *rsa_oaep_ctx_create(int32_t *err) {
    jo_assert(err != NULL);

    rsa_oaep_ctx *ctx = (rsa_oaep_ctx *) OPENSSL_zalloc(sizeof(rsa_oaep_ctx));
    jo_assert(ctx != NULL);

    *err = JO_SUCCESS;
    return ctx;
}


void rsa_oaep_ctx_destroy(rsa_oaep_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
    }
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}


/*
 * Verify the supplied EVP_PKEY is RSA. Public/private both accepted —
 * encrypt uses the public part, decrypt uses the private part, and
 * OpenSSL chooses internally based on which init was called.
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


int32_t rsa_oaep_init(rsa_oaep_ctx *ctx, const key_spec *key,
                      int32_t op_mode,
                      const char *oaep_md_name,
                      const char *mgf1_md_name,
                      const uint8_t *label, size_t label_len,
                      void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(key != NULL);
    jo_assert(oaep_md_name != NULL);

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }
    if (op_mode != RSA_OAEP_OP_ENCRYPT && op_mode != RSA_OAEP_OP_DECRYPT) {
        return JO_INVALID_OP_MODE;
    }
    // Both directions need a RAND source: encrypt for the OAEP seed,
    // decrypt for RSA blinding (timing-channel countermeasure).
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    if (label == NULL && label_len != 0) {
        return JO_INPUT_IS_NULL;
    }
    if (label_len > INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    int32_t check = check_is_rsa(key->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;

    // Re-init: free any previously-configured EVP_PKEY_CTX.
    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
        ctx->pctx = NULL;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key->key, NULL);
    if (OPS_OPENSSL_ERROR_1 pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(2000);
        goto exit;
    }

    int init_rc;
    if (op_mode == RSA_OAEP_OP_ENCRYPT) {
        init_rc = EVP_PKEY_encrypt_init(pctx);
    } else {
        init_rc = EVP_PKEY_decrypt_init(pctx);
    }
    if (OPS_OPENSSL_ERROR_2 init_rc != 1) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(2001);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(2010);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 1 != EVP_PKEY_CTX_set_rsa_oaep_md_name(pctx, oaep_md_name, NULL)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(2011);
        goto exit;
    }

    // Default the MGF1 hash to the OAEP hash when unspecified — modern
    // best practice and consistent with the PSS default policy.
    const char *mgf = (mgf1_md_name != NULL) ? mgf1_md_name : oaep_md_name;
    if (OPS_OPENSSL_ERROR_5 1 != EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, mgf, NULL)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(2012);
        goto exit;
    }

    if (label != NULL && label_len > 0) {
        // EVP_PKEY_CTX_set0_rsa_oaep_label TAKES OWNERSHIP of the
        // buffer (frees it via OPENSSL_free when the ctx is freed),
        // so we duplicate the caller's bytes into an OPENSSL_malloc'd
        // buffer first.
        uint8_t *label_copy = OPENSSL_malloc(label_len);
        if (label_copy == NULL) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;
        }
        memcpy(label_copy, label, label_len);
        if (OPS_OPENSSL_ERROR_6 1 != EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, label_copy, (int) label_len)) {
            OPENSSL_free(label_copy);
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(2013);
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


int32_t rsa_oaep_dofinal(rsa_oaep_ctx *ctx,
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

    // RSA blinding (used in private-key ops for timing-channel
    // resistance) consumes entropy on the path through OpenSSL's RAND;
    // require a non-null source for both encrypt and decrypt.
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    size_t out_required = 0;

    int rc;
    if (ctx->op_mode == RSA_OAEP_OP_ENCRYPT) {
        rc = EVP_PKEY_encrypt(ctx->pctx, NULL, &out_required, in, in_len);
    } else {
        rc = EVP_PKEY_decrypt(ctx->pctx, NULL, &out_required, in, in_len);
    }
    if (OPS_OPENSSL_ERROR_1 rc != 1) {
        // The bridge surfaces InvalidCipherTextException to
        // NI-level callers and BadPaddingException to JCE callers.
        int32_t base = (ctx->op_mode == RSA_OAEP_OP_DECRYPT)
                ? JO_INVALID_CIPHER_TEXT : JO_OPENSSL_ERROR;
        return base OPS_OFFSET_OPENSSL_ERROR_1(2002);
    }

    if (OPS_INT32_OVERFLOW_1 out_required > (size_t) INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    if (out == NULL) {
        // Caller wants required length only.
        return (int32_t) out_required;
    }

    if (out_len < out_required) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t actual = out_len;
    if (ctx->op_mode == RSA_OAEP_OP_ENCRYPT) {
        rc = EVP_PKEY_encrypt(ctx->pctx, out, &actual, in, in_len);
    } else {
        rc = EVP_PKEY_decrypt(ctx->pctx, out, &actual, in, in_len);
    }
    if (OPS_OPENSSL_ERROR_2 rc != 1) {
        // InvalidCipherTextException; the JCE SPI translates that to
        // BadPaddingException at engineDoFinal. Encrypt failures stay
        // as JO_OPENSSL_ERROR (translated to IllegalBlockSizeException
        // by the SPI).
        int32_t base = (ctx->op_mode == RSA_OAEP_OP_DECRYPT)
                ? JO_INVALID_CIPHER_TEXT : JO_OPENSSL_ERROR;
        return base OPS_OFFSET_OPENSSL_ERROR_2(2003);
    }

    if (actual > (size_t) INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    return (int32_t) actual;
}
