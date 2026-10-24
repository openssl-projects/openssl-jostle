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

    ctx->kind = RSA_OAEP_CTX_KIND;
    *err = JO_SUCCESS;
    JO_LEDGER_CREATED(JO_LEDGER_RSA_OAEP_CTX);
    return ctx;
}


int32_t rsa_oaep_ctx_check(const rsa_oaep_ctx *ctx) {
    if (ctx == NULL) {
        return JO_CIPHER_CTX_IS_NULL;
    }
    if (ctx->kind != RSA_OAEP_CTX_KIND) {
        return JO_RSA_OAEP_CTX_WRONG_KIND;
    }
    return JO_SUCCESS;
}


void rsa_oaep_ctx_destroy(rsa_oaep_ctx *ctx) {
    // Frees nothing on a wrong kind: freeing another object as an rsa_oaep_ctx corrupts it.
    if (rsa_oaep_ctx_check(ctx) != JO_SUCCESS) {
        return;
    }
    JO_LEDGER_DESTROYED(JO_LEDGER_RSA_OAEP_CTX);
    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
    }
    ctx->kind = RSA_OAEP_CTX_NONE;
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


/* 1 when the library can fetch the digest; the probe's own error is scoped out. */
static int oaep_digest_fetchable(OSSL_LIB_CTX *libctx, const char *digest_name) {
    ERR_set_mark();
    EVP_MD *md = EVP_MD_fetch(libctx, digest_name, NULL);
    ERR_pop_to_mark();
    if (md == NULL) {
        return 0;
    }
    EVP_MD_free(md);
    return 1;
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
    // Both directions need a RAND source: encrypt for the OAEP seed, decrypt for RSA blinding.
    jo_assert(rnd_src != NULL);

    // Drop the previous session before any check, so a refused re-init cannot leave the old key and direction live.
    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
        ctx->pctx = NULL;
    }
    ctx->op_mode = RSA_OAEP_OP_NONE;

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }
    if (op_mode != RSA_OAEP_OP_ENCRYPT && op_mode != RSA_OAEP_OP_DECRYPT) {
        return JO_INVALID_OP_MODE;
    }
    if (label == NULL && label_len != 0) {
        return JO_INPUT_IS_NULL;
    }
    if (label_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    int32_t check = check_is_rsa(key->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    // Default the MGF1 hash to the OAEP hash when unspecified, consistent with the PSS default policy.
    const char *mgf = (mgf1_md_name != NULL) ? mgf1_md_name : oaep_md_name;

    OSSL_LIB_CTX *libctx = get_global_jostle_fips_ossl_lib_ctx();
    if (!oaep_digest_fetchable(libctx, oaep_md_name) || !oaep_digest_fetchable(libctx, mgf)) {
        return JO_RSA_DIGEST_NOT_SUPPORTED;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;

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
    rand_clear_java_srand_call();
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
    if (in_len > (size_t) INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    // Checked by the bridges: RSA blinding and the OAEP seed draw from it in both directions.
    jo_assert(rnd_src != NULL);
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
        rand_clear_java_srand_call();
        // A decrypt failure is JO_INVALID_CIPHER_TEXT, which takes no OPS offset: the test names the flag.
        if (ctx->op_mode == RSA_OAEP_OP_DECRYPT) {
            return JO_INVALID_CIPHER_TEXT;
        }
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(2002);
    }

    if (OPS_INT32_OVERFLOW_1 out_required > (size_t) INT32_MAX) {
        rand_clear_java_srand_call();
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    if (out == NULL) {
        // Caller wants required length only.
        rand_clear_java_srand_call();
        return (int32_t) out_required;
    }

    if (out_len < out_required) {
        rand_clear_java_srand_call();
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t actual = out_len;
    if (ctx->op_mode == RSA_OAEP_OP_ENCRYPT) {
        rc = EVP_PKEY_encrypt(ctx->pctx, out, &actual, in, in_len);
    } else {
        rc = EVP_PKEY_decrypt(ctx->pctx, out, &actual, in, in_len);
    }
    if (OPS_OPENSSL_ERROR_2 rc != 1) {
        rand_clear_java_srand_call();
        // InvalidCipherTextException at the NI, BadPaddingException at the JCE; no OPS offset on it.
        if (ctx->op_mode == RSA_OAEP_OP_DECRYPT) {
            return JO_INVALID_CIPHER_TEXT;
        }
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(2003);
    }

    if (actual > (size_t) INT32_MAX) {
        rand_clear_java_srand_call();
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    rand_clear_java_srand_call();
    return (int32_t) actual;
}
