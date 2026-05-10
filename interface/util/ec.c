//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "ec.h"

#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "key_spec.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"


// =============================================================
// Helpers
// =============================================================

/*
 * Verify the supplied EVP_PKEY is EC. Returns JO_SUCCESS on match,
 * JO_INCORRECT_KEY_TYPE otherwise. Mirrors check_is_rsa in rsa.c.
 */
static int32_t check_is_ec(const EVP_PKEY *pkey) {
    const char *algo = EVP_PKEY_get0_type_name(pkey);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }
    if (strcmp(algo, "EC") != 0) {
        return JO_INCORRECT_KEY_TYPE;
    }
    return JO_SUCCESS;
}


// =============================================================
// Curve introspection
// =============================================================

int32_t ec_curve_supported(const char *curve_name) {
    if (curve_name == NULL) {
        return 0;
    }

    // OpenSSL's EC keymgmt only validates the curve name lazily —
    // EVP_PKEY_CTX_set_params(GROUP_NAME) stores the string and
    // returns success regardless of whether the name resolves.
    // Validation happens at paramgen/keygen. Drive a full
    // EVP_PKEY_paramgen so an unrecognised name fails here rather
    // than slipping through to a pretend-supported state.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(
            get_global_jostle_ossl_lib_ctx(), "EC", NULL);
    if (ctx == NULL) {
        ERR_clear_error();
        return 0;
    }

    int32_t supported = 0;
    if (1 == EVP_PKEY_paramgen_init(ctx)) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, (char *) curve_name, 0);
        params[1] = OSSL_PARAM_construct_end();
        if (1 == EVP_PKEY_CTX_set_params(ctx, params)) {
            EVP_PKEY *pkey = NULL;
            if (1 == EVP_PKEY_paramgen(ctx, &pkey) && pkey != NULL) {
                supported = 1;
            }
            EVP_PKEY_free(pkey);
        }
    }

    EVP_PKEY_CTX_free(ctx);
    // Suppress any "no such group" entry the failed probe queued — the
    // caller is checking a boolean, not asking for an error report.
    ERR_clear_error();
    return supported;
}


// =============================================================
// Key generation
// =============================================================

int32_t ec_generate_key(key_spec *spec, const char *curve_name,
                        void *rnd_src) {
    jo_assert(spec != NULL);
    jo_assert(curve_name != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                     "EC", NULL);
    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3000);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(3001);
        goto exit;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, (char *) curve_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_CTX_set_params(ctx, params)) {
        // Most likely cause: unknown curve name. Java SPI should have
        // pre-validated via ec_curve_supported() — surface as a generic
        // OpenSSL error here so callers that bypass the SPI also fail
        // cleanly.
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(3002);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 1 != EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(3003);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_5 spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(3004);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}


// =============================================================
// Component getter
// =============================================================

/*
 * Fetch the curve name (UTF-8). Two-call protocol — see ec_get_component
 * docstring. Does NOT write a trailing NUL into the caller's buffer.
 */
static int32_t get_curve_name_component(const key_spec *spec,
                                        uint8_t *out, size_t out_len) {
    size_t name_len = 0;
    if (1 != EVP_PKEY_get_utf8_string_param(spec->key,
                                            OSSL_PKEY_PARAM_GROUP_NAME,
                                            NULL, 0, &name_len)) {
        return JO_OPENSSL_ERROR;
    }

    if (out == NULL || out_len == 0) {
        if (name_len > (size_t) INT32_MAX) {
            return JO_OUTPUT_TOO_LONG_INT32;
        }
        return (int32_t) name_len;
    }

    if (out_len < name_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    // OpenSSL's UTF-8 fetch writes a NUL terminator and requires
    // `max_buf_sz >= name_len + 1`. Use a temp buffer so the caller's
    // `out` doesn't need to leave room for a terminator they don't want.
    char *tmp = OPENSSL_malloc(name_len + 1);
    if (tmp == NULL) {
        return JO_OPENSSL_ERROR;
    }
    int32_t ret_code;
    if (1 != EVP_PKEY_get_utf8_string_param(spec->key,
                                            OSSL_PKEY_PARAM_GROUP_NAME,
                                            tmp, name_len + 1, NULL)) {
        ret_code = JO_OPENSSL_ERROR;
    } else {
        memcpy(out, tmp, name_len);
        ret_code = (int32_t) name_len;
    }
    OPENSSL_clear_free(tmp, name_len + 1);
    return ret_code;
}


/*
 * Fetch a BIGNUM component identified by an OSSL_PKEY_PARAM_* name and
 * return it as big-endian unsigned magnitude. Used for X / Y / private
 * scalar.
 */
static int32_t get_bn_component(const key_spec *spec, const char *param_name,
                                uint8_t *out, size_t out_len) {
    BIGNUM *bn = NULL;
    int32_t ret_code = JO_FAIL;

    if (1 != EVP_PKEY_get_bn_param(spec->key, param_name, &bn)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    int byte_len = BN_num_bytes(bn);
    if (byte_len < 0) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (out == NULL || out_len == 0) {
        ret_code = (int32_t) byte_len;
        goto exit;
    }

    if (out_len < (size_t) byte_len) {
        ret_code = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }

    int written = BN_bn2bin(bn, out);
    if (written < 0) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = (int32_t) written;

exit:
    BN_clear_free(bn);
    return ret_code;
}


int32_t ec_get_component(const key_spec *spec, int32_t component,
                         uint8_t *out, size_t out_len) {
    jo_assert(spec != NULL);

    if (spec->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_ec(spec->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    ERR_clear_error();

    switch (component) {
        case EC_COMP_CURVE_NAME:
            return get_curve_name_component(spec, out, out_len);
        case EC_COMP_PUBLIC_X:
            return get_bn_component(spec, OSSL_PKEY_PARAM_EC_PUB_X,
                                    out, out_len);
        case EC_COMP_PUBLIC_Y:
            return get_bn_component(spec, OSSL_PKEY_PARAM_EC_PUB_Y,
                                    out, out_len);
        case EC_COMP_PRIVATE_VALUE:
            return get_bn_component(spec, OSSL_PKEY_PARAM_PRIV_KEY,
                                    out, out_len);
        default:
            return JO_FAIL;
    }
}


// =============================================================
// Construct EVP_PKEY from raw components
// =============================================================

#include <openssl/param_build.h>

int32_t ec_make_private_from_components(key_spec *spec,
                                        const char *curve_name,
                                        const uint8_t *scalar_be,
                                        size_t scalar_len,
                                        void *rnd_src) {
    jo_assert(spec != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    if (curve_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    if (scalar_be == NULL) {
        return JO_INPUT_IS_NULL;
    }
    if (scalar_len == 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }

    // OpenSSL re-derives the public point from the scalar via
    // point-blinded multiplication on first use of the resulting
    // EVP_PKEY. Bind the per-thread Java RAND upcall before any of
    // that runs; the same pattern as ec_ctx_init_sign and
    // ec_kex_init.
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *scalar_bn = NULL;
    EVP_PKEY *pkey = NULL;

    scalar_bn = BN_bin2bn(scalar_be, (int) scalar_len, NULL);
    if (OPS_OPENSSL_ERROR_6 scalar_bn == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(3010);
        goto exit;
    }

    bld = OSSL_PARAM_BLD_new();
    if (OPS_OPENSSL_ERROR_7 bld == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(3011);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_8 1 != OSSL_PARAM_BLD_push_utf8_string(
            bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(3012);
        goto exit;
    }
    if (OPS_OPENSSL_ERROR_9 1 != OSSL_PARAM_BLD_push_BN(
            bld, OSSL_PKEY_PARAM_PRIV_KEY, scalar_bn)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(3013);
        goto exit;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (OPS_OPENSSL_ERROR_10 params == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(3014);
        goto exit;
    }

    pctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                      "EC", NULL);
    if (OPS_OPENSSL_ERROR_11 pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_11(3015);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_12 1 != EVP_PKEY_fromdata_init(pctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_12(3016);
        goto exit;
    }

    // EVP_PKEY_KEYPAIR asks the keymgmt to materialise BOTH halves
    // (private + public). With only OSSL_PKEY_PARAM_PRIV_KEY supplied,
    // OpenSSL derives the public point via Q = d * G — the source of
    // the entropy upcall above.
    // Reuses OPS_OPENSSL_ERROR_1 (see also ec_generate_key); each test
    // exercises only one entry point per flag.
    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_fromdata(pctx, &pkey,
                                                    EVP_PKEY_KEYPAIR, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3017);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 pkey == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(3018);
        goto exit;
    }

    // Replace any prior key on the spec, then transfer ownership.
    if (spec->key != NULL) {
        EVP_PKEY_free(spec->key);
    }
    spec->key = pkey;
    pkey = NULL;
    ret_code = JO_SUCCESS;

exit:
    BN_clear_free(scalar_bn);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return ret_code;
}


// =============================================================
// Sign / verify session
// =============================================================

ec_ctx *ec_ctx_create(int32_t *err) {
    jo_assert(err != NULL);

    ec_ctx *ctx = (ec_ctx *) OPENSSL_zalloc(sizeof(ec_ctx));
    jo_assert(ctx != NULL);

    *err = JO_SUCCESS;
    return ctx;
}


void ec_ctx_destroy(ec_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->digest_ctx != NULL) {
        EVP_MD_CTX_free(ctx->digest_ctx);
    }
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}


int32_t ec_ctx_init_sign(ec_ctx *ctx, const key_spec *key,
                         const char *digest_name,
                         void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(key != NULL);
    jo_assert(digest_name != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_ec(key->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_MD_CTX *md_ctx = NULL;       // local; transferred to ctx on success
    EVP_PKEY_CTX *pctx = NULL;       // not owned — owned by md_ctx

    // Free any prior session state up-front (rsa_ctx_init_sign rationale).
    if (ctx->digest_ctx != NULL) {
        EVP_MD_CTX_free(ctx->digest_ctx);
        ctx->digest_ctx = NULL;
    }
    ctx->opp = 0;

    // Reuses OPS_OPENSSL_ERROR_3 / _4. Each test drives only one path.
    md_ctx = EVP_MD_CTX_new();
    if (OPS_OPENSSL_ERROR_3 md_ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(3020);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 1 != EVP_DigestSignInit_ex(
            md_ctx, &pctx, digest_name, libctx, NULL, key->key, NULL)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(3021);
        goto exit;
    }

    // ECDSA has no padding modes — nothing else to configure.

    ctx->digest_ctx = md_ctx;
    ctx->opp = EC_OP_SIGN;
    md_ctx = NULL; // ownership transferred
    ret_code = JO_SUCCESS;

exit:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    return ret_code;
}


int32_t ec_ctx_init_verify(ec_ctx *ctx, const key_spec *key,
                           const char *digest_name) {
    jo_assert(ctx != NULL);
    jo_assert(key != NULL);
    jo_assert(digest_name != NULL);

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_ec(key->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    if (ctx->digest_ctx != NULL) {
        EVP_MD_CTX_free(ctx->digest_ctx);
        ctx->digest_ctx = NULL;
    }
    ctx->opp = 0;

    // Reuses OPS_OPENSSL_ERROR_5 / _6. Each test drives only one path.
    md_ctx = EVP_MD_CTX_new();
    if (OPS_OPENSSL_ERROR_5 md_ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(3030);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_6 1 != EVP_DigestVerifyInit_ex(
            md_ctx, &pctx, digest_name, libctx, NULL, key->key, NULL)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(3031);
        goto exit;
    }

    ctx->digest_ctx = md_ctx;
    ctx->opp = EC_OP_VERIFY;
    md_ctx = NULL;
    ret_code = JO_SUCCESS;

exit:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    return ret_code;
}


int32_t ec_ctx_update(ec_ctx *ctx, const uint8_t *in, size_t in_len) {
    jo_assert(ctx != NULL);
    jo_assert(in != NULL);

    if (ctx->digest_ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (in_len > (size_t) INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ERR_clear_error();

    // Both branches share the same OPS flag; each test exercises one
    // mode only. Distinct offsets keep the failures distinguishable.
    if (ctx->opp == EC_OP_SIGN) {
        if (OPS_OPENSSL_ERROR_7 1 != EVP_DigestSignUpdate(
                ctx->digest_ctx, in, in_len)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(3040);
        }
    } else if (ctx->opp == EC_OP_VERIFY) {
        if (OPS_OPENSSL_ERROR_7 1 != EVP_DigestVerifyUpdate(
                ctx->digest_ctx, in, in_len)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(3041);
        }
    } else {
        return JO_UNEXPECTED_STATE;
    }

    return JO_SUCCESS;
}


int32_t ec_ctx_sign(ec_ctx *ctx, uint8_t *out, size_t out_len,
                    void *rnd_src) {
    jo_assert(ctx != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (ctx->digest_ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (ctx->opp != EC_OP_SIGN) {
        return JO_UNEXPECTED_STATE;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    size_t sig_len = 0;
    if (OPS_OPENSSL_ERROR_8 1 != EVP_DigestSignFinal(
            ctx->digest_ctx, NULL, &sig_len)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(3050);
    }

    if (sig_len > (size_t) INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    if (out == NULL) {
        // Two-call protocol: report required length without consuming the
        // streaming digest state. Caller calls again with a real buffer.
        return (int32_t) sig_len;
    }

    if (sig_len > out_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    // ECDSA signatures are DER-encoded SEQUENCE { INTEGER r, INTEGER s };
    // the actual length varies (each integer can be up to curve_byte_len + 1
    // due to the leading-zero rule for unsigned integers in ASN.1 DER).
    // The first DigestSignFinal call returned an UPPER BOUND; the real
    // length comes back from the second call. We report the actual.
    if (OPS_OPENSSL_ERROR_9 1 != EVP_DigestSignFinal(
            ctx->digest_ctx, out, &sig_len)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(3051);
    }

    return (int32_t) sig_len;
}


int32_t ec_ctx_verify(ec_ctx *ctx, const uint8_t *sig, size_t sig_len,
                      void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(sig != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (ctx->digest_ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (ctx->opp != EC_OP_VERIFY) {
        return JO_UNEXPECTED_STATE;
    }

    if (sig_len > (size_t) INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    // EC point blinding inside EVP_DigestVerifyFinal pulls bytes from the
    // RAND provider. Bind the per-thread Java upcall before that path runs.
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    // Mark so verify-fail's "invalid signature" noise can be popped while
    // genuine OpenSSL errors remain queued (rsa_ctx_verify pattern).
    ERR_set_mark();

    int ret = EVP_DigestVerifyFinal(ctx->digest_ctx, sig, sig_len);

    // OPS instrumentation: OPS_OPENSSL_ERROR_10 forces the
    // structural-error branch (ret == -1 path).
    if (OPS_OPENSSL_ERROR_10 0) {
        ERR_clear_last_mark();
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(3060);
    }

    if (ret == 1) {
        ERR_pop_to_mark();
        return JO_SUCCESS;
    } else if (ret == 0) {
        ERR_pop_to_mark();
        return JO_FAIL;
    } else {
        ERR_clear_last_mark();
        return JO_OPENSSL_ERROR;
    }
}


// =============================================================
// Key agreement (ECDH)
// =============================================================

ec_kex_ctx *ec_kex_create(int32_t *err) {
    jo_assert(err != NULL);

    ec_kex_ctx *ctx = (ec_kex_ctx *) OPENSSL_zalloc(sizeof(ec_kex_ctx));
    jo_assert(ctx != NULL);

    *err = JO_SUCCESS;
    return ctx;
}


void ec_kex_destroy(ec_kex_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
    }
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}


int32_t ec_kex_init(ec_kex_ctx *ctx, const key_spec *my_priv,
                    void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(my_priv != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (my_priv->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_ec(my_priv->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    // Free any prior derive ctx so re-init replaces state cleanly.
    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
        ctx->pctx = NULL;
    }
    ctx->peer_set = 0;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(
            get_global_jostle_ossl_lib_ctx(), my_priv->key, NULL);
    if (OPS_OPENSSL_ERROR_11 pctx == NULL) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_11(3070);
    }

    if (OPS_OPENSSL_ERROR_12 1 != EVP_PKEY_derive_init(pctx)) {
        EVP_PKEY_CTX_free(pctx);
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_12(3071);
    }

    ctx->pctx = pctx;
    return JO_SUCCESS;
}


int32_t ec_kex_set_peer(ec_kex_ctx *ctx, const key_spec *peer_pub,
                        void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(peer_pub != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (ctx->pctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (peer_pub->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_ec(peer_pub->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    // Binary-field curves: EVP_PKEY_derive_set_peer runs an internal
    // EVP_PKEY_public_check that scalar-multiplies the peer point with
    // point-blinded multiplication, drawing from RAND. Bind the
    // per-thread Java upcall so the RAND provider can call out into
    // Java entropy. Same pattern as ec_ctx_verify / ec_kex_derive.
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    // EVP_PKEY_derive_set_peer also enforces curve-equality between the
    // local and peer keys; a mismatch surfaces as JO_OPENSSL_ERROR which
    // the Java SPI translates to InvalidKeyException at doPhase().
    // Reuses OPS_OPENSSL_ERROR_1 (also used in keygen / fromdata) — the
    // test exercises only one of those paths per flag setting.
    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_derive_set_peer(
            ctx->pctx, peer_pub->key)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3080);
    }

    ctx->peer_set = 1;
    return JO_SUCCESS;
}


int32_t ec_kex_derive(ec_kex_ctx *ctx, uint8_t *out, size_t out_len,
                      void *rnd_src) {
    jo_assert(ctx != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (ctx->pctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (!ctx->peer_set) {
        return JO_UNEXPECTED_STATE;
    }

    // Same rationale as ec_ctx_verify: EC point-blinding inside the
    // derive primitive draws from the RAND provider, so the per-thread
    // upcall must be installed before EVP_PKEY_derive runs.
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    // Two derive sites (probe + fetch) share OPS_OPENSSL_ERROR_2 — same
    // multiplexing logic as ec_ctx_sign's pair of DigestSignFinal calls.
    size_t need = 0;
    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_derive(ctx->pctx, NULL, &need)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(3090);
    }

    if (need > (size_t) INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    if (out == NULL || out_len == 0) {
        return (int32_t) need;
    }

    if (out_len < need) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = out_len;
    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_derive(ctx->pctx, out, &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(3091);
    }

    if (written > (size_t) INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    return (int32_t) written;
}
