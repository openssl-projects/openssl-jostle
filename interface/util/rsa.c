//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "rsa.h"

#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "key_spec.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"


// =============================================================
// Helpers
// =============================================================

/*
 * Check that an EVP_PKEY is RSA. RSA-PSS keys (a separate "RSA-PSS"
 * algorithm name in OpenSSL) are accepted because OpenSSL's PSS
 * provider exposes the same parameter set; however the JCE side
 * never asks for that — keep this strict for now.
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


/*
 * Map a public RSA_COMP_* selector to its OSSL_PKEY_PARAM_RSA_* name.
 * Returns NULL for an unknown selector.
 */
static const char *component_param_name(int32_t component) {
    switch (component) {
        case RSA_COMP_MODULUS:          return OSSL_PKEY_PARAM_RSA_N;
        case RSA_COMP_PUBLIC_EXPONENT:  return OSSL_PKEY_PARAM_RSA_E;
        case RSA_COMP_PRIVATE_EXPONENT: return OSSL_PKEY_PARAM_RSA_D;
        case RSA_COMP_PRIME_P:          return OSSL_PKEY_PARAM_RSA_FACTOR1;
        case RSA_COMP_PRIME_Q:          return OSSL_PKEY_PARAM_RSA_FACTOR2;
        case RSA_COMP_EXPONENT_P:       return OSSL_PKEY_PARAM_RSA_EXPONENT1;
        case RSA_COMP_EXPONENT_Q:       return OSSL_PKEY_PARAM_RSA_EXPONENT2;
        case RSA_COMP_CRT_COEFFICIENT:  return OSSL_PKEY_PARAM_RSA_COEFFICIENT1;
        default:                        return NULL;
    }
}


/*
 * Given an OSSL_PARAM_BLD with the desired components pushed, materialize
 * an EVP_PKEY of the requested selection (EVP_PKEY_PUBLIC_KEY or
 * EVP_PKEY_KEYPAIR). Frees the param block on every path.
 */
static int32_t fromdata_construct(OSSL_PARAM_BLD *bld, int selection,
                                  EVP_PKEY **pkey_out) {
    int32_t ret_code = JO_FAIL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (OPS_OPENSSL_ERROR_7 params == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(1030);
        goto exit;
    }

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "RSA", NULL);
    if (OPS_OPENSSL_ERROR_8 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(1031);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_9 1 != EVP_PKEY_fromdata_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(1032);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_10 1 != EVP_PKEY_fromdata(ctx, pkey_out, selection, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(1033);
        goto exit;
    }

    if (*pkey_out == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}


// =============================================================
// Key generation
// =============================================================

int32_t rsa_generate_key(key_spec *spec, int32_t bits,
                         const uint8_t *pubexp, size_t pubexp_len,
                         void *rnd_src) {
    jo_assert(spec != NULL);
    jo_assert(pubexp != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    // pubexp_len is user-controlled (size of a Java byte[] passed
    // through the NI layer). An empty byte array is a legitimate Java
    // value but a meaningless RSA public exponent — surface it as an
    // error rather than asserting (CLAUDE.md "Never use jo_assert for
    // user-supplied input").
    if (pubexp_len == 0) {
        return JO_RSA_PUB_EXP_IS_NULL;
    }

    if (pubexp_len > INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *e_bn = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "RSA", NULL);
    // OPS slot _6 is reused — currently fires in configure_padding's
    // PSS-saltlen branch, which is unreachable from rsa_generate_key.
    if (OPS_OPENSSL_ERROR_6 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(1044);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1040);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(1041);
        goto exit;
    }

    e_bn = BN_bin2bn(pubexp, (int) pubexp_len, NULL);
    if (OPS_OPENSSL_ERROR_4 e_bn == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(1042);
        goto exit;
    }

    // set1 makes an internal copy; we still own e_bn and free it below.
    if (OPS_OPENSSL_ERROR_5 1 != EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e_bn)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(1043);
        goto exit;
    }

    // OPS slot _7 is reused — currently fires in fromdata_construct's
    // OSSL_PARAM_BLD_to_param branch, which is unreachable from
    // rsa_generate_key (this function uses EVP_PKEY_keygen directly).
    if (OPS_OPENSSL_ERROR_7 1 != EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(1045);
        goto exit;
    }

#ifdef JOSTLE_OPS
    if (OPS_OPENSSL_ERROR_1 0) {
        EVP_PKEY_free(spec->key);
        spec->key = NULL;
    }
#endif

    if (spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    BN_free(e_bn);
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}


// =============================================================
// Component-based decoding
// =============================================================

int32_t rsa_decode_public_components(key_spec *spec,
                                     const uint8_t *n, size_t n_len,
                                     const uint8_t *e, size_t e_len) {
    jo_assert(spec != NULL);
    jo_assert(n != NULL);
    jo_assert(e != NULL);

    if (n_len > INT_MAX || e_len > INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    BIGNUM *n_bn = NULL;
    BIGNUM *e_bn = NULL;
    OSSL_PARAM_BLD *bld = NULL;

    n_bn = BN_bin2bn(n, (int) n_len, NULL);
    e_bn = BN_bin2bn(e, (int) e_len, NULL);
    if (OPS_OPENSSL_ERROR_2 n_bn == NULL || e_bn == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1050);
        goto exit;
    }
    bld = OSSL_PARAM_BLD_new();
    if (OPS_OPENSSL_ERROR_11 bld == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_11(1051);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_12 1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n_bn) ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_12(1052);
        goto exit;
    }

    ret_code = fromdata_construct(bld, EVP_PKEY_PUBLIC_KEY, &(spec->key));

exit:
    OSSL_PARAM_BLD_free(bld);
    BN_free(n_bn);
    BN_free(e_bn);
    return ret_code;
}


int32_t rsa_decode_private_components(key_spec *spec,
                                      const uint8_t *n, size_t n_len,
                                      const uint8_t *e, size_t e_len,
                                      const uint8_t *d, size_t d_len) {
    jo_assert(spec != NULL);
    jo_assert(n != NULL);
    jo_assert(e != NULL);
    jo_assert(d != NULL);

    if (n_len > INT_MAX || e_len > INT_MAX || d_len > INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    BIGNUM *n_bn = NULL;
    BIGNUM *e_bn = NULL;
    BIGNUM *d_bn = NULL;
    OSSL_PARAM_BLD *bld = NULL;

    n_bn = BN_bin2bn(n, (int) n_len, NULL);
    e_bn = BN_bin2bn(e, (int) e_len, NULL);
    // BN_secure_new for d: it's the secret exponent, allocate from the
    // OpenSSL secure heap if available.
    d_bn = BN_secure_new();
    if (OPS_OPENSSL_ERROR_3 n_bn == NULL || e_bn == NULL || d_bn == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(1060);
        goto exit;
    }
    if (OPS_OPENSSL_ERROR_4 BN_bin2bn(d, (int) d_len, d_bn) == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(1061);
        goto exit;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n_bn) ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn) ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d_bn)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = fromdata_construct(bld, EVP_PKEY_KEYPAIR, &(spec->key));

exit:
    OSSL_PARAM_BLD_free(bld);
    BN_free(n_bn);
    BN_free(e_bn);
    BN_clear_free(d_bn);
    return ret_code;
}


int32_t rsa_decode_private_components_crt(key_spec *spec,
                                          const uint8_t *n, size_t n_len,
                                          const uint8_t *e, size_t e_len,
                                          const uint8_t *d, size_t d_len,
                                          const uint8_t *p, size_t p_len,
                                          const uint8_t *q, size_t q_len,
                                          const uint8_t *dp, size_t dp_len,
                                          const uint8_t *dq, size_t dq_len,
                                          const uint8_t *qinv, size_t qinv_len) {
    jo_assert(spec != NULL);
    jo_assert(n != NULL && e != NULL && d != NULL);
    jo_assert(p != NULL && q != NULL && dp != NULL && dq != NULL && qinv != NULL);

    if (n_len > INT_MAX || e_len > INT_MAX || d_len > INT_MAX ||
        p_len > INT_MAX || q_len > INT_MAX || dp_len > INT_MAX ||
        dq_len > INT_MAX || qinv_len > INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    BIGNUM *n_bn = NULL, *e_bn = NULL, *d_bn = NULL;
    BIGNUM *p_bn = NULL, *q_bn = NULL;
    BIGNUM *dp_bn = NULL, *dq_bn = NULL, *qi_bn = NULL;
    OSSL_PARAM_BLD *bld = NULL;

    n_bn = BN_bin2bn(n, (int) n_len, NULL);
    e_bn = BN_bin2bn(e, (int) e_len, NULL);
    // Secret components into the secure heap.
    d_bn  = BN_secure_new();
    p_bn  = BN_secure_new();
    q_bn  = BN_secure_new();
    dp_bn = BN_secure_new();
    dq_bn = BN_secure_new();
    qi_bn = BN_secure_new();

    if (n_bn == NULL || e_bn == NULL || d_bn == NULL ||
        p_bn == NULL || q_bn == NULL ||
        dp_bn == NULL || dq_bn == NULL || qi_bn == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (BN_bin2bn(d,    (int) d_len,    d_bn)  == NULL ||
        BN_bin2bn(p,    (int) p_len,    p_bn)  == NULL ||
        BN_bin2bn(q,    (int) q_len,    q_bn)  == NULL ||
        BN_bin2bn(dp,   (int) dp_len,   dp_bn) == NULL ||
        BN_bin2bn(dq,   (int) dq_len,   dq_bn) == NULL ||
        BN_bin2bn(qinv, (int) qinv_len, qi_bn) == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n_bn) ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn) ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d_bn) ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1,    p_bn)  ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2,    q_bn)  ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1,  dp_bn) ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2,  dq_bn) ||
        1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qi_bn)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = fromdata_construct(bld, EVP_PKEY_KEYPAIR, &(spec->key));

exit:
    OSSL_PARAM_BLD_free(bld);
    BN_free(n_bn);
    BN_free(e_bn);
    BN_clear_free(d_bn);
    BN_clear_free(p_bn);
    BN_clear_free(q_bn);
    BN_clear_free(dp_bn);
    BN_clear_free(dq_bn);
    BN_clear_free(qi_bn);
    return ret_code;
}


// =============================================================
// Component getter
// =============================================================

int32_t rsa_get_component(const key_spec *spec, int32_t component,
                          uint8_t *out, size_t out_len) {
    jo_assert(spec != NULL);

    if (spec->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_rsa(spec->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    const char *param_name = component_param_name(component);
    if (param_name == NULL) {
        return JO_FAIL;
    }

    ERR_clear_error();

    BIGNUM *bn = NULL;
    int32_t ret_code = JO_FAIL;

    // EVP_PKEY_get_bn_param allocates a new BIGNUM that the caller frees.
    // For private-only components on a public key, this fails — return the
    // OpenSSL error code; the SPI layer maps that to a null-component
    // return per the JCE contract.
    //
    // OPS slot _8 is reused — currently fires in fromdata_construct's
    // EVP_PKEY_CTX_new_from_name branch, which is unreachable from
    // rsa_get_component. The OPS-injected return code (-1072) differs
    // from a real "component absent" failure (bare -2), so a test can
    // tell them apart.
    if (OPS_OPENSSL_ERROR_8 1 != EVP_PKEY_get_bn_param(spec->key, param_name, &bn)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(1070);
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


// =============================================================
// Sign / verify session
// =============================================================

rsa_ctx *rsa_ctx_create(int32_t *err) {
    jo_assert(err != NULL);

    rsa_ctx *ctx = (rsa_ctx *) OPENSSL_zalloc(sizeof(rsa_ctx));
    jo_assert(ctx != NULL);

    *err = JO_SUCCESS;
    return ctx;
}


void rsa_ctx_destroy(rsa_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->digest_ctx != NULL) {
        EVP_MD_CTX_free(ctx->digest_ctx);
    }
    if (ctx->raw_pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->raw_pctx);
    }
    if (ctx->raw_buf != NULL) {
        OPENSSL_clear_free(ctx->raw_buf, ctx->raw_buf_cap);
    }

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}


/*
 * Free all per-session state on the ctx and return it to the "freshly
 * created" state (opp == 0, padding_mode == 0, no digest_ctx, no raw
 * session). Called at the top of init_sign / init_verify so a failed
 * (re-)init can't leave a half-configured context behind, and from
 * rsa_ctx_destroy. NULL-tolerant on every field.
 */
static void rsa_ctx_clear_session(rsa_ctx *ctx) {
    if (ctx->digest_ctx != NULL) {
        EVP_MD_CTX_free(ctx->digest_ctx);
        ctx->digest_ctx = NULL;
    }
    if (ctx->raw_pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->raw_pctx);
        ctx->raw_pctx = NULL;
    }
    if (ctx->raw_buf != NULL) {
        OPENSSL_clear_free(ctx->raw_buf, ctx->raw_buf_cap);
        ctx->raw_buf = NULL;
    }
    ctx->raw_buf_len = 0;
    ctx->raw_buf_cap = 0;
    ctx->opp = 0;
    ctx->padding_mode = 0;
}

/*
 * Initialise the raw PKCS#1 v1.5 ("NoneWithRSA") session: an EVP_PKEY_CTX
 * set up for EVP_PKEY_sign / EVP_PKEY_verify with RSA_PKCS1_PADDING and NO
 * signature md, so OpenSSL pads the caller-supplied bytes directly. Caller
 * has already cleared prior session state via rsa_ctx_clear_session.
 */
static int32_t rsa_raw_init(rsa_ctx *ctx, OSSL_LIB_CTX *libctx,
                            EVP_PKEY *key, int op) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, NULL);
    if (pctx == NULL) {
        return JO_OPENSSL_ERROR;
    }

    int init_rc = (op == RSA_OP_SIGN)
                      ? EVP_PKEY_sign_init(pctx)
                      : EVP_PKEY_verify_init(pctx);
    if (1 != init_rc) {
        EVP_PKEY_CTX_free(pctx);
        return JO_OPENSSL_ERROR;
    }

    if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING)) {
        EVP_PKEY_CTX_free(pctx);
        return JO_OPENSSL_ERROR;
    }

    ctx->raw_pctx = pctx;
    ctx->opp = op;
    ctx->padding_mode = RSA_PADDING_PKCS1_NONE;
    return JO_SUCCESS;
}

/*
 * Append caller-supplied bytes to the raw-mode buffer (the TBS that
 * EVP_PKEY_sign / EVP_PKEY_verify will consume one-shot). Grows the buffer
 * geometrically; the total is bounded to INT32_MAX so the eventual cast to
 * int on the Java return path can't overflow.
 */
static int32_t rsa_raw_append(rsa_ctx *ctx, const uint8_t *in, size_t in_len) {
    if (in_len > (size_t) INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }
    if (ctx->raw_buf_len > (size_t) INT_MAX - in_len) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    size_t need = ctx->raw_buf_len + in_len;
    if (need > ctx->raw_buf_cap) {
        size_t new_cap = ctx->raw_buf_cap != 0 ? ctx->raw_buf_cap : 64;
        while (new_cap < need) {
            new_cap *= 2;
        }
        uint8_t *nb = OPENSSL_realloc(ctx->raw_buf, new_cap);
        jo_assert(nb != NULL);
        ctx->raw_buf = nb;
        ctx->raw_buf_cap = new_cap;
    }

    if (in_len > 0) {
        memcpy(ctx->raw_buf + ctx->raw_buf_len, in, in_len);
    }
    ctx->raw_buf_len = need;
    return JO_SUCCESS;
}


/*
 * Common configuration for both sign and verify after EVP_DigestSign/
 * VerifyInit_ex has populated *pctx. Maps the padding mode flag to the
 * OpenSSL constant and applies PSS parameters when relevant.
 */
static int32_t configure_padding(EVP_PKEY_CTX *pctx,
                                 int32_t padding_mode,
                                 const char *digest_name,
                                 const char *mgf1_md_name,
                                 int32_t salt_len) {
    if (padding_mode == RSA_PADDING_PKCS1) {
        if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(1020);
        }
        return JO_SUCCESS;
    }

    if (padding_mode == RSA_PADDING_PSS) {
        if (OPS_OPENSSL_ERROR_4 1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(1021);
        }

        // Default: MGF1 hash matches the signing hash (modern safe default).
        // Java SPI substitutes the signing hash explicitly when
        // PSSParameterSpec did not specify one; here we just honour NULL
        // as a defensive fallback.
        const char *mgf = (mgf1_md_name != NULL) ? mgf1_md_name : digest_name;
        if (OPS_OPENSSL_ERROR_5 1 != EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, mgf, NULL)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(1022);
        }

        // Negative salt_len → "use digest output length".
        int actual_saltlen = (salt_len < 0) ? RSA_PSS_SALTLEN_DIGEST : (int) salt_len;
        if (OPS_OPENSSL_ERROR_6 1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, actual_saltlen)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(1023);
        }
        return JO_SUCCESS;
    }

    return JO_INVALID_MODE;
}


int32_t rsa_ctx_init_sign(rsa_ctx *ctx, const key_spec *key,
                          const char *digest_name,
                          int32_t padding_mode,
                          const char *mgf1_md_name,
                          int32_t salt_len,
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

    int32_t check = check_is_rsa(key->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_MD_CTX *md_ctx = NULL;       // local; transferred to ctx on success
    EVP_PKEY_CTX *pctx = NULL;       // not owned — owned by md_ctx

    // Free any prior session state up-front. If init then fails partway,
    // ctx stays cleared so subsequent rsa_ctx_update / _sign / _verify
    // return JO_NOT_INITIALIZED rather than dispatching into a
    // half-configured context (undefined behaviour inside libcrypto).
    rsa_ctx_clear_session(ctx);

    // Raw PKCS#1 v1.5 ("NoneWithRSA") has no streaming digest — set up an
    // EVP_PKEY_CTX and buffer input until rsa_ctx_sign.
    if (padding_mode == RSA_PADDING_PKCS1_NONE) {
        return rsa_raw_init(ctx, libctx, key->key, RSA_OP_SIGN);
    }

    md_ctx = EVP_MD_CTX_new();
    if (OPS_OPENSSL_ERROR_1 md_ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1000);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_DigestSignInit_ex(md_ctx, &pctx,
                                                       digest_name, libctx, NULL,
                                                       key->key, NULL)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1001);
        goto exit;
    }

    int32_t pad_rc = configure_padding(pctx, padding_mode, digest_name,
                                       mgf1_md_name, salt_len);
    if (pad_rc != JO_SUCCESS) {
        ret_code = pad_rc;
        goto exit;
    }

    // All configuration succeeded — transfer ownership.
    ctx->digest_ctx = md_ctx;
    ctx->opp = RSA_OP_SIGN;
    ctx->padding_mode = padding_mode;
    md_ctx = NULL; // ownership transferred
    ret_code = JO_SUCCESS;

exit:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    return ret_code;
}


int32_t rsa_ctx_init_verify(rsa_ctx *ctx, const key_spec *key,
                            const char *digest_name,
                            int32_t padding_mode,
                            const char *mgf1_md_name,
                            int32_t salt_len) {
    jo_assert(ctx != NULL);
    jo_assert(key != NULL);
    jo_assert(digest_name != NULL);

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_rsa(key->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_MD_CTX *md_ctx = NULL;       // local; transferred to ctx on success
    EVP_PKEY_CTX *pctx = NULL;       // not owned — owned by md_ctx

    // Clear prior session state up-front (see rsa_ctx_init_sign for why).
    rsa_ctx_clear_session(ctx);

    // Raw PKCS#1 v1.5 ("NoneWithRSA") verify path — buffer + EVP_PKEY_verify.
    if (padding_mode == RSA_PADDING_PKCS1_NONE) {
        return rsa_raw_init(ctx, libctx, key->key, RSA_OP_VERIFY);
    }

    md_ctx = EVP_MD_CTX_new();
    if (OPS_OPENSSL_ERROR_1 md_ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1003);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_DigestVerifyInit_ex(md_ctx, &pctx,
                                                         digest_name, libctx, NULL,
                                                         key->key, NULL)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1004);
        goto exit;
    }

    int32_t pad_rc = configure_padding(pctx, padding_mode, digest_name,
                                       mgf1_md_name, salt_len);
    if (pad_rc != JO_SUCCESS) {
        ret_code = pad_rc;
        goto exit;
    }

    ctx->digest_ctx = md_ctx;
    ctx->opp = RSA_OP_VERIFY;
    ctx->padding_mode = padding_mode;
    md_ctx = NULL; // ownership transferred
    ret_code = JO_SUCCESS;

exit:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    return ret_code;
}


int32_t rsa_ctx_update(rsa_ctx *ctx, const uint8_t *in, size_t in_len) {
    jo_assert(ctx != NULL);
    jo_assert(in != NULL);

    // Raw PKCS#1 v1.5: accumulate into the buffer, no streaming digest.
    if (ctx->padding_mode == RSA_PADDING_PKCS1_NONE) {
        if (ctx->raw_pctx == NULL) {
            return JO_NOT_INITIALIZED;
        }
        if (ctx->opp != RSA_OP_SIGN && ctx->opp != RSA_OP_VERIFY) {
            return JO_UNEXPECTED_STATE;
        }
        return rsa_raw_append(ctx, in, in_len);
    }

    if (ctx->digest_ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (in_len > (size_t) INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ERR_clear_error();

    if (ctx->opp == RSA_OP_SIGN) {
        // OPS slot _9 is reused — currently fires in fromdata_construct's
        // EVP_PKEY_fromdata_init branch, which is unreachable from
        // rsa_ctx_update (this function operates on an already-initialised
        // EVP_MD_CTX, not a key-construction pipeline).
        if (OPS_OPENSSL_ERROR_9 1 != EVP_DigestSignUpdate(ctx->digest_ctx, in, in_len)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(1010);
        }
    } else if (ctx->opp == RSA_OP_VERIFY) {
        // OPS slot _10 is reused — currently fires in fromdata_construct's
        // EVP_PKEY_fromdata branch, unreachable from rsa_ctx_update.
        if (OPS_OPENSSL_ERROR_10 1 != EVP_DigestVerifyUpdate(ctx->digest_ctx, in, in_len)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(1011);
        }
    } else {
        return JO_UNEXPECTED_STATE;
    }

    return JO_SUCCESS;
}


int32_t rsa_ctx_sign(rsa_ctx *ctx, uint8_t *out, size_t out_len,
                     void *rnd_src) {
    jo_assert(ctx != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    // Raw PKCS#1 v1.5 ("NoneWithRSA"): one-shot EVP_PKEY_sign over the
    // buffered caller-supplied bytes. PKCS#1 v1.5 signing is deterministic,
    // so rnd_src is unused beyond the bridge's null check.
    if (ctx->padding_mode == RSA_PADDING_PKCS1_NONE) {
        if (ctx->raw_pctx == NULL) {
            return JO_NOT_INITIALIZED;
        }
        if (ctx->opp != RSA_OP_SIGN) {
            return JO_UNEXPECTED_STATE;
        }

        rand_set_java_srand_call(rnd_src);
        ERR_clear_error();

        size_t raw_sig_len = 0;
        if (1 != EVP_PKEY_sign(ctx->raw_pctx, NULL, &raw_sig_len,
                               ctx->raw_buf, ctx->raw_buf_len)) {
            return JO_OPENSSL_ERROR;
        }
        if (raw_sig_len > INT32_MAX) {
            return JO_OUTPUT_TOO_LONG_INT32;
        }
        if (out == NULL) {
            return (int32_t) raw_sig_len;
        }
        if (raw_sig_len > out_len) {
            return JO_OUTPUT_TOO_SMALL;
        }
        const size_t raw_expected = raw_sig_len;
        if (1 != EVP_PKEY_sign(ctx->raw_pctx, out, &raw_sig_len,
                               ctx->raw_buf, ctx->raw_buf_len)) {
            return JO_OPENSSL_ERROR;
        }
        if (raw_sig_len != raw_expected) {
            return JO_UNEXPECTED_SIG_LEN_CHANGE;
        }
        return (int32_t) raw_sig_len;
    }

    if (ctx->digest_ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (ctx->opp != RSA_OP_SIGN) {
        return JO_UNEXPECTED_STATE;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    size_t sig_len = 0;
    if (OPS_OPENSSL_ERROR_1 1 != EVP_DigestSignFinal(ctx->digest_ctx, NULL, &sig_len)) {
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_1 sig_len > INT32_MAX) {
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

    const size_t expected = sig_len;
    if (OPS_OPENSSL_ERROR_2 1 != EVP_DigestSignFinal(ctx->digest_ctx, out, &sig_len)) {
        return JO_OPENSSL_ERROR;
    }

    if (OPS_LEN_CHANGE_1 sig_len != expected) {
        return JO_UNEXPECTED_SIG_LEN_CHANGE;
    }

    return (int32_t) sig_len;
}


int32_t rsa_ctx_verify(rsa_ctx *ctx, const uint8_t *sig, size_t sig_len) {
    jo_assert(ctx != NULL);
    jo_assert(sig != NULL);

    // Raw PKCS#1 v1.5 ("NoneWithRSA"): one-shot EVP_PKEY_verify of the
    // signature against the buffered caller-supplied bytes.
    if (ctx->padding_mode == RSA_PADDING_PKCS1_NONE) {
        if (ctx->raw_pctx == NULL) {
            return JO_NOT_INITIALIZED;
        }
        if (ctx->opp != RSA_OP_VERIFY) {
            return JO_UNEXPECTED_STATE;
        }
        if (sig_len > (size_t) INT_MAX) {
            return JO_INPUT_TOO_LONG_INT32;
        }

        ERR_clear_error();
        ERR_set_mark();
        int raw_ret = EVP_PKEY_verify(ctx->raw_pctx, sig, sig_len,
                                      ctx->raw_buf, ctx->raw_buf_len);
        if (raw_ret == 1) {
            ERR_pop_to_mark();
            return JO_SUCCESS;
        } else if (raw_ret == 0) {
            ERR_pop_to_mark();
            return JO_FAIL;
        } else {
            ERR_clear_last_mark();
            return JO_OPENSSL_ERROR;
        }
    }

    if (ctx->digest_ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (ctx->opp != RSA_OP_VERIFY) {
        return JO_UNEXPECTED_STATE;
    }

    if (sig_len > (size_t) INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ERR_clear_error();

    // Mark so verify-fail's "invalid signature" noise can be popped while
    // genuine OpenSSL errors remain queued.
    ERR_set_mark();

    int ret = EVP_DigestVerifyFinal(ctx->digest_ctx, sig, sig_len);

    if (OPS_OPENSSL_ERROR_1 0) {
        ret = -1;
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
