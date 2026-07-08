//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "dh.h"

#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "key_spec.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"

// OPS fault-injection offsets in this file use the 5200 block
// (rsa.c: 1000s, rsa_oaep.c: 2000s, ec.c: 3000s, dsa.c: 5000s).


// =============================================================
// Helpers
// =============================================================

/*
 * Verify the supplied EVP_PKEY is finite-field DH. Accepts both the
 * PKCS#3 "DH" and X9.42 "DHX" EVP_PKEY types — they share the FFC key
 * shape and both support EVP_PKEY_derive. Mirrors check_is_dsa in
 * dsa.c.
 */
static int32_t check_is_dh(const EVP_PKEY *pkey) {
    const char *algo = EVP_PKEY_get0_type_name(pkey);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }
    if (strcmp(algo, "DH") != 0 && strcmp(algo, "DHX") != 0) {
        return JO_INCORRECT_KEY_TYPE;
    }
    return JO_SUCCESS;
}


// =============================================================
// Group introspection
// =============================================================

int32_t dh_group_supported(const char *group_name) {
    // Bridge-validated invariant: group_name was null-checked by the
    // JNI / FFI bridge, which surfaced JO_NAME_IS_NULL on its own.
    jo_assert(group_name != NULL);

    // Like the EC keymgmt, the DH keymgmt validates the group name
    // lazily — set_params stores the string and real validation
    // happens at paramgen. Drive a full EVP_PKEY_paramgen so an
    // unrecognised name fails here (ec_curve_supported rationale).

    int32_t ret_code = JO_CURVE_NOT_SUPPORTED;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                     "DH", NULL);
    if (ctx == NULL) {
        goto exit;
    }

    if (1 != EVP_PKEY_paramgen_init(ctx)) {
        goto exit;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, (char *) group_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (1 != EVP_PKEY_CTX_set_params(ctx, params)) {
        goto exit;
    }

    if (1 != EVP_PKEY_paramgen(ctx, &pkey)) {
        goto exit;
    }
    if (pkey == NULL) {
        goto exit;
    }

    ret_code = 1;

exit:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    // Suppress any "no such group" entry the failed probe queued — the
    // caller is asking a yes/no question, not requesting an error
    // report.
    ERR_clear_error();
    return ret_code;
}


// =============================================================
// Key generation (named group)
// =============================================================

int32_t dh_generate_key_by_group(key_spec *spec, const char *group_name,
                                 void *rnd_src) {
    jo_assert(spec != NULL);
    jo_assert(group_name != NULL);

    jo_assert(rnd_src != NULL);

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                     "DH", NULL);
    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(5200);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(5201);
        goto exit;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, (char *) group_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_CTX_set_params(ctx, params)) {
        // Most likely cause: unknown group name. The Java SPI maps key
        // sizes to known RFC 7919 names, so this is reachable only for
        // NI-level callers passing arbitrary strings.
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(5202);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 1 != EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(5203);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_5 spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(5204);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}


// =============================================================
// Domain-parameter generation (safe prime)
// =============================================================

int32_t dh_generate_parameters(key_spec *spec, int32_t p_bits,
                               void *rnd_src) {
    // Bridge-validated invariant: both bridges range-check p_bits > 0;
    // the Java SPI applies the policy bounds (512..8192, multiple of 64).
    jo_assert(spec != NULL);
    jo_assert(p_bits > 0);

    jo_assert(rnd_src != NULL);

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned int pbits_u = (unsigned int) p_bits;

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                     "DH", NULL);
    // Reuses flags 6..9 (flags 1..5 cover the named-group keygen path);
    // each test drives only one entry point per flag.
    if (OPS_OPENSSL_ERROR_6 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(5210);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_7 1 != EVP_PKEY_paramgen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(5211);
        goto exit;
    }

    // PKCS#3-style safe-prime generation: OpenSSL's DH paramgen
    // defaults to the "generator" type (p safe prime, g = 2) when only
    // the prime length is supplied.
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_PBITS, &pbits_u);
    params[1] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_8 1 != EVP_PKEY_CTX_set_params(ctx, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(5212);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_9 1 != EVP_PKEY_paramgen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(5213);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_10 spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(5214);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}


// =============================================================
// Construct EVP_PKEY from raw components (shared fromdata path)
// =============================================================

/*
 * Build a DH EVP_PKEY from big-endian unsigned magnitudes via
 * OSSL_PARAM_BLD + EVP_PKEY_fromdata, replacing any prior key on the
 * spec. Exactly one of three shapes per call:
 *
 *   x_be == NULL && y_be == NULL  — parameters only (EVP_PKEY_KEY_PARAMETERS)
 *   x_be == NULL && y_be != NULL  — public key (EVP_PKEY_PUBLIC_KEY)
 *   x_be != NULL                  — private key (EVP_PKEY_KEYPAIR); the
 *                                   public value y = g^x mod p is computed
 *                                   here because OpenSSL's FFC fromdata
 *                                   import does not re-derive it.
 *
 * Mirrors dsa_fromdata; PKCS#3 DH has no q.
 */
static int32_t dh_fromdata(key_spec *spec,
                           const uint8_t *p_be, size_t p_len,
                           const uint8_t *g_be, size_t g_len,
                           const uint8_t *y_be, size_t y_len,
                           const uint8_t *x_be, size_t x_len) {
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *p_bn = NULL;
    BIGNUM *g_bn = NULL;
    BIGNUM *y_bn = NULL;
    BIGNUM *x_bn = NULL;
    BN_CTX *bn_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int selection = EVP_PKEY_KEY_PARAMETERS;

    p_bn = BN_bin2bn(p_be, (int) p_len, NULL);
    g_bn = BN_bin2bn(g_be, (int) g_len, NULL);
    if (OPS_OPENSSL_ERROR_6 p_bn == NULL || g_bn == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(5220);
        goto exit;
    }

    if (y_be != NULL) {
        y_bn = BN_bin2bn(y_be, (int) y_len, NULL);
        if (OPS_OPENSSL_ERROR_3 y_bn == NULL) {
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(5221);
            goto exit;
        }
        selection = EVP_PKEY_PUBLIC_KEY;
    }

    if (x_be != NULL) {
        x_bn = BN_bin2bn(x_be, (int) x_len, NULL);
        if (OPS_OPENSSL_ERROR_4 x_bn == NULL) {
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(5222);
            goto exit;
        }
        // The private value is secret — flag it constant-time so the
        // y = g^x mod p exponentiation below uses the hardened path.
        BN_set_flags(x_bn, BN_FLG_CONSTTIME);
        selection = EVP_PKEY_KEYPAIR;

        if (y_bn == NULL) {
            // OpenSSL's FFC fromdata import stores exactly what it is
            // given — it does NOT re-derive the public half from the
            // private value, and a keypair import without
            // OSSL_PKEY_PARAM_PUB_KEY fails. Compute y = g^x mod p
            // ourselves (dsa_fromdata rationale).
            bn_ctx = BN_CTX_new();
            y_bn = BN_new();
            if (OPS_OPENSSL_ERROR_5 bn_ctx == NULL || y_bn == NULL) {
                ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(5223);
                goto exit;
            }
            if (OPS_OPENSSL_ERROR_7 1 != BN_mod_exp(y_bn, g_bn, x_bn,
                                                    p_bn, bn_ctx)) {
                ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(5224);
                goto exit;
            }
        }
    }

    bld = OSSL_PARAM_BLD_new();
    if (OPS_OPENSSL_ERROR_8 bld == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(5225);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_9 1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p_bn)
        || 1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g_bn)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(5226);
        goto exit;
    }

    if (y_bn != NULL) {
        if (OPS_OPENSSL_ERROR_10 1 != OSSL_PARAM_BLD_push_BN(
                bld, OSSL_PKEY_PARAM_PUB_KEY, y_bn)) {
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(5227);
            goto exit;
        }
    }
    if (x_bn != NULL) {
        if (OPS_OPENSSL_ERROR_11 1 != OSSL_PARAM_BLD_push_BN(
                bld, OSSL_PKEY_PARAM_PRIV_KEY, x_bn)) {
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_11(5228);
            goto exit;
        }
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (OPS_OPENSSL_ERROR_12 params == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_12(5229);
        goto exit;
    }

    pctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                      "DH", NULL);
    if (OPS_OPENSSL_ERROR_1 pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(5230);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_fromdata_init(pctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(5231);
        goto exit;
    }

    // Reuses OPS_FAILED_INIT_1 for the fromdata call (dsa_fromdata
    // precedent); each test exercises only one entry point per flag.
    if (OPS_FAILED_INIT_1 1 != EVP_PKEY_fromdata(pctx, &pkey,
                                                 selection, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_FAILED_INIT_1(5232);
        goto exit;
    }

    if (pkey == NULL) {
        ret_code = JO_OPENSSL_ERROR;
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
    BN_free(p_bn);
    BN_free(g_bn);
    BN_free(y_bn);
    BN_clear_free(x_bn);
    BN_CTX_free(bn_ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return ret_code;
}


int32_t dh_make_params_from_components(key_spec *spec,
                                       const uint8_t *p_be, size_t p_len,
                                       const uint8_t *g_be, size_t g_len) {
    // Bridge-validated invariants: pointer null checks and length
    // bounds (zero / > INT32_MAX) are done by both bridges.
    jo_assert(spec != NULL);
    jo_assert(p_be != NULL && p_len > 0 && p_len <= (size_t) INT32_MAX);
    jo_assert(g_be != NULL && g_len > 0 && g_len <= (size_t) INT32_MAX);

    return dh_fromdata(spec, p_be, p_len, g_be, g_len,
                       NULL, 0, NULL, 0);
}


int32_t dh_make_private_from_components(key_spec *spec,
                                        const uint8_t *p_be, size_t p_len,
                                        const uint8_t *g_be, size_t g_len,
                                        const uint8_t *x_be, size_t x_len,
                                        void *rnd_src) {
    jo_assert(spec != NULL);
    jo_assert(p_be != NULL && p_len > 0 && p_len <= (size_t) INT32_MAX);
    jo_assert(g_be != NULL && g_len > 0 && g_len <= (size_t) INT32_MAX);
    jo_assert(x_be != NULL && x_len > 0 && x_len <= (size_t) INT32_MAX);
    jo_assert(rnd_src != NULL);

    // The import path doesn't structurally need entropy today, but the
    // upcall is bound anyway so RAND consumed anywhere inside the
    // OpenSSL import path resolves to fresh Java entropy rather than a
    // stale thread-local (dsa_make_private_from_components rationale).
    rand_set_java_srand_call(rnd_src);

    return dh_fromdata(spec, p_be, p_len, g_be, g_len,
                       NULL, 0, x_be, x_len);
}


int32_t dh_make_public_from_components(key_spec *spec,
                                       const uint8_t *p_be, size_t p_len,
                                       const uint8_t *g_be, size_t g_len,
                                       const uint8_t *y_be, size_t y_len) {
    jo_assert(spec != NULL);
    jo_assert(p_be != NULL && p_len > 0 && p_len <= (size_t) INT32_MAX);
    jo_assert(g_be != NULL && g_len > 0 && g_len <= (size_t) INT32_MAX);
    jo_assert(y_be != NULL && y_len > 0 && y_len <= (size_t) INT32_MAX);

    return dh_fromdata(spec, p_be, p_len, g_be, g_len,
                       y_be, y_len, NULL, 0);
}


// =============================================================
// Key generation (from established parameters)
// =============================================================

int32_t dh_generate_key(key_spec *spec, const key_spec *params,
                        void *rnd_src) {
    jo_assert(spec != NULL);
    jo_assert(params != NULL);

    jo_assert(rnd_src != NULL);

    if (params->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_dh(params->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(get_global_jostle_ossl_lib_ctx(),
                                     params->key, NULL);
    // Reuses flags 3..6 (dsa_generate_key precedent); each test drives
    // only one entry point per flag.
    if (OPS_OPENSSL_ERROR_3 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(5240);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 1 != EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(5241);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_5 1 != EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(5242);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_6 spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(5243);
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
 * Fetch a BIGNUM component identified by an OSSL_PKEY_PARAM_* name and
 * return it as big-endian unsigned magnitude. Mirrors get_bn_component
 * in dsa.c.
 */
static int32_t get_bn_component(const key_spec *spec, const char *param_name,
                                uint8_t *out, size_t out_len) {
    BIGNUM *bn = NULL;
    int32_t ret_code = JO_FAIL;

    if (OPS_OPENSSL_ERROR_7 1 != EVP_PKEY_get_bn_param(spec->key, param_name, &bn)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(5250);
        goto exit;
    }

    int byte_len = BN_num_bytes(bn);
    if (OPS_OPENSSL_ERROR_8 byte_len < 0) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(5251);
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
    if (OPS_OPENSSL_ERROR_9 written < 0) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(5252);
        goto exit;
    }

    ret_code = (int32_t) written;

exit:
    BN_clear_free(bn);
    return ret_code;
}


int32_t dh_get_component(const key_spec *spec, int32_t component,
                         uint8_t *out, size_t out_len) {
    jo_assert(spec != NULL);

    if (spec->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_dh(spec->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    ERR_clear_error();

    switch (component) {
        case DH_COMP_P:
            return get_bn_component(spec, OSSL_PKEY_PARAM_FFC_P,
                                    out, out_len);
        case DH_COMP_Q:
            return get_bn_component(spec, OSSL_PKEY_PARAM_FFC_Q,
                                    out, out_len);
        case DH_COMP_G:
            return get_bn_component(spec, OSSL_PKEY_PARAM_FFC_G,
                                    out, out_len);
        case DH_COMP_PUBLIC_VALUE:
            return get_bn_component(spec, OSSL_PKEY_PARAM_PUB_KEY,
                                    out, out_len);
        case DH_COMP_PRIVATE_VALUE:
            return get_bn_component(spec, OSSL_PKEY_PARAM_PRIV_KEY,
                                    out, out_len);
        default:
            return JO_FAIL;
    }
}


// =============================================================
// Key agreement
// =============================================================

dh_kex_ctx *dh_kex_create(int32_t *err) {
    jo_assert(err != NULL);

    dh_kex_ctx *ctx = (dh_kex_ctx *) OPENSSL_zalloc(sizeof(dh_kex_ctx));
    jo_assert(ctx != NULL);

    *err = JO_SUCCESS;
    return ctx;
}


void dh_kex_destroy(dh_kex_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
    }
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}


int32_t dh_kex_init(dh_kex_ctx *ctx, const key_spec *my_priv,
                    void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(my_priv != NULL);

    jo_assert(rnd_src != NULL);

    if (my_priv->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_dh(my_priv->key);
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
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_11(5260);
    }

    if (OPS_OPENSSL_ERROR_12 1 != EVP_PKEY_derive_init(pctx)) {
        EVP_PKEY_CTX_free(pctx);
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_12(5261);
    }

    // SECURITY-RELEVANT PARAMETER — DO NOT CHANGE THIS VALUE.
    //
    // pad = 1 makes EVP_PKEY_derive return the shared secret
    // left-padded to the prime length instead of stripping leading
    // zeros (OpenSSL's default). BouncyCastle's JCE DH agreement
    // returns p-length output and TLS 1.3 FFDHE (RFC 8446 §7.4.1)
    // requires padded secrets; the unpadded form silently diverges
    // from both on roughly 1 in 256 derivations. Set explicitly per
    // the CLAUDE.md "hard-code security-critical OpenSSL parameters"
    // rule; the matching runtime hard guard is
    // DHKeyAgreementTest.testDh_SharedSecretPadding_HardGuard.
    unsigned int pad = 1;
    OSSL_PARAM pad_params[2];
    pad_params[0] = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad);
    pad_params[1] = OSSL_PARAM_construct_end();

    if (OPS_FAILED_INIT_2 1 != EVP_PKEY_CTX_set_params(pctx, pad_params)) {
        EVP_PKEY_CTX_free(pctx);
        return JO_OPENSSL_ERROR OPS_OFFSET_FAILED_INIT_2(5262);
    }

    ctx->pctx = pctx;
    return JO_SUCCESS;
}


int32_t dh_kex_set_peer(dh_kex_ctx *ctx, const key_spec *peer_pub,
                        void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(peer_pub != NULL);

    jo_assert(rnd_src != NULL);

    if (ctx->pctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (peer_pub->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_dh(peer_pub->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    // Bound for parity with the EC kex surface — any internal
    // public-key validation that consumes RAND resolves to fresh Java
    // entropy rather than a stale thread-local.
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    // EVP_PKEY_derive_set_peer also enforces group equality between
    // the local and peer keys; a mismatch surfaces as JO_OPENSSL_ERROR
    // which the Java SPI translates to InvalidKeyException at doPhase().
    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_derive_set_peer(
            ctx->pctx, peer_pub->key)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(5270);
    }

    ctx->peer_set = 1;
    return JO_SUCCESS;
}


int32_t dh_kex_derive(dh_kex_ctx *ctx, uint8_t *out, size_t out_len,
                      void *rnd_src) {
    jo_assert(ctx != NULL);

    jo_assert(rnd_src != NULL);

    if (ctx->pctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (!ctx->peer_set) {
        return JO_UNEXPECTED_STATE;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    // Probe and fetch sites use distinct OPS flags (ec_kex_derive
    // rationale — sharing a flag would make the fetch site unreachable
    // from a test because the probe site fires first).
    size_t need = 0;
    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_derive(ctx->pctx, NULL, &need)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(5280);
    }

    if (OPS_INT32_OVERFLOW_1 need > (size_t) INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    if (out == NULL || out_len == 0) {
        return (int32_t) need;
    }

    if (out_len < need) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = out_len;
    if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_derive(ctx->pctx, out, &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(5281);
    }

    if (OPS_INT32_OVERFLOW_2 written > (size_t) INT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    return (int32_t) written;
}
