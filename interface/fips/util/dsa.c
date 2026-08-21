//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "dsa.h"

#include <string.h>
#include <openssl/bio.h>
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

// OPS fault-injection offsets in this file use the 5000 block
// (rsa.c: 1000s, rsa_oaep.c: 2000s, ec.c: 3000s, xec/edec: 3300/4000).


// =============================================================
// Helpers
// =============================================================

/*
 * Verify the supplied EVP_PKEY is DSA. Returns JO_SUCCESS on match,
 * JO_INCORRECT_KEY_TYPE otherwise. Mirrors check_is_ec in ec.c.
 */
static int32_t check_is_dsa(const EVP_PKEY *pkey) {
    const char *algo = EVP_PKEY_get0_type_name(pkey);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }
    if (strcmp(algo, "DSA") != 0) {
        return JO_INCORRECT_KEY_TYPE;
    }
    return JO_SUCCESS;
}


/*
 * A failure whose code carries an OPS offset was INJECTED by the
 * operations-test harness, not produced by OpenSSL — the OPS_OFFSET_* macros
 * expand to nothing in a release build, so only an unadorned JO_OPENSSL_ERROR
 * can be a real one. The classifiers below must not reinterpret a synthetic
 * failure as a provider capability: doing so would swallow the offset that
 * identifies which call site the test drove, and would report a capability
 * the provider may well have.
 */
#define JO_ERROR_WAS_INJECTED(code) ((code) != JO_OPENSSL_ERROR)

/*
 * Classify a FAILED DSA generation call. Returns JO_DSA_KEYGEN_UNAVAILABLE
 * when the provider serving this ctx gates DSA keygen behind its FIPS
 * "sign-check" indicator, JO_OPENSSL_ERROR otherwise.
 *
 * Diagnosis-on-failure (the dh_kex_init pattern), never pre-validation: the
 * generation is attempted first and only its failure is explained. OpenSSL's
 * 3.5+ FIPS module refuses DSA keygen in strict mode via
 * OSSL_FIPS_IND_ON_UNAPPROVED(..., "DSA", "Keygen", ...) and returns 0
 * WITHOUT raising an error of its own, so libcrypto reports only the generic
 * "provider keymgmt failure" - unusable for a precise message. The gate's own
 * settable, OSSL_PKEY_PARAM_FIPS_SIGN_CHECK, is present on the gen ctx
 * exactly where the gate exists.
 *
 * Probe-measured on both supported modules (fips-c-review/probes/dsa_gate_probe.c),
 * at both call sites (paramgen ctx and keygen-from-parameters ctx):
 *
 *   3.1.2 : settable ABSENT,  generation SUCCEEDS  -> branch never taken
 *   3.5.7 : settable PRESENT, generation REFUSED   -> precise code returned
 *
 * Because the branch cannot fire on a provider that performs the operation,
 * the identical source serves the fips and nonfips trees. ERR marks scope the
 * probe so its own noise cannot disturb the primary error report.
 */
static int32_t classify_dsa_gen_failure(EVP_PKEY_CTX *ctx, int32_t generic) {
    jo_assert(ctx != NULL);

    ERR_set_mark();
    const OSSL_PARAM *settable = EVP_PKEY_CTX_settable_params(ctx);
    int gated = settable != NULL
                && OSSL_PARAM_locate_const(settable,
                                           OSSL_PKEY_PARAM_FIPS_SIGN_CHECK) != NULL;
    ERR_pop_to_mark();

    if (gated) {
        return JO_DSA_KEYGEN_UNAVAILABLE;
    }
    return generic;
}




/*
 * Reference digest for the sign probe below. An input we CHOOSE, not a value
 * read back from OpenSSL, so hard-coding it is correct: SHA-256 is approved
 * for DSA signing by every FIPS module we support (and by mainline), which is
 * exactly what makes it usable as the control.
 */
#define DSA_SIGN_PROBE_DIGEST "SHA256"

/*
 * Classify a FAILED DSA sign-init. Returns JO_DSA_SIGN_UNAVAILABLE only when
 * the provider refuses to SIGN with this key at all while still VERIFYING
 * with it; JO_OPENSSL_ERROR otherwise.
 *
 * Diagnosis-on-failure, and both probes ask for the property semantically
 * rather than reading an indicator name that could drift:
 *
 *   1. Retry the sign init with a digest the provider certainly approves. If
 *      THAT works, the provider does sign DSA and the caller's failure was
 *      about something else - the digest it asked for, or the raw mode.
 *   2. Only then check that verification does work, which is what the
 *      returned message claims.
 *
 * Probe 1 is not optional, and leaving it out is a bug that shipped for
 * exactly one test run: the 3.1.2 module signs DSA happily but refuses SHA-1
 * (ossl_fips_ind_digest_sign_check), and a verify-only probe classified that
 * as "DSA signature generation is not supported" - telling the caller the
 * algorithm was unavailable when only one digest was.
 *
 * Worth the extra calls because the real capability failure is otherwise
 * mute: OpenSSL's 3.5+ FIPS module runs dsa_sig.c::dsa_sign_check_approved
 * only when signing and returns 0 WITHOUT raising, so the error queue is empty
 * and the generic path reports "OpenSSL Error: null" (probe-measured). A
 * provider that signs never reaches this, so the identical source serves both
 * trees.
 *
 * ERR marks scope both probes: a probe failing for its own reasons must not
 * displace the sign-init error the caller is about to be told about.
 */
static int32_t classify_dsa_sign_failure(OSSL_LIB_CTX *libctx, EVP_PKEY *key,
                                         int32_t generic) {
    jo_assert(libctx != NULL);
    jo_assert(key != NULL);

    ERR_set_mark();

    EVP_MD_CTX *sign_probe = EVP_MD_CTX_new();
    int sign_ok = sign_probe != NULL
                  && 1 == EVP_DigestSignInit_ex(sign_probe, NULL,
                                                DSA_SIGN_PROBE_DIGEST, libctx,
                                                NULL, key, NULL);
    EVP_MD_CTX_free(sign_probe);

    int verify_ok = 0;
    if (!sign_ok) {
        EVP_PKEY_CTX *verify_probe = EVP_PKEY_CTX_new_from_pkey(libctx, key, NULL);
        verify_ok = verify_probe != NULL && 1 == EVP_PKEY_verify_init(verify_probe);
        EVP_PKEY_CTX_free(verify_probe);
    }

    ERR_pop_to_mark();

    if (!sign_ok && verify_ok) {
        return JO_DSA_SIGN_UNAVAILABLE;
    }
    return generic;
}

// =============================================================
// Domain-parameter generation
// =============================================================

int32_t dsa_generate_parameters(key_spec *spec, int32_t p_bits,
                                int32_t q_bits, void *rnd_src) {
    // Bridge-validated invariants: both bridges range-check the bit
    // sizes (> 0) before this util function runs; the Java SPI applies
    // the policy bounds.
    jo_assert(spec != NULL);
    jo_assert(p_bits > 0);
    jo_assert(q_bits > 0);

    jo_assert(rnd_src != NULL);

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned int pbits_u = (unsigned int) p_bits;
    unsigned int qbits_u = (unsigned int) q_bits;

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                     "DSA", NULL);
    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(5000);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_paramgen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(5001);
        goto exit;
    }

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_PBITS, &pbits_u);
    params[1] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_QBITS, &qbits_u);
    params[2] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_CTX_set_params(ctx, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(5002);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 1 != EVP_PKEY_paramgen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(5003);
        if (!JO_ERROR_WAS_INJECTED(ret_code)) {
            ret_code = classify_dsa_gen_failure(ctx, ret_code);
        }
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_5 spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(5004);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    EVP_PKEY_CTX_free(ctx);
    rand_clear_java_srand_call();
    return ret_code;
}


// =============================================================
// Construct EVP_PKEY from raw components (shared fromdata path)
// =============================================================

/*
 * Build a DSA EVP_PKEY from big-endian unsigned magnitudes via
 * OSSL_PARAM_BLD + EVP_PKEY_fromdata, replacing any prior key on the
 * spec. Exactly one of three shapes per call:
 *
 *   x_be == NULL && y_be == NULL  — parameters only (EVP_PKEY_KEY_PARAMETERS)
 *   x_be == NULL && y_be != NULL  — public key (EVP_PKEY_PUBLIC_KEY)
 *   x_be != NULL                  — private key (EVP_PKEY_KEYPAIR); the
 *                                   public value y = g^x mod p is computed
 *                                   here because OpenSSL's FFC fromdata
 *                                   import does not re-derive it.
 */
static int32_t dsa_fromdata(key_spec *spec,
                            const uint8_t *p_be, size_t p_len,
                            const uint8_t *q_be, size_t q_len,
                            const uint8_t *g_be, size_t g_len,
                            const uint8_t *y_be, size_t y_len,
                            const uint8_t *x_be, size_t x_len) {
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *p_bn = NULL;
    BIGNUM *q_bn = NULL;
    BIGNUM *g_bn = NULL;
    BIGNUM *y_bn = NULL;
    BIGNUM *x_bn = NULL;
    BN_CTX *bn_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int selection = EVP_PKEY_KEY_PARAMETERS;

    p_bn = BN_bin2bn(p_be, (int) p_len, NULL);
    q_bn = BN_bin2bn(q_be, (int) q_len, NULL);
    g_bn = BN_bin2bn(g_be, (int) g_len, NULL);
    if (OPS_OPENSSL_ERROR_6 p_bn == NULL || q_bn == NULL || g_bn == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(5010);
        goto exit;
    }

    if (y_be != NULL) {
        y_bn = BN_bin2bn(y_be, (int) y_len, NULL);
        if (OPS_OPENSSL_ERROR_3 y_bn == NULL) {
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(5019);
            goto exit;
        }
        selection = EVP_PKEY_PUBLIC_KEY;
    }

    if (x_be != NULL) {
        // Secure-heap BN: OSSL_PARAM_BLD serialises every pushed BN
        // into the params blob, and only BNs flagged secure route that
        // copy into the secure block that OSSL_PARAM_free cleanses. A
        // plain BN would leave the private value behind in ordinary
        // freed heap.
        x_bn = BN_secure_new();
        if (OPS_OPENSSL_ERROR_4 x_bn == NULL
            || NULL == BN_bin2bn(x_be, (int) x_len, x_bn)) {
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(5020);
            goto exit;
        }
        // The private value is secret — flag it constant-time so the
        // y = g^x mod p exponentiation below uses the hardened path.
        BN_set_flags(x_bn, BN_FLG_CONSTTIME);
        selection = EVP_PKEY_KEYPAIR;

        if (y_bn == NULL) {
            // OpenSSL's FFC fromdata import stores exactly what it is
            // given — it does NOT re-derive the public half from the
            // private value. A keypair import without
            // OSSL_PKEY_PARAM_PUB_KEY half-succeeds: it reports
            // success but yields a key with no public half, which
            // breaks encoding and public-side operations later.
            // Compute y = g^x mod p ourselves.
            bn_ctx = BN_CTX_new_ex(get_global_jostle_ossl_lib_ctx());
            y_bn = BN_new();
            if (OPS_OPENSSL_ERROR_5 bn_ctx == NULL || y_bn == NULL) {
                ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(5021);
                goto exit;
            }
            if (OPS_OPENSSL_ERROR_7 1 != BN_mod_exp(y_bn, g_bn, x_bn,
                                                    p_bn, bn_ctx)) {
                ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(5011);
                goto exit;
            }
        }
    }

    bld = OSSL_PARAM_BLD_new();
    if (OPS_OPENSSL_ERROR_8 bld == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(5012);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_9 1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p_bn)
        || 1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q_bn)
        || 1 != OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g_bn)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(5013);
        goto exit;
    }

    if (y_bn != NULL) {
        if (OPS_OPENSSL_ERROR_10 1 != OSSL_PARAM_BLD_push_BN(
                bld, OSSL_PKEY_PARAM_PUB_KEY, y_bn)) {
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(5014);
            goto exit;
        }
    }
    if (x_bn != NULL) {
        if (OPS_OPENSSL_ERROR_11 1 != OSSL_PARAM_BLD_push_BN(
                bld, OSSL_PKEY_PARAM_PRIV_KEY, x_bn)) {
            ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_11(5015);
            goto exit;
        }
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (OPS_OPENSSL_ERROR_12 params == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_12(5016);
        goto exit;
    }

    pctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                      "DSA", NULL);
    if (OPS_OPENSSL_ERROR_1 pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(5017);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_fromdata_init(pctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(5018);
        goto exit;
    }

    // Reuses OPS_FAILED_INIT_1 for the fromdata call so the raw-init
    // flag space stays within ops.h's defined set; each test exercises
    // only one entry point per flag.
    if (OPS_FAILED_INIT_1 1 != EVP_PKEY_fromdata(pctx, &pkey,
                                                 selection, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_FAILED_INIT_1(5022);
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
    BN_free(q_bn);
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


int32_t dsa_make_params_from_components(key_spec *spec,
                                        const uint8_t *p_be, size_t p_len,
                                        const uint8_t *q_be, size_t q_len,
                                        const uint8_t *g_be, size_t g_len) {
    // Bridge-validated invariants: pointer null checks and length
    // bounds (zero / > INT32_MAX) are done by both bridges.
    jo_assert(spec != NULL);
    jo_assert(p_be != NULL && p_len > 0 && p_len <= (size_t) INT32_MAX);
    jo_assert(q_be != NULL && q_len > 0 && q_len <= (size_t) INT32_MAX);
    jo_assert(g_be != NULL && g_len > 0 && g_len <= (size_t) INT32_MAX);

    return dsa_fromdata(spec, p_be, p_len, q_be, q_len, g_be, g_len,
                        NULL, 0, NULL, 0);
}


int32_t dsa_make_private_from_components(key_spec *spec,
                                         const uint8_t *p_be, size_t p_len,
                                         const uint8_t *q_be, size_t q_len,
                                         const uint8_t *g_be, size_t g_len,
                                         const uint8_t *x_be, size_t x_len,
                                         void *rnd_src) {
    jo_assert(spec != NULL);
    jo_assert(p_be != NULL && p_len > 0 && p_len <= (size_t) INT32_MAX);
    jo_assert(q_be != NULL && q_len > 0 && q_len <= (size_t) INT32_MAX);
    jo_assert(g_be != NULL && g_len > 0 && g_len <= (size_t) INT32_MAX);
    jo_assert(x_be != NULL && x_len > 0 && x_len <= (size_t) INT32_MAX);
    jo_assert(rnd_src != NULL);

    // DSA's import path doesn't structurally need entropy today, but
    // the upcall is bound anyway so RAND consumed anywhere inside the
    // OpenSSL import path resolves to fresh Java entropy rather than a
    // stale thread-local (mirrors ec_make_private_from_components).
    rand_set_java_srand_call(rnd_src);

    int32_t ret_code = dsa_fromdata(spec, p_be, p_len, q_be, q_len, g_be, g_len,
                                    NULL, 0, x_be, x_len);
    rand_clear_java_srand_call();
    return ret_code;
}


int32_t dsa_make_public_from_components(key_spec *spec,
                                        const uint8_t *p_be, size_t p_len,
                                        const uint8_t *q_be, size_t q_len,
                                        const uint8_t *g_be, size_t g_len,
                                        const uint8_t *y_be, size_t y_len) {
    jo_assert(spec != NULL);
    jo_assert(p_be != NULL && p_len > 0 && p_len <= (size_t) INT32_MAX);
    jo_assert(q_be != NULL && q_len > 0 && q_len <= (size_t) INT32_MAX);
    jo_assert(g_be != NULL && g_len > 0 && g_len <= (size_t) INT32_MAX);
    jo_assert(y_be != NULL && y_len > 0 && y_len <= (size_t) INT32_MAX);

    return dsa_fromdata(spec, p_be, p_len, q_be, q_len, g_be, g_len,
                        y_be, y_len, NULL, 0);
}


// =============================================================
// Key generation
// =============================================================

int32_t dsa_generate_key(key_spec *spec, const key_spec *params,
                         void *rnd_src) {
    jo_assert(spec != NULL);
    jo_assert(params != NULL);

    jo_assert(rnd_src != NULL);

    if (params->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_dsa(params->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(get_global_jostle_ossl_lib_ctx(),
                                     params->key, NULL);
    // Reuses flags 3..5 (also used in paramgen / fromdata); each test
    // drives only one entry point per flag.
    if (OPS_OPENSSL_ERROR_3 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(5030);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 1 != EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(5031);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_5 1 != EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(5032);
        if (!JO_ERROR_WAS_INJECTED(ret_code)) {
            ret_code = classify_dsa_gen_failure(ctx, ret_code);
        }
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_6 spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(5033);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    EVP_PKEY_CTX_free(ctx);
    rand_clear_java_srand_call();
    return ret_code;
}


// =============================================================
// Component getter
// =============================================================

/*
 * Fetch a BIGNUM component identified by an OSSL_PKEY_PARAM_* name and
 * return it as big-endian unsigned magnitude. Mirrors get_bn_component
 * in ec.c.
 */
static int32_t get_bn_component(const key_spec *spec, const char *param_name,
                                uint8_t *out, size_t out_len) {
    BIGNUM *bn = NULL;
    int32_t ret_code = JO_FAIL;

    if (OPS_OPENSSL_ERROR_7 1 != EVP_PKEY_get_bn_param(spec->key, param_name, &bn)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(5110);
        goto exit;
    }

    int byte_len = BN_num_bytes(bn);
    if (OPS_OPENSSL_ERROR_8 byte_len < 0) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(5111);
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
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(5112);
        goto exit;
    }

    ret_code = (int32_t) written;

exit:
    BN_clear_free(bn);
    return ret_code;
}


int32_t dsa_get_component(const key_spec *spec, int32_t component,
                          uint8_t *out, size_t out_len) {
    jo_assert(spec != NULL);

    if (spec->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_dsa(spec->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    ERR_clear_error();

    switch (component) {
        case DSA_COMP_P:
            return get_bn_component(spec, OSSL_PKEY_PARAM_FFC_P,
                                    out, out_len);
        case DSA_COMP_Q:
            return get_bn_component(spec, OSSL_PKEY_PARAM_FFC_Q,
                                    out, out_len);
        case DSA_COMP_G:
            return get_bn_component(spec, OSSL_PKEY_PARAM_FFC_G,
                                    out, out_len);
        case DSA_COMP_PUBLIC_VALUE:
            return get_bn_component(spec, OSSL_PKEY_PARAM_PUB_KEY,
                                    out, out_len);
        case DSA_COMP_PRIVATE_VALUE:
            return get_bn_component(spec, OSSL_PKEY_PARAM_PRIV_KEY,
                                    out, out_len);
        default:
            return JO_FAIL;
    }
}


// =============================================================
// Sign / verify session
// =============================================================

dsa_ctx *dsa_ctx_create(int32_t *err) {
    jo_assert(err != NULL);

    dsa_ctx *ctx = (dsa_ctx *) OPENSSL_zalloc(sizeof(dsa_ctx));
    jo_assert(ctx != NULL);

    *err = JO_SUCCESS;
    return ctx;
}


static void dsa_ctx_clear_session(dsa_ctx *ctx);

void dsa_ctx_destroy(dsa_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    dsa_ctx_clear_session(ctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}


/*
 * Free all per-session state on the ctx, returning it to the freshly-created
 * state (no digest_ctx, no raw session, opp == 0). NULL-tolerant on every
 * field. Called at the top of init_sign / init_verify and from dsa_ctx_destroy.
 */
static void dsa_ctx_clear_session(dsa_ctx *ctx) {
    if (ctx->digest_ctx != NULL) {
        EVP_MD_CTX_free(ctx->digest_ctx);
        ctx->digest_ctx = NULL;
    }
    if (ctx->raw_pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->raw_pctx);
        ctx->raw_pctx = NULL;
    }
    BIO_free_all(ctx->raw_bio);
    ctx->raw_bio = NULL;
    ctx->opp = 0;
}

/*
 * Initialise the raw DSA ("NoneWithDSA") session: an EVP_PKEY_CTX set up
 * for EVP_PKEY_sign / EVP_PKEY_verify with no EVP_MD, so OpenSSL treats the
 * caller-supplied bytes as the already-computed digest. DSA has no padding,
 * so there is nothing else to configure. Caller has already cleared prior
 * session state via dsa_ctx_clear_session.
 */
static int32_t dsa_raw_init(dsa_ctx *ctx, OSSL_LIB_CTX *libctx,
                            EVP_PKEY *key, int op) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, NULL);
    if (OPS_OPENSSL_ERROR_11 pctx == NULL) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_11(5090);
    }

    int init_rc = (op == DSA_OP_SIGN)
                      ? EVP_PKEY_sign_init(pctx)
                      : EVP_PKEY_verify_init(pctx);
    if (OPS_FAILED_INIT_2 1 != init_rc) {
        EVP_PKEY_CTX_free(pctx);
        int32_t generic = JO_OPENSSL_ERROR OPS_OFFSET_FAILED_INIT_2(5093);
        if (op == DSA_OP_SIGN && !JO_ERROR_WAS_INJECTED(generic)) {
            return classify_dsa_sign_failure(libctx, key, generic);
        }
        return generic;
    }

    ctx->raw_pctx = pctx;
    ctx->opp = op;
    return JO_SUCCESS;
}

/*
 * Return a pointer to the accumulated raw-mode bytes and set *len to their
 * length. Returns NULL with *len == 0 when nothing has been appended (the
 * BIO was never created), which EVP_PKEY_sign / EVP_PKEY_verify accept as a
 * zero-length input.
 */
static const uint8_t *dsa_raw_data(dsa_ctx *ctx, size_t *len) {
    if (ctx->raw_bio == NULL) {
        *len = 0;
        return NULL;
    }
    char *p = NULL;
    const long n = BIO_get_mem_data(ctx->raw_bio, &p);
    *len = (size_t) n;
    return (const uint8_t *) p;
}

/*
 * Append caller-supplied bytes to the raw-mode buffer (the pre-computed digest
 * that EVP_PKEY_sign / EVP_PKEY_verify consumes one-shot). A memory BIO owns
 * the growth (BIO_write grows via BUF_MEM_grow_clean, cleansing the old copy
 * on realloc) and the zeroization on release; the total is bounded to
 * INT32_MAX so the eventual int cast can't overflow.
 */
static int32_t dsa_raw_append(dsa_ctx *ctx, const uint8_t *in, size_t in_len) {
    if (in_len > (size_t) INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }
    if (ctx->raw_bio == NULL) {
        ctx->raw_bio = BIO_new(BIO_s_mem());
        jo_assert(ctx->raw_bio != NULL);
    }
    size_t cur = 0;
    (void) dsa_raw_data(ctx, &cur);
    if (cur > (size_t) INT32_MAX - in_len) {
        return JO_INPUT_TOO_LONG_INT32;
    }
    if (in_len > 0) {
        const int w = BIO_write(ctx->raw_bio, in, (int) in_len);
        jo_assert(w == (int) in_len);
    }
    return JO_SUCCESS;
}


int32_t dsa_ctx_init_sign(dsa_ctx *ctx, const key_spec *key,
                          const char *digest_name,
                          void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(key != NULL);
    jo_assert(digest_name != NULL);

    jo_assert(rnd_src != NULL);

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_dsa(key->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_MD_CTX *md_ctx = NULL;       // local; transferred to ctx on success
    EVP_PKEY_CTX *pctx = NULL;       // not owned — owned by md_ctx

    // Free any prior session state up-front (ec_ctx_init_sign rationale).
    dsa_ctx_clear_session(ctx);

    // Raw DSA ("NoneWithDSA") — no streaming digest; buffer the
    // caller-supplied digest and sign it one-shot in dsa_ctx_sign.
    if (strcmp(digest_name, "NONE") == 0) {
        int32_t raw_ret = dsa_raw_init(ctx, libctx, key->key, DSA_OP_SIGN);
        rand_clear_java_srand_call();
        return raw_ret;
    }

    // Reuses OPS_OPENSSL_ERROR_3 / _4. Each test drives only one path.
    md_ctx = EVP_MD_CTX_new();
    if (OPS_OPENSSL_ERROR_3 md_ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(5040);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 1 != EVP_DigestSignInit_ex(
            md_ctx, &pctx, digest_name, libctx, NULL, key->key, NULL)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(5041);
        if (!JO_ERROR_WAS_INJECTED(ret_code)) {
            ret_code = classify_dsa_sign_failure(libctx, key->key, ret_code);
        }
        goto exit;
    }

    // DSA has no padding modes — nothing else to configure.

    ctx->digest_ctx = md_ctx;
    ctx->opp = DSA_OP_SIGN;
    md_ctx = NULL; // ownership transferred
    ret_code = JO_SUCCESS;

exit:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    rand_clear_java_srand_call();
    return ret_code;
}


int32_t dsa_ctx_init_verify(dsa_ctx *ctx, const key_spec *key,
                            const char *digest_name) {
    jo_assert(ctx != NULL);
    jo_assert(key != NULL);
    jo_assert(digest_name != NULL);

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int32_t check = check_is_dsa(key->key);
    if (check != JO_SUCCESS) {
        return check;
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    dsa_ctx_clear_session(ctx);

    // Raw DSA ("NoneWithDSA") verify path — buffer + EVP_PKEY_verify.
    if (strcmp(digest_name, "NONE") == 0) {
        return dsa_raw_init(ctx, libctx, key->key, DSA_OP_VERIFY);
    }

    // Reuses OPS_OPENSSL_ERROR_5 / _6. Each test drives only one path.
    md_ctx = EVP_MD_CTX_new();
    if (OPS_OPENSSL_ERROR_5 md_ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(5050);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_6 1 != EVP_DigestVerifyInit_ex(
            md_ctx, &pctx, digest_name, libctx, NULL, key->key, NULL)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(5051);
        goto exit;
    }

    ctx->digest_ctx = md_ctx;
    ctx->opp = DSA_OP_VERIFY;
    md_ctx = NULL;
    ret_code = JO_SUCCESS;

exit:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }
    return ret_code;
}


int32_t dsa_ctx_update(dsa_ctx *ctx, const uint8_t *in, size_t in_len) {
    // Bridges pass in_len as int32_t (JNI: jint; FFI: int32_t) and
    // already null-check `in` and bounds-check the offset/length pair,
    // so an in_len exceeding INT32_MAX is structurally impossible from
    // either bridge. Util treats both as invariants.
    jo_assert(ctx != NULL);
    jo_assert(in != NULL);
    jo_assert(in_len <= (size_t) INT32_MAX);

    // Raw DSA: accumulate the caller-supplied digest, no streaming hash.
    if (ctx->raw_pctx != NULL) {
        if (ctx->opp != DSA_OP_SIGN && ctx->opp != DSA_OP_VERIFY) {
            return JO_UNEXPECTED_STATE;
        }
        return dsa_raw_append(ctx, in, in_len);
    }

    if (ctx->digest_ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    ERR_clear_error();

    // Both branches share the same OPS flag; each test exercises one
    // mode only. Distinct offsets keep the failures distinguishable.
    if (ctx->opp == DSA_OP_SIGN) {
        if (OPS_OPENSSL_ERROR_7 1 != EVP_DigestSignUpdate(
                ctx->digest_ctx, in, in_len)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(5060);
        }
    } else if (ctx->opp == DSA_OP_VERIFY) {
        if (OPS_OPENSSL_ERROR_7 1 != EVP_DigestVerifyUpdate(
                ctx->digest_ctx, in, in_len)) {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_7(5061);
        }
    } else {
        return JO_UNEXPECTED_STATE;
    }

    return JO_SUCCESS;
}


int32_t dsa_ctx_sign(dsa_ctx *ctx, uint8_t *out, size_t out_len,
                     void *rnd_src) {
    jo_assert(ctx != NULL);

    jo_assert(rnd_src != NULL);

    // Raw DSA ("NoneWithDSA"): one-shot EVP_PKEY_sign over the buffered
    // caller-supplied digest. DSA is randomised, so rnd_src feeds the nonce.
    if (ctx->raw_pctx != NULL) {
        if (ctx->opp != DSA_OP_SIGN) {
            return JO_UNEXPECTED_STATE;
        }
        rand_set_java_srand_call(rnd_src);
        ERR_clear_error();

        size_t raw_len = 0;
        const uint8_t *raw_ptr = dsa_raw_data(ctx, &raw_len);

        size_t raw_sig_len = 0;
        if (OPS_OPENSSL_ERROR_12 1 != EVP_PKEY_sign(ctx->raw_pctx, NULL, &raw_sig_len,
                               raw_ptr, raw_len)) {
            rand_clear_java_srand_call();
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_12(5091);
        }
        if (raw_sig_len > (size_t) INT32_MAX) {
            rand_clear_java_srand_call();
            return JO_OUTPUT_TOO_LONG_INT32;
        }
        if (out == NULL) {
            rand_clear_java_srand_call();
            return (int32_t) raw_sig_len;
        }
        if (raw_sig_len > out_len) {
            rand_clear_java_srand_call();
            return JO_OUTPUT_TOO_SMALL;
        }
        // DSA DER length varies; the first call returned an upper bound and
        // the second writes the actual length back into raw_sig_len.
        if (1 != EVP_PKEY_sign(ctx->raw_pctx, out, &raw_sig_len,
                               raw_ptr, raw_len)) {
            rand_clear_java_srand_call();
            return JO_OPENSSL_ERROR;
        }
        rand_clear_java_srand_call();
        return (int32_t) raw_sig_len;
    }

    if (ctx->digest_ctx == NULL) {
        rand_clear_java_srand_call();
        return JO_NOT_INITIALIZED;
    }

    if (ctx->opp != DSA_OP_SIGN) {
        rand_clear_java_srand_call();
        return JO_UNEXPECTED_STATE;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    size_t sig_len = 0;
    if (OPS_OPENSSL_ERROR_8 1 != EVP_DigestSignFinal(
            ctx->digest_ctx, NULL, &sig_len)) {
        rand_clear_java_srand_call();
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_8(5070);
    }

    if (OPS_INT32_OVERFLOW_1 sig_len > (size_t) INT32_MAX) {
        rand_clear_java_srand_call();
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    if (out == NULL) {
        // Two-call protocol: report required length without consuming the
        // streaming digest state. Caller calls again with a real buffer.
        rand_clear_java_srand_call();
        return (int32_t) sig_len;
    }

    if (sig_len > out_len) {
        rand_clear_java_srand_call();
        return JO_OUTPUT_TOO_SMALL;
    }

    // DSA signatures are DER-encoded SEQUENCE { INTEGER r, INTEGER s };
    // the actual length varies (each integer can be up to q_byte_len + 1
    // due to the leading-zero rule for unsigned integers in ASN.1 DER).
    // The first DigestSignFinal call returned an UPPER BOUND; the real
    // length comes back from the second call. We report the actual.
    if (OPS_OPENSSL_ERROR_9 1 != EVP_DigestSignFinal(
            ctx->digest_ctx, out, &sig_len)) {
        rand_clear_java_srand_call();
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_9(5071);
    }

    rand_clear_java_srand_call();
    return (int32_t) sig_len;
}


int32_t dsa_ctx_verify(dsa_ctx *ctx, const uint8_t *sig, size_t sig_len,
                       void *rnd_src) {
    // Bridges pass sig_len as int32_t (JNI: jint; FFI: int32_t) and
    // already null-check `sig` and range-check the length, so sig_len
    // exceeding INT32_MAX is structurally impossible from either bridge.
    jo_assert(ctx != NULL);
    jo_assert(sig != NULL);
    jo_assert(sig_len <= (size_t) INT32_MAX);

    jo_assert(rnd_src != NULL);

    // Raw DSA ("NoneWithDSA"): one-shot EVP_PKEY_verify of the DER
    // signature against the buffered caller-supplied digest.
    if (ctx->raw_pctx != NULL) {
        if (ctx->opp != DSA_OP_VERIFY) {
            return JO_UNEXPECTED_STATE;
        }
        rand_set_java_srand_call(rnd_src);
        ERR_clear_error();
        ERR_set_mark();
        size_t raw_len = 0;
        const uint8_t *raw_ptr = dsa_raw_data(ctx, &raw_len);
        int raw_ret = EVP_PKEY_verify(ctx->raw_pctx, sig, sig_len,
                                      raw_ptr, raw_len);
        // OPS: force the structural-error (-1) branch.
        if (OPS_OPENSSL_ERROR_11 0) {
            ERR_clear_last_mark();
            rand_clear_java_srand_call();
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_11(5092);
        }
        if (raw_ret == 1) {
            ERR_pop_to_mark();
            rand_clear_java_srand_call();
            return JO_SUCCESS;
        } else if (raw_ret == 0) {
            ERR_pop_to_mark();
            rand_clear_java_srand_call();
            return JO_FAIL;
        } else {
            ERR_clear_last_mark();
            rand_clear_java_srand_call();
            return JO_OPENSSL_ERROR;
        }
    }

    if (ctx->digest_ctx == NULL) {
        rand_clear_java_srand_call();
        return JO_NOT_INITIALIZED;
    }

    if (ctx->opp != DSA_OP_VERIFY) {
        rand_clear_java_srand_call();
        return JO_UNEXPECTED_STATE;
    }

    // DSA verification doesn't currently draw from RAND inside OpenSSL,
    // but the per-thread upcall is bound anyway — see dsa.h.
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
        rand_clear_java_srand_call();
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_10(5080);
    }

    if (ret == 1) {
        ERR_pop_to_mark();
        rand_clear_java_srand_call();
        return JO_SUCCESS;
    } else if (ret == 0) {
        ERR_pop_to_mark();
        rand_clear_java_srand_call();
        return JO_FAIL;
    } else {
        ERR_clear_last_mark();
        rand_clear_java_srand_call();
        return JO_OPENSSL_ERROR;
    }
}
