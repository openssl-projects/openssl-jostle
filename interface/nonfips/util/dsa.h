//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef DSA_H
#define DSA_H
#include <stdint.h>

#include <openssl/evp.h>

#include "key_spec.h"

// Sign / verify operation flags (analogous to EC_OP_SIGN / EC_OP_VERIFY).
#define DSA_OP_SIGN 1
#define DSA_OP_VERIFY 2

// Component selectors for dsa_get_component(). Stable identifiers
// across the FFI/JNI boundary — do NOT renumber.
#define DSA_COMP_P              0   // FFC prime modulus p
#define DSA_COMP_Q              1   // FFC subgroup order q
#define DSA_COMP_G              2   // FFC generator g
#define DSA_COMP_PUBLIC_VALUE   3   // public value y = g^x mod p
#define DSA_COMP_PRIVATE_VALUE  4   // private value x


// =============================================================
// Domain-parameter generation / construction
// =============================================================

/*
 * Generate DSA domain parameters (p, q, g) per FIPS 186-4. The
 * resulting parameters-only EVP_PKEY is written into spec->key.
 * Returns JO_SUCCESS or a negative error code; on failure spec->key
 * is left NULL.
 *
 *   p_bits:  modulus length in bits (e.g. 1024 / 2048 / 3072).
 *            MUST be > 0; the Java SPI enforces the policy bounds.
 *   q_bits:  subgroup order length in bits (160 / 224 / 256).
 *            MUST be > 0.
 *   rnd_src: RandSource for the prime-search entropy. MUST be non-NULL.
 */
int32_t dsa_generate_parameters(key_spec *spec, int32_t p_bits,
                                int32_t q_bits, void *rnd_src);

/*
 * Build a parameters-only DSA EVP_PKEY from explicit (p, q, g)
 * big-endian unsigned magnitudes via EVP_PKEY_fromdata. Used by the
 * KeyPairGenerator's DSAParameterSpec path and by the component-form
 * KeyFactory paths.
 */
int32_t dsa_make_params_from_components(key_spec *spec,
                                        const uint8_t *p_be, size_t p_len,
                                        const uint8_t *q_be, size_t q_len,
                                        const uint8_t *g_be, size_t g_len);


// =============================================================
// Key generation
// =============================================================

/*
 * Generate a DSA keypair from previously-established domain parameters
 * (a spec produced by dsa_generate_parameters or
 * dsa_make_params_from_components). The resulting EVP_PKEY is written
 * into spec->key; on failure spec->key is left NULL.
 *
 *   rnd_src: RandSource for the private-value entropy. MUST be non-NULL.
 */
int32_t dsa_generate_key(key_spec *spec, const key_spec *params,
                         void *rnd_src);


// =============================================================
// Component getter / component-form key construction
// =============================================================

/*
 * Fetch a single BIGNUM component from a DSA EVP_PKEY as big-endian
 * unsigned magnitude. Two-call protocol matching ec_get_component:
 * pass NULL out / 0 out_len to query the required byte length; the
 * second call with a sufficiently-large buffer writes the component
 * and returns the byte count.
 *
 * Returns a negative error code if the component is absent (e.g.
 * asking for DSA_COMP_PRIVATE_VALUE on a public key).
 */
int32_t dsa_get_component(const key_spec *spec, int32_t component,
                          uint8_t *out, size_t out_len);

/*
 * Build a DSA private key from explicit (p, q, g, x) big-endian
 * unsigned magnitudes. The public value y = g^x mod p is computed
 * here (constant-time modular exponentiation) because OpenSSL's
 * fromdata import does not re-derive it for FFC key types.
 *
 *   rnd_src: RandSource. Conservatively required so any RAND
 *            consumption inside the OpenSSL import path can up-call
 *            for entropy (mirrors ec_make_private_from_components).
 */
int32_t dsa_make_private_from_components(key_spec *spec,
                                         const uint8_t *p_be, size_t p_len,
                                         const uint8_t *q_be, size_t q_len,
                                         const uint8_t *g_be, size_t g_len,
                                         const uint8_t *x_be, size_t x_len,
                                         void *rnd_src);

/*
 * Build a DSA public key from explicit (p, q, g, y) big-endian
 * unsigned magnitudes.
 */
int32_t dsa_make_public_from_components(key_spec *spec,
                                        const uint8_t *p_be, size_t p_len,
                                        const uint8_t *q_be, size_t q_len,
                                        const uint8_t *g_be, size_t g_len,
                                        const uint8_t *y_be, size_t y_len);


// =============================================================
// Sign / verify session
// =============================================================

typedef struct dsa_ctx {
    EVP_MD_CTX *digest_ctx;
    int opp;            // DSA_OP_SIGN | DSA_OP_VERIFY
    // Raw DSA ("NoneWithDSA", digest name "NONE") session state: the
    // caller supplies an already-computed digest, which is buffered and
    // signed/verified one-shot via EVP_PKEY_sign/EVP_PKEY_verify (no EVP_MD).
    // Mutually exclusive with digest_ctx — exactly one is set after init.
    EVP_PKEY_CTX *raw_pctx;
    uint8_t *raw_buf;
    size_t raw_buf_len;
    size_t raw_buf_cap;
} dsa_ctx;

dsa_ctx *dsa_ctx_create(int32_t *err);

void dsa_ctx_destroy(dsa_ctx *ctx);

/*
 * Initialise for DSA signing.
 *   digest_name: OpenSSL EVP_MD name ("SHA-256", "SHA3-256", etc.), or
 *                "NONE" for the raw pre-hashed path. MUST be non-NULL.
 *   rnd_src:     RandSource. Required — DSA produces a random
 *                per-signature nonce k.
 */
int32_t dsa_ctx_init_sign(dsa_ctx *ctx, const key_spec *key,
                          const char *digest_name,
                          void *rnd_src);

int32_t dsa_ctx_init_verify(dsa_ctx *ctx, const key_spec *key,
                            const char *digest_name);

int32_t dsa_ctx_update(dsa_ctx *ctx, const uint8_t *in, size_t in_len);

/*
 * Two-call protocol: first call with out=NULL returns the required
 * signature length (an upper bound — DER-encoded DSA signatures vary
 * in size); second call writes the signature and returns the byte
 * count actually written.
 */
int32_t dsa_ctx_sign(dsa_ctx *ctx, uint8_t *out, size_t out_len,
                     void *rnd_src);

/*
 * Returns JO_SUCCESS for a valid signature, JO_FAIL for an invalid one,
 * or a negative error code for a structurally-broken call.
 *
 *   rnd_src: RandSource. DSA verification does not currently consume
 *            RAND inside OpenSSL, but the upcall is bound anyway so a
 *            future OpenSSL that adds verify-side blinding (as EC has)
 *            cannot silently read stale thread-local entropy state.
 */
int32_t dsa_ctx_verify(dsa_ctx *ctx, const uint8_t *sig, size_t sig_len,
                       void *rnd_src);


#endif // DSA_H
