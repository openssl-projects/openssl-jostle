//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef DH_H
#define DH_H
#include <stdint.h>

#include <openssl/evp.h>

#include "key_spec.h"

// Component selectors for dh_get_component(). Stable identifiers
// across the FFI/JNI boundary — do NOT renumber.
#define DH_COMP_P              0   // FFC prime modulus p
#define DH_COMP_Q              1   // FFC subgroup order q (absent on PKCS#3 keys)
#define DH_COMP_G              2   // FFC generator g
#define DH_COMP_PUBLIC_VALUE   3   // public value y = g^x mod p
#define DH_COMP_PRIVATE_VALUE  4   // private value x


// =============================================================
// Group introspection
// =============================================================

/*
 * Probe whether the loaded OpenSSL provider chain recognises the given
 * DH group name (RFC 7919 "ffdhe2048" … "ffdhe8192", RFC 3526
 * "modp_1536" … "modp_8192"). Returns 1 if a full paramgen succeeds for
 * the name, 0 otherwise. Mirrors ec_curve_supported — OpenSSL is the
 * source of truth for supported groups; the error queue is purged
 * before returning.
 */
int32_t dh_group_supported(const char *group_name);


// =============================================================
// Key generation
// =============================================================

/*
 * Generate a DH keypair on the named group (e.g. "ffdhe2048"). The
 * resulting EVP_PKEY is written into spec->key. Returns JO_SUCCESS or
 * a negative error code; on failure spec->key is left NULL.
 *
 *   group_name: OpenSSL DH group name. MUST be non-NULL. Callers
 *               SHOULD pre-validate via dh_group_supported().
 *   rnd_src:    RandSource for keygen entropy. MUST be non-NULL.
 */
int32_t dh_generate_key_by_group(key_spec *spec, const char *group_name,
                                 void *rnd_src);

/*
 * Generate a DH keypair from previously-established domain parameters
 * (a spec produced by dh_generate_parameters or
 * dh_make_params_from_components).
 */
int32_t dh_generate_key(key_spec *spec, const key_spec *params,
                        void *rnd_src);


// =============================================================
// Domain-parameter generation / construction
// =============================================================

/*
 * Generate PKCS#3-style DH domain parameters (safe prime p, generator
 * g) of the requested modulus length. This is a safe-prime search —
 * slow at 2048 bits and above; the named-group keygen path is the
 * modern alternative. The Java SPI applies the policy bounds; the
 * bridge backstop rejects p_bits <= 0.
 */
int32_t dh_generate_parameters(key_spec *spec, int32_t p_bits,
                               void *rnd_src);

/*
 * Build a parameters-only DH EVP_PKEY from explicit (p, g) big-endian
 * unsigned magnitudes via EVP_PKEY_fromdata. PKCS#3 DH has no q.
 */
int32_t dh_make_params_from_components(key_spec *spec,
                                       const uint8_t *p_be, size_t p_len,
                                       const uint8_t *g_be, size_t g_len);


// =============================================================
// Component getter / component-form key construction
// =============================================================

/*
 * Fetch a single BIGNUM component from a DH EVP_PKEY as big-endian
 * unsigned magnitude. Two-call protocol matching dsa_get_component.
 * Returns a negative error code if the component is absent (e.g.
 * DH_COMP_Q on a PKCS#3 key, or DH_COMP_PRIVATE_VALUE on a public key).
 */
int32_t dh_get_component(const key_spec *spec, int32_t component,
                         uint8_t *out, size_t out_len);

/*
 * Build a DH private key from explicit (p, g, x) big-endian unsigned
 * magnitudes. The public value y = g^x mod p is computed here
 * (constant-time modular exponentiation) because OpenSSL's FFC
 * fromdata import does not re-derive it.
 *
 *   rnd_src: RandSource. Conservatively required so any RAND
 *            consumption inside the OpenSSL import path can up-call
 *            for entropy (mirrors dsa_make_private_from_components).
 */
int32_t dh_make_private_from_components(key_spec *spec,
                                        const uint8_t *p_be, size_t p_len,
                                        const uint8_t *g_be, size_t g_len,
                                        const uint8_t *x_be, size_t x_len,
                                        void *rnd_src);

/*
 * Build a DH public key from explicit (p, g, y) big-endian unsigned
 * magnitudes.
 */
int32_t dh_make_public_from_components(key_spec *spec,
                                       const uint8_t *p_be, size_t p_len,
                                       const uint8_t *g_be, size_t g_len,
                                       const uint8_t *y_be, size_t y_len);


// =============================================================
// Key agreement
// =============================================================

/*
 * Per-instance state for a DH KeyAgreement. Mirrors ec_kex_ctx, but
 * DH-typed: the type gate is "DH"/"DHX" and the derive context is
 * configured with the padded-output exchange parameter (see
 * dh_kex_init).
 */
typedef struct dh_kex_ctx {
    EVP_PKEY_CTX *pctx;     // owned
    int peer_set;           // 0 until dh_kex_set_peer succeeds
} dh_kex_ctx;

dh_kex_ctx *dh_kex_create(int32_t *err);

void dh_kex_destroy(dh_kex_ctx *ctx);

/*
 * Initialise the kex ctx with the local DH private key. Replaces any
 * prior state (call again to reuse the ctx with a different key).
 *
 * SECURITY-RELEVANT PARAMETER (do not change): the derive context is
 * configured with OSSL_EXCHANGE_PARAM_PAD = 1, so the shared secret is
 * returned left-padded to the prime length rather than with leading
 * zeros stripped (OpenSSL's default). BouncyCastle's JCE DH agreement
 * returns p-length output and TLS 1.3 FFDHE (RFC 8446 §7.4.1) requires
 * padded secrets; an unpadded secret diverges from both on ~1 in 256
 * derivations — a classic intermittent-interop bug. The hard-guard
 * test DHKeyAgreementTest.testDh_SharedSecretPadding_HardGuard exists
 * to catch removal of this parameter.
 *
 *   rnd_src: RandSource. Bound for parity with the EC kex surface so
 *            any RAND consumption inside the derive path resolves to
 *            fresh Java entropy.
 */
int32_t dh_kex_init(dh_kex_ctx *ctx, const key_spec *my_priv,
                    void *rnd_src);

/*
 * Bind the peer public key. Must be called after dh_kex_init and
 * before dh_kex_derive. OpenSSL's EVP_PKEY_derive_set_peer enforces
 * group equality between the local and peer keys; a mismatch surfaces
 * as JO_OPENSSL_ERROR, which the Java SPI translates to
 * InvalidKeyException at doPhase().
 */
int32_t dh_kex_set_peer(dh_kex_ctx *ctx, const key_spec *peer_pub,
                        void *rnd_src);

/*
 * Two-call protocol:
 *   - first call with out=NULL (or out_len=0) returns the required
 *     length (the prime length, because of the pad parameter);
 *   - second call with a sufficiently-large buffer writes the shared
 *     secret and returns the byte count actually written.
 */
int32_t dh_kex_derive(dh_kex_ctx *ctx, uint8_t *out, size_t out_len,
                      void *rnd_src);


#endif // DH_H
