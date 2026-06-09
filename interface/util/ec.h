//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef EC_H
#define EC_H
#include <stdint.h>

#include "key_spec.h"

// Sign / verify operation flags (analogous to RSA_OP_SIGN / EDEC_SIGN).
#define EC_OP_SIGN 1
#define EC_OP_VERIFY 2

// Component selectors for ec_get_component(). Stable identifiers
// across the FFI/JNI boundary — do NOT renumber.
#define EC_COMP_CURVE_NAME      0   // OpenSSL group name as UTF-8 bytes
#define EC_COMP_PUBLIC_X        1   // affine X coordinate of public point
#define EC_COMP_PUBLIC_Y        2   // affine Y coordinate of public point
#define EC_COMP_PRIVATE_VALUE   3   // private scalar `s`


// =============================================================
// Curve introspection
// =============================================================

/*
 * Probe whether the loaded OpenSSL provider chain recognises the given
 * curve name. Returns 1 if `EVP_PKEY_CTX_set_params` accepts the name
 * for an EC paramgen context, 0 otherwise (including curve_name == NULL).
 *
 * Used by the Java SPI to validate curve names BEFORE attempting keygen,
 * so unknown curves surface as InvalidAlgorithmParameterException with
 * a clear message rather than a generic OpenSSLException from deep in
 * the keygen stack. We rely on OpenSSL as the source of truth for
 * supported curves rather than maintaining our own list.
 *
 * Side-effect: the OpenSSL error queue is purged before returning so
 * a "no such group" entry from a probe doesn't pollute subsequent
 * error reporting.
 */
int32_t ec_curve_supported(const char *curve_name);


// =============================================================
// Key generation
// =============================================================

/*
 * Generate an EC keypair on the named curve. The resulting EVP_PKEY is
 * written into spec->key. Returns JO_SUCCESS on success or a negative
 * error code on failure; on failure spec->key is left NULL.
 *
 *   curve_name: OpenSSL group name (e.g. "secp256r1", "P-256",
 *               "prime256v1" — all aliases for the same curve).
 *               MUST be non-NULL. Invalid names produce JO_OPENSSL_ERROR;
 *               callers SHOULD pre-validate via ec_curve_supported().
 *   rnd_src:    RandSource for keygen entropy. MUST be non-NULL.
 */
int32_t ec_generate_key(key_spec *spec, const char *curve_name,
                        void *rnd_src);


// =============================================================
// Component getter
// =============================================================

/*
 * Fetch a single component from an EC EVP_PKEY:
 *   EC_COMP_CURVE_NAME    — group name as UTF-8 bytes (no NUL terminator)
 *   EC_COMP_PUBLIC_X / Y  — affine coordinate as big-endian unsigned magnitude
 *   EC_COMP_PRIVATE_VALUE — private scalar as big-endian unsigned magnitude
 *
 * Two-call protocol matching rsa_get_component: pass NULL out / 0 out_len
 * to query the required byte length without copying; second call with a
 * sufficiently-large buffer writes the component and returns the byte
 * count.
 *
 * Returns a negative error code if the component is absent (e.g. asking
 * for EC_COMP_PRIVATE_VALUE on a public key). The Java-side getters
 * surface "absent" components per the JCA contract.
 */
int32_t ec_get_component(const key_spec *spec, int32_t component,
                         uint8_t *out, size_t out_len);


/*
 * Build an EC private key from its raw scalar component plus a curve
 * name. {@code spec->key} is set on success; on failure the
 * {@code spec} is left unchanged and an error code is returned.
 *
 *   curve_name: OpenSSL group name (e.g. "P-256"). MUST be non-NULL.
 *               Callers SHOULD pre-validate via ec_curve_supported().
 *   scalar_be:  the private scalar as big-endian unsigned magnitude.
 *               MUST be non-NULL.
 *   scalar_len: number of bytes in scalar_be. MUST be > 0.
 *   rnd_src:    RandSource. Required because OpenSSL re-derives the
 *               public point from the scalar using point-blinded
 *               multiplication, which consumes RAND.
 *
 * The path uses OSSL_PARAM_BLD + EVP_PKEY_fromdata (the OpenSSL 3.x
 * idiom for constructing keys from raw components) rather than the
 * encoded-form decoder, so it doesn't depend on OpenSSL's PKCS#8
 * decoder accepting a foreign provider's emission.
 */
int32_t ec_make_private_from_components(key_spec *spec,
                                        const char *curve_name,
                                        const uint8_t *scalar_be,
                                        size_t scalar_len,
                                        void *rnd_src);


// =============================================================
// Sign / verify session
// =============================================================

typedef struct ec_ctx {
    EVP_MD_CTX *digest_ctx;
    int opp;            // EC_OP_SIGN | EC_OP_VERIFY
    // Raw ECDSA ("NoneWithECDSA", digest name "NONE") session state: the
    // caller supplies an already-computed digest, which is buffered and
    // signed/verified one-shot via EVP_PKEY_sign/EVP_PKEY_verify (no EVP_MD).
    // Mutually exclusive with digest_ctx — exactly one is set after init.
    EVP_PKEY_CTX *raw_pctx;
    uint8_t *raw_buf;
    size_t raw_buf_len;
    size_t raw_buf_cap;
} ec_ctx;

ec_ctx *ec_ctx_create(int32_t *err);

void ec_ctx_destroy(ec_ctx *ctx);

/*
 * Initialise for ECDSA signing.
 *   digest_name: OpenSSL EVP_MD name ("SHA-256", "SHA-384", "SHA3-256", etc.).
 *                MUST be non-NULL.
 *   rnd_src:     RandSource. Required — ECDSA produces a random per-signature
 *                nonce k; OpenSSL also uses RAND for blinding on the private-key
 *                op.
 */
int32_t ec_ctx_init_sign(ec_ctx *ctx, const key_spec *key,
                         const char *digest_name,
                         void *rnd_src);

int32_t ec_ctx_init_verify(ec_ctx *ctx, const key_spec *key,
                           const char *digest_name);

int32_t ec_ctx_update(ec_ctx *ctx, const uint8_t *in, size_t in_len);

/*
 * Two-call protocol: first call with out=NULL (or out_len=0) returns the
 * required signature length; second call with a sufficiently-large
 * buffer writes the signature and returns the byte count actually
 * written. Note that the actual signature length varies (DER-encoded
 * ECDSA signatures are not constant size); the first call returns the
 * upper bound.
 */
int32_t ec_ctx_sign(ec_ctx *ctx, uint8_t *out, size_t out_len,
                    void *rnd_src);

/*
 * Returns JO_SUCCESS for a valid signature, JO_FAIL for an invalid one,
 * or a negative error code for a structurally-broken call.
 *
 *   rnd_src: RandSource for blinding entropy. MUST be non-NULL.
 *            Although verify is a public-key operation, OpenSSL's EC
 *            implementation uses RAND internally for point-blinding as
 *            a side-channel mitigation (ossl_ec_GFp_simple_blind_coordinates).
 *            That RAND consumption flows through Jostle's lib-ctx-bound
 *            RAND provider, which expects a thread-local Java RandSource
 *            installed via rand_set_java_srand_call.
 */
int32_t ec_ctx_verify(ec_ctx *ctx, const uint8_t *sig, size_t sig_len,
                      void *rnd_src);


// =============================================================
// Key agreement (ECDH)
// =============================================================

/*
 * Per-instance state for an ECDH KeyAgreement. The OpenSSL EVP_PKEY_CTX is
 * created fresh from the local private key in ec_kex_init, and the peer
 * public key is bound via ec_kex_set_peer before ec_kex_derive can run.
 */
typedef struct ec_kex_ctx {
    EVP_PKEY_CTX *pctx;     // owned
    int peer_set;           // 0 until ec_kex_set_peer succeeds
} ec_kex_ctx;


/*
 * Allocate an empty kex ctx. Returns NULL on allocation failure (and
 * writes a JO_* code through err).
 */
ec_kex_ctx *ec_kex_create(int32_t *err);

void ec_kex_destroy(ec_kex_ctx *ctx);

/*
 * Initialise the kex ctx with the local EC private key. Replaces any
 * prior state (call again to reuse the ctx with a different key).
 *
 *   rnd_src: RandSource. EVP_PKEY_derive uses RAND internally for point
 *            blinding (the same side-channel mitigation that ECDSA verify
 *            uses), so a non-NULL upcall MUST be installed before
 *            ec_kex_derive runs.
 */
int32_t ec_kex_init(ec_kex_ctx *ctx, const key_spec *my_priv,
                    void *rnd_src);

/*
 * Bind the peer public key. Must be called after ec_kex_init and before
 * ec_kex_derive.
 *
 *   rnd_src: RandSource. Required even though set_peer is logically a
 *            "just hand me the public point" operation — for binary-field
 *            curves OpenSSL's {@code EVP_PKEY_derive_set_peer} runs an
 *            internal {@code EVP_PKEY_public_check} that scalar-multiplies
 *            the peer point with point-blinded multiplication, which
 *            consumes RAND through the lib-ctx-bound provider.
 */
int32_t ec_kex_set_peer(ec_kex_ctx *ctx, const key_spec *peer_pub,
                        void *rnd_src);

/*
 * Two-call protocol:
 *   - first call with out=NULL (or out_len=0) returns the required
 *     length;
 *   - second call with a sufficiently-large buffer writes the shared
 *     secret and returns the byte count actually written.
 *
 * The shared secret is the affine X coordinate of the shared point as
 * big-endian unsigned magnitude (SEC 1 / ANSI X9.63), padded to the
 * curve byte length. Java's KeyAgreement.generateSecret returns these
 * bytes verbatim.
 *
 *   rnd_src: RandSource for the same point-blinding entropy that
 *            ec_ctx_verify needs. Must be non-NULL.
 */
int32_t ec_kex_derive(ec_kex_ctx *ctx, uint8_t *out, size_t out_len,
                      void *rnd_src);


#endif // EC_H
