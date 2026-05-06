//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef RSA_H
#define RSA_H
#include <stdint.h>

#include "key_spec.h"

// Sign / verify operation flags (analogous to EDEC_SIGN / EDEC_VERIFY).
#define RSA_OP_SIGN 1
#define RSA_OP_VERIFY 2

// Padding modes. These are stable identifiers across the FFI/JNI
// boundary — do NOT renumber. Map to OpenSSL's RSA_PKCS1_PADDING /
// RSA_PKCS1_PSS_PADDING inside rsa.c.
#define RSA_PADDING_PKCS1 1
#define RSA_PADDING_PSS   2

// Component selectors for rsa_get_component(). Stable identifiers
// across the FFI/JNI boundary — do NOT renumber.
#define RSA_COMP_MODULUS          0
#define RSA_COMP_PUBLIC_EXPONENT  1
#define RSA_COMP_PRIVATE_EXPONENT 2
#define RSA_COMP_PRIME_P          3
#define RSA_COMP_PRIME_Q          4
#define RSA_COMP_EXPONENT_P       5  // d mod (p - 1)
#define RSA_COMP_EXPONENT_Q       6  // d mod (q - 1)
#define RSA_COMP_CRT_COEFFICIENT  7  // q^-1 mod p


typedef struct rsa_ctx {
    EVP_MD_CTX *digest_ctx;
    int opp;            // RSA_OP_SIGN | RSA_OP_VERIFY
    int padding_mode;   // RSA_PADDING_*
} rsa_ctx;


// =============================================================
// Key generation and decoding
// =============================================================

/*
 * Generate an RSA keypair.
 *
 * `pubexp` is a big-endian byte representation of the desired public
 * exponent. The Java SPI rejects values < 3 before this function is
 * called; OpenSSL itself will reject pathological values during keygen
 * (returned as JO_OPENSSL_ERROR).
 */
int32_t rsa_generate_key(key_spec *spec, int32_t bits,
                         const uint8_t *pubexp, size_t pubexp_len,
                         void *rnd_src);


/*
 * Note: PKCS#8 / SubjectPublicKeyInfo encoded-form encoding and
 * decoding for RSA are handled by the existing generic ASN.1 layer
 * in asn1_util.c (asn1_writer_decode_*_key / asn1_writer_encode_*_key).
 * Those entry points work for any EVP_PKEY type including RSA, so no
 * RSA-specific encoded-form functions are needed here. KeyFactorySpi's
 * X.509/PKCS#8 paths route through ASNEncoder on the Java side.
 */


/*
 * Big-integer component decoding for KeyFactorySpi's per-component
 * specs. Each component is a big-endian byte sequence; leading zero
 * stripping by the caller is permitted.
 */

// RSAPublicKeySpec(modulus, publicExponent).
int32_t rsa_decode_public_components(key_spec *spec,
                                     const uint8_t *n, size_t n_len,
                                     const uint8_t *e, size_t e_len);

/*
 * RSAPrivateKeySpec(modulus, privateExponent). Public exponent is
 * required because OpenSSL's RSA provider needs it to construct the
 * EVP_PKEY; callers that lack the public exponent should fail at the
 * Java SPI layer with InvalidKeySpecException.
 */
int32_t rsa_decode_private_components(key_spec *spec,
                                      const uint8_t *n, size_t n_len,
                                      const uint8_t *e, size_t e_len,
                                      const uint8_t *d, size_t d_len);

/*
 * RSAPrivateCrtKeySpec — full eight-component form. Required for
 * RSAPrivateCrtKey.getPrime{P,Q}() / getPrimeExponent{P,Q}() /
 * getCrtCoefficient() to return non-null on the resulting key.
 */
int32_t rsa_decode_private_components_crt(key_spec *spec,
                                          const uint8_t *n, size_t n_len,
                                          const uint8_t *e, size_t e_len,
                                          const uint8_t *d, size_t d_len,
                                          const uint8_t *p, size_t p_len,
                                          const uint8_t *q, size_t q_len,
                                          const uint8_t *dp, size_t dp_len,
                                          const uint8_t *dq, size_t dq_len,
                                          const uint8_t *qinv, size_t qinv_len);


/*
 * Component getter — single entry for all eight RSA_COMP_*. Returns
 * the required big-endian byte length when out=NULL or out_len=0;
 * otherwise copies the component into out and returns the byte count.
 *
 * Returns a negative error code if the component is absent (e.g. CRT
 * components on a private key constructed from RSAPrivateKeySpec
 * without OpenSSL deriving them, or any private-only component on a
 * public key). Callers that surface RSAPrivateCrtKey via the JCE must
 * map "absent" to null per the JCA contract — a negative return here
 * is the signal to do so.
 */
int32_t rsa_get_component(const key_spec *spec, int32_t component,
                          uint8_t *out, size_t out_len);


// =============================================================
// Sign / verify session
// =============================================================

rsa_ctx *rsa_ctx_create(int32_t *err);

void rsa_ctx_destroy(rsa_ctx *ctx);

/*
 * Initialise for signing.
 *
 *   digest_name:    OpenSSL EVP_MD name ("SHA-256", "SHA-384",
 *                   "SHA3-256", etc.).
 *   padding_mode:   RSA_PADDING_PKCS1 or RSA_PADDING_PSS.
 *   mgf1_md_name:   PSS only. NULL means "use the same hash as
 *                   digest_name" (the modern safe default — the
 *                   Java SPI passes NULL when PSSParameterSpec did
 *                   not specify an MGF). Ignored for PKCS#1 v1.5.
 *   salt_len:       PSS only. A negative value means "use the
 *                   digest output length" (RSA_PSS_SALTLEN_DIGEST).
 *                   Ignored for PKCS#1 v1.5.
 *   rnd_src:        passed to rand_set_java_srand_call before
 *                   any OpenSSL call that may consume entropy
 *                   (PSS salt generation).
 */
int32_t rsa_ctx_init_sign(rsa_ctx *ctx, const key_spec *key,
                          const char *digest_name,
                          int32_t padding_mode,
                          const char *mgf1_md_name,
                          int32_t salt_len,
                          void *rnd_src);

/*
 * Initialise for verifying. Same parameter semantics as init_sign
 * minus rnd_src — verify does not consume entropy.
 */
int32_t rsa_ctx_init_verify(rsa_ctx *ctx, const key_spec *key,
                            const char *digest_name,
                            int32_t padding_mode,
                            const char *mgf1_md_name,
                            int32_t salt_len);

int32_t rsa_ctx_update(rsa_ctx *ctx, const uint8_t *in, size_t in_len);

/*
 * Two-call protocol: first call with out=NULL (or out_len=0) returns
 * the required signature length; second call with a sufficiently-
 * large buffer writes the signature and returns the byte count.
 */
int32_t rsa_ctx_sign(rsa_ctx *ctx, uint8_t *out, size_t out_len,
                     void *rnd_src);

/*
 * Returns JO_SUCCESS for a valid signature, JO_FAIL for an invalid
 * one (per the existing EdDSA convention), or a negative error code
 * for a structurally-broken call.
 */
int32_t rsa_ctx_verify(rsa_ctx *ctx, const uint8_t *sig, size_t sig_len);


#endif //RSA_H
