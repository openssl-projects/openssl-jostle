//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef RSA_PKCS1_H
#define RSA_PKCS1_H

#include <stdint.h>
#include <openssl/evp.h>

#include "key_spec.h"


// Operation modes — stable across the FFM/JNI boundary; do NOT
// renumber. Map to JCE Cipher.ENCRYPT_MODE / DECRYPT_MODE on the
// Java side. Mirror the rsa_oaep.h values for consistency.
#define RSA_PKCS1_OP_ENCRYPT 1
#define RSA_PKCS1_OP_DECRYPT 2
#define RSA_PKCS1_OP_NONE 0         /* no session: what a dropped or never-made session leaves */


/*
 * Asymmetric cipher state for PKCS#1 v1.5 encryption (RFC 8017
 * RSAES-PKCS1-v1_5). Carries a configured EVP_PKEY_CTX whose lifetime
 * is bound to this struct.
 *
 * <p>PKCS#1 v1.5 encryption is structurally vulnerable to
 * Bleichenbacher-style padding-oracle attacks. OpenSSL's RSA provider
 * mitigates this with "implicit rejection": a decrypt of malformed
 * PKCS#1 v1.5 padding returns a deterministic synthetic plaintext
 * instead of signalling failure. rsa_pkcs1_init does NOT merely rely
 * on the default — for a DECRYPT session it capability-probes the
 * provider for OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION (which
 * entered OpenSSL 3.2; the FIPS-validated 3.1.x module lacks it),
 * fails loud with JO_IMPLICIT_REJECTION_UNAVAILABLE when the parameter
 * is absent, and otherwise pins the value to 1 explicitly. See the
 * block comment in rsa_pkcs1_init (rsa_pkcs1.c) for the full contract.
 */
/*
 * A non-trivial magic, neither 0 nor 1, so freed or cleared memory does not read as an rsa_pkcs1_ctx.
 * First field, so a handle to another object is refused before anything past its first word is read.
 */
#define RSA_PKCS1_CTX_KIND 0x52503101u /* "RP1\1" */
#define RSA_PKCS1_CTX_NONE 0u          /* what a freed ctx is left with; never a valid kind */

typedef struct rsa_pkcs1_ctx {
    uint32_t kind;
    EVP_PKEY_CTX *pctx;
    int op_mode;        // RSA_PKCS1_OP_*
} rsa_pkcs1_ctx;


rsa_pkcs1_ctx *rsa_pkcs1_ctx_create(int32_t *err);

/*
 * JO_CIPHER_CTX_IS_NULL, JO_RSA_PKCS1_CTX_WRONG_KIND or JO_SUCCESS; reads only the kind.
 */
int32_t rsa_pkcs1_ctx_check(const rsa_pkcs1_ctx *ctx);

/* Frees nothing unless ctx is a live rsa_pkcs1_ctx. */
void rsa_pkcs1_ctx_destroy(rsa_pkcs1_ctx *ctx);


/*
 * Configure the context for PKCS#1 v1.5 encrypt or decrypt.
 *
 *   op_mode:  RSA_PKCS1_OP_ENCRYPT or RSA_PKCS1_OP_DECRYPT.
 *   rnd_src:  Java RandSource handle, checked by the bridges. Encrypt
 *             uses entropy for the PS padding bytes, decrypt for RSA
 *             blinding (timing-channel countermeasure).
 *
 * Any previous session is dropped first, so a refused re-init leaves
 * the ctx uninitialised.
 */
int32_t rsa_pkcs1_init(rsa_pkcs1_ctx *ctx, const key_spec *key,
                       int32_t op_mode,
                       void *rnd_src);


/*
 * Two-call protocol: first call with out=NULL returns the required
 * output buffer length; second call with a sufficiently-large buffer
 * writes the result and returns the byte count.
 */
int32_t rsa_pkcs1_dofinal(rsa_pkcs1_ctx *ctx,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_len,
                          void *rnd_src);


#endif // RSA_PKCS1_H
