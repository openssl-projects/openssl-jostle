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


// Operation modes — stable across the FFI/JNI boundary; do NOT
// renumber. Map to JCE Cipher.ENCRYPT_MODE / DECRYPT_MODE on the
// Java side. Mirror the rsa_oaep.h values for consistency.
#define RSA_PKCS1_OP_ENCRYPT 1
#define RSA_PKCS1_OP_DECRYPT 2


/*
 * Asymmetric cipher state for PKCS#1 v1.5 encryption (RFC 8017
 * RSAES-PKCS1-v1_5). Carries a configured EVP_PKEY_CTX whose lifetime
 * is bound to this struct.
 *
 * <p>PKCS#1 v1.5 encryption is structurally vulnerable to
 * Bleichenbacher-style padding-oracle attacks. OpenSSL 3.x mitigates
 * this by enabling implicit rejection by default — the decryptor
 * emits a deterministic-length pseudo-random plaintext on padding
 * failure rather than signalling the failure. This struct relies on
 * the OpenSSL default; we do not toggle the implicit-rejection flag.
 */
typedef struct rsa_pkcs1_ctx {
    EVP_PKEY_CTX *pctx;
    int op_mode;        // RSA_PKCS1_OP_*
} rsa_pkcs1_ctx;


rsa_pkcs1_ctx *rsa_pkcs1_ctx_create(int32_t *err);

void rsa_pkcs1_ctx_destroy(rsa_pkcs1_ctx *ctx);


/*
 * Configure the context for PKCS#1 v1.5 encrypt or decrypt.
 *
 *   op_mode:  RSA_PKCS1_OP_ENCRYPT or RSA_PKCS1_OP_DECRYPT.
 *   rnd_src:  Java RandSource handle. Required for both directions —
 *             encrypt uses entropy for the PS padding bytes, decrypt
 *             uses entropy for RSA blinding (timing-channel countermeasure).
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
