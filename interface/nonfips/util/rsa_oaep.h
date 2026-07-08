//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef RSA_OAEP_H
#define RSA_OAEP_H

#include <stdint.h>
#include <openssl/evp.h>

#include "key_spec.h"


// Operation modes — stable across the FFI/JNI boundary; do NOT
// renumber. Map to JCE Cipher.ENCRYPT_MODE / DECRYPT_MODE on the
// Java side.
#define RSA_OAEP_OP_ENCRYPT 1
#define RSA_OAEP_OP_DECRYPT 2


/*
 * Asymmetric cipher state carrying a configured EVP_PKEY_CTX.
 *
 * OAEP is a one-shot operation in the JCE: update() buffers, doFinal()
 * runs the operation. The native side mirrors that — init configures
 * the ctx, dofinal performs the encrypt or decrypt in a single
 * EVP_PKEY_{encrypt,decrypt} call.
 */
typedef struct rsa_oaep_ctx {
    EVP_PKEY_CTX *pctx;
    int op_mode;        // RSA_OAEP_OP_*
} rsa_oaep_ctx;


rsa_oaep_ctx *rsa_oaep_ctx_create(int32_t *err);

void rsa_oaep_ctx_destroy(rsa_oaep_ctx *ctx);


/*
 * Configure the context for OAEP encrypt or decrypt.
 *
 *   op_mode:        RSA_OAEP_OP_ENCRYPT or RSA_OAEP_OP_DECRYPT.
 *   oaep_md_name:   OpenSSL EVP_MD name for the OAEP hash
 *                   ("SHA-1", "SHA-256", etc.).
 *   mgf1_md_name:   MGF1 hash name. NULL means "use the same hash
 *                   as oaep_md_name" — the modern safe default.
 *   label:          optional OAEP label bytes (PKCS#1 v2.2 L). May
 *                   be NULL with label_len = 0 for the empty label.
 *   label_len:      bytes in label.
 *   rnd_src:        Java RandSource handle. Required for encrypt
 *                   (OAEP consumes entropy for the seed); ignored
 *                   for decrypt.
 *
 * The label, if provided, is copied into the EVP_PKEY_CTX via
 * EVP_PKEY_CTX_set0_rsa_oaep_label, which transfers ownership to
 * OpenSSL. The caller's buffer is no longer referenced after init.
 */
int32_t rsa_oaep_init(rsa_oaep_ctx *ctx, const key_spec *key,
                      int32_t op_mode,
                      const char *oaep_md_name,
                      const char *mgf1_md_name,
                      const uint8_t *label, size_t label_len,
                      void *rnd_src);


/*
 * Execute the encrypt or decrypt configured by rsa_oaep_init.
 *
 * Two-call protocol: first call with out=NULL returns the required
 * output buffer length; second call with a sufficiently-large buffer
 * writes the result and returns the byte count.
 */
int32_t rsa_oaep_dofinal(rsa_oaep_ctx *ctx,
                         const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_len,
                         void *rnd_src);


#endif // RSA_OAEP_H
