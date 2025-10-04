//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef ASN1_UTIL_H
#define ASN1_UTIL_H
#include <openssl/types.h>

#include "key_spec.h"


typedef struct asn1_ctx {
    BIO *buffer;
} asn1_ctx;


asn1_ctx *asn1_writer_allocate(void);

void asn1_writer_free(asn1_ctx *ctx);

/**
 * Copy buffered output/
 * @param ctx  the ctx
 * @param data the data, set null to return length only
 * @param written amount written
 * @param output_len absolute max_len of output buffer
 *
 */
int32_t asn1_writer_get_content(asn1_ctx *ctx, uint8_t *output, size_t *written, const size_t output_len);


/**
 * Encode a public key into a SubjectPublicKeyInfo structure
 * @param ctx the ctx
 * @param key_spec the key spec
 * @param buf_len receiver for the length of data in the buffer
 *
 * @return 1 = success, 0 = failure
 */
int32_t asn1_writer_encode_public_key(asn1_ctx *ctx, key_spec *key_spec, size_t *buf_len);

/**
 * Encode a private key into a PrivateKeyInfo structure
 * @param ctx the ctx
 * @param key_spec the key spec
 * @param buf_len receiver for the length of data in the buffer
 *
 * @return 1 = success, 0 = failure
 */
int32_t asn1_writer_encode_private_key(asn1_ctx *ctx, key_spec *key_spec, size_t *buf_len);


/**
 * Decodes an encoded PrivateKeyInfo structure
 * @param src the source
 * @param src_len  the source length
 * @param ret_code receiver for the return code
 * @return a pointer to a key_spec, ownership is the callers
 */
key_spec *asn1_writer_decode_private_key(const uint8_t *src, size_t src_len, int32_t *ret_code);

/**
 * Decodes an encoded PublicKeyInfo structure
 * @param src the source
 * @param src_len  the length
 * @param ret_code receiver for error code
 * @return a new key_spec, ownership is the callers
 */
key_spec *asn1_writer_decode_public_key(const uint8_t *src, size_t src_len, int32_t *ret_code);


#endif //ASN1_UTIL_H
