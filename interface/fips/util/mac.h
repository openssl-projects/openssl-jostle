//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef JOSTLE_MAC_H
#define JOSTLE_MAC_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/types.h>

#define MAC_CTX_KIND 0x4D414301u   /* "MAC\1" */
#define MAC_CTX_NONE 0u            /* what a freed ctx is left with; never a valid kind */

typedef struct jo_mac_ctx
{
    uint32_t kind;
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    char *mac_name;
    char *function_name;
    uint8_t *key;
    size_t key_len;
    // GMAC's nonce, NULL otherwise; held because mac_reset re-inits from held state.
    uint8_t *iv;
    size_t iv_len;
    // KMAC's customisation string, NULL otherwise; held for mac_reset. KMAC treats NULL and empty alike.
    uint8_t *custom;
    size_t custom_len;
    // KMAC's output length in bytes; 0 leaves OpenSSL's default, which a forwarded 0 would replace with no output.
    size_t out_len;
    int initialized;
} mac_ctx;


mac_ctx *allocate_mac(const char *mac_name, const char *function, int32_t *err);
mac_ctx *mac_copy(const mac_ctx *src, int32_t *err);

/*
 * JO_MAC_CTX_IS_NULL, JO_MAC_CTX_WRONG_KIND or JO_SUCCESS; reads only the kind.
 */
int32_t mac_ctx_check(const mac_ctx *ctx);

// iv carries GMAC's nonce; custom and out_len carry KMAC's customisation string and output length. Each is NULL
// or 0 for a MAC that takes none; init_mac_ctx refuses one supplied to a MAC that does not take it.
int32_t mac_init(mac_ctx *mctx, const uint8_t *key, size_t key_len,
                 const uint8_t *iv, size_t iv_len,
                 const uint8_t *custom, size_t custom_len, size_t out_len);
int32_t mac_update(mac_ctx *ctx, const uint8_t *in, int32_t off, int32_t len);
int32_t mac_final(mac_ctx *ctx, uint8_t *out, int32_t off, int32_t out_len);
int32_t mac_len(mac_ctx *ctx);
int32_t mac_len_for(mac_ctx *ctx);

int32_t mac_reset(mac_ctx *ctx);

/*
 * Frees nothing unless mac_ctx_check passes.
 */
void mac_free(mac_ctx *ctx);

#endif
