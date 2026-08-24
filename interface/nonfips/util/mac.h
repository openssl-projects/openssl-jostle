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

typedef struct jo_mac_ctx
{
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    char *mac_name;
    char *function_name;
    uint8_t *key;
    size_t key_len;
    // GMAC's nonce; NULL for every other arm. Retained for the lifetime of the
    // ctx because mac_reset re-inits from held state, and a GMAC ctx cannot be
    // restored by a NULL-key/NULL-param re-init - measured, see
    // fips-c-review/probes/gmac_probe.c Q8.
    uint8_t *iv;
    size_t iv_len;
    // KMAC's customisation string S; NULL for every other arm. Retained for
    // the same reason as the IV - mac_reset re-inits from held state. A NULL S
    // is not distinguishable from an empty one by KMAC itself (measured, see
    // fips-c-review/probes/kmac_probe.c Q8), so no separate "was it set"
    // flag is needed.
    uint8_t *custom;
    size_t custom_len;
    // KMAC's requested output length in bytes. 0 means "the caller did not ask
    // for a length", in which case OSSL_MAC_PARAM_SIZE is NOT set and the
    // module's own default (32 for KMAC-128, 64 for KMAC-256) applies.
    //
    // 0 can never be forwarded to OpenSSL as a real request: three of the four
    // measured environments ACCEPT size=0 and then produce a ZERO-LENGTH MAC -
    // a tag equal to every other zero-length tag (kmac_probe.c Q5). Leaving the
    // param unset is what makes the sentinel safe.
    size_t out_len;
    int initialized;
} mac_ctx;


mac_ctx *allocate_mac(const char *mac_name, const char *function, int32_t *err);
mac_ctx *mac_copy(const mac_ctx *src, int32_t *err);

// iv/iv_len carry GMAC's nonce; custom/custom_len and out_len carry KMAC's
// customisation string and requested output length. Every other MAC passes
// NULL/0 for all of them.
//
// A NULL iv or custom is legitimate here rather than a bridge-level rejection,
// because only the per-MAC arm in init_mac_ctx knows whether this MAC needs
// one - and conversely, supplying one to an arm that takes none is rejected
// there (JO_MODE_TAKES_NO_IV / JO_MAC_TAKES_NO_CUSTOM) rather than ignored.
int32_t mac_init(mac_ctx *mctx, const uint8_t *key, size_t key_len,
                 const uint8_t *iv, size_t iv_len,
                 const uint8_t *custom, size_t custom_len, size_t out_len);
int32_t mac_update(mac_ctx *ctx, const uint8_t *in, int32_t off, int32_t len);
int32_t mac_final(mac_ctx *ctx, uint8_t *out, int32_t off, int32_t out_len);
int32_t mac_len(mac_ctx *ctx);
int32_t mac_len_for(mac_ctx *ctx);

int32_t mac_reset(mac_ctx *ctx);
void mac_free(mac_ctx *ctx);

#endif
