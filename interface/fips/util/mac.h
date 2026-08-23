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
    int initialized;
} mac_ctx;


mac_ctx *allocate_mac(const char *mac_name, const char *function, int32_t *err);
mac_ctx *mac_copy(const mac_ctx *src, int32_t *err);

// iv/iv_len carry GMAC's nonce; every other MAC passes NULL/0. A NULL iv is
// legitimate here rather than a bridge-level rejection, because only the
// per-MAC arm in init_mac_ctx knows whether this MAC needs one.
int32_t mac_init(mac_ctx *mctx, const uint8_t *key, size_t key_len,
                 const uint8_t *iv, size_t iv_len);
int32_t mac_update(mac_ctx *ctx, const uint8_t *in, int32_t off, int32_t len);
int32_t mac_final(mac_ctx *ctx, uint8_t *out, int32_t off, int32_t out_len);
int32_t mac_len(mac_ctx *ctx);
int32_t mac_len_for(mac_ctx *ctx);

int32_t mac_reset(mac_ctx *ctx);
void mac_free(mac_ctx *ctx);

#endif
