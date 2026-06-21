//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef KS_H
#define KS_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/types.h>

typedef struct ks_entry_st {
    char *alias;
    EVP_PKEY *key;
    uint8_t *key_password;
    size_t key_password_len;
    uint8_t *certificate_chain;
    size_t certificate_chain_len;
    int certificate_entry;
    int64_t creation_time;
    struct ks_entry_st *next;
} ks_entry;

typedef struct ks_ctx_st {
    char *type;
    ks_entry *entries;
} ks_ctx;

ks_ctx *ks_allocate(const char *type, int32_t *err);

void ks_free(ks_ctx *ctx);

int32_t ks_load(ks_ctx *ctx, const uint8_t *input, size_t input_len,
                const uint8_t *password, size_t password_len);

int32_t ks_store(ks_ctx *ctx, uint8_t **out, size_t *out_len,
                 const uint8_t *password, size_t password_len);

int32_t ks_get_key(ks_ctx *ctx, const char *alias, uint8_t **out, size_t *out_len,
                   const uint8_t *password, size_t password_len);

int32_t ks_set_key(ks_ctx *ctx, const char *alias, const uint8_t *key, size_t key_len,
                   const uint8_t *password, size_t password_len);

int32_t ks_get_certificate_chain(ks_ctx *ctx, const char *alias, uint8_t **out, size_t *out_len);

int32_t ks_set_certificate_chain(ks_ctx *ctx, const char *alias, const uint8_t *chain, size_t chain_len);

int32_t ks_set_certificate_entry(ks_ctx *ctx, const char *alias, const uint8_t *certificate, size_t certificate_len);

int32_t ks_delete_entry(ks_ctx *ctx, const char *alias);

int32_t ks_get_aliases(ks_ctx *ctx, uint8_t **out, size_t *out_len);

int32_t ks_contains_alias(ks_ctx *ctx, const char *alias);

int32_t ks_size(ks_ctx *ctx);

int32_t ks_is_key_entry(ks_ctx *ctx, const char *alias);

int32_t ks_is_certificate_entry(ks_ctx *ctx, const char *alias);

int64_t ks_get_creation_date(ks_ctx *ctx, const char *alias, int32_t *err);

#endif //KS_H
