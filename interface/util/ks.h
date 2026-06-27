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
#include <openssl/x509.h>

typedef struct ks_entry_st {
    char *alias;
    EVP_PKEY *key;
    uint8_t *key_password;
    size_t key_password_len;
    STACK_OF(X509) *certificate_chain;
    int certificate_entry;
    int64_t creation_time;
    struct ks_entry_st *next;
} ks_entry;

typedef struct ks_ctx_st {
    char *type;
    ks_entry *entries;
} ks_ctx;

/*
 * Store-time algorithm profile selectors. These are Jostle-level intents
 * chosen by the SPI per registered KeyStore type name; ks.c maps them to
 * concrete OpenSSL algorithms. They are policy inputs we choose (not values
 * queried from OpenSSL), so an enum here is correct, not a transcribed table.
 */
typedef enum ks_pbe_alg_e {
    KS_PBE_NONE = 0,          /* no encryption (cert safe only)          */
    KS_PBE_3DES = 1,          /* PBES1 pbeWithSHAAnd3-KeyTripleDES-CBC    */
    KS_PBE_AES_128_CBC = 2,   /* PBES2 PBKDF2(HMAC-SHA256) + AES-128-CBC  */
    KS_PBE_AES_256_CBC = 3,   /* PBES2 PBKDF2(HMAC-SHA256) + AES-256-CBC  */
    KS_PBE_AES_128_GCM = 4,   /* PBES2 PBKDF2(HMAC-SHA256) + AES-128-GCM  */
    KS_PBE_AES_256_GCM = 5    /* PBES2 PBKDF2(HMAC-SHA256) + AES-256-GCM  */
} ks_pbe_alg;

typedef enum ks_mac_scheme_e {
    KS_MAC_NONE = 0,          /* no integrity MAC (e.g. AES-GCM content)  */
    KS_MAC_TRADITIONAL = 1,   /* classic PKCS#12 MAC (PKCS12_set_mac)     */
    KS_MAC_PBMAC1 = 2         /* RFC 9579 PBMAC1 (PBKDF2 + HMAC)          */
} ks_mac_scheme;

typedef enum ks_md_e {
    KS_MD_SHA1 = 1,
    KS_MD_SHA256 = 2,
    KS_MD_SHA512 = 3
} ks_md;

ks_ctx *ks_allocate(const char *type, int32_t *err);

void ks_free(ks_ctx *ctx);

int32_t ks_load(ks_ctx *ctx, const uint8_t *input, size_t input_len,
                const uint8_t *password, size_t password_len);

int32_t ks_store(ks_ctx *ctx, uint8_t **out, size_t *out_len,
                 const uint8_t *password, size_t password_len,
                 int32_t key_pbe, int32_t cert_pbe, int32_t mac_scheme,
                 int32_t mac_digest, int32_t pbe_iter, int32_t mac_iter);

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
