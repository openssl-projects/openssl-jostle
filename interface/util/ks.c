//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "ks.h"

#include <limits.h>
#include <string.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "asn1_util.h"
#include "bc_err_codes.h"
#include "jo_assert.h"
#include "key_spec.h"

static int supported_type(const char *type) {
    if (type == NULL) {
        return 0;
    }
    return strcmp(type, "PKCS12") == 0
           || strcmp(type, "PKCS#12") == 0
           || strcmp(type, "P12") == 0;
}

static ks_entry *find_entry(ks_ctx *ctx, const char *alias) {
    if (ctx == NULL || alias == NULL) {
        return NULL;
    }

    ks_entry *entry = ctx->entries;
    while (entry != NULL) {
        if (entry->alias != NULL && strcmp(entry->alias, alias) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

static uint32_t read_u32_be(const uint8_t *in) {
    return ((uint32_t) in[0] << 24)
           | ((uint32_t) in[1] << 16)
           | ((uint32_t) in[2] << 8)
           | (uint32_t) in[3];
}

static void write_u32_be(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t) (value >> 24);
    out[1] = (uint8_t) (value >> 16);
    out[2] = (uint8_t) (value >> 8);
    out[3] = (uint8_t) value;
}

static int64_t current_time_ms(void) {
    return (int64_t) time(NULL) * 1000;
}

static char *copy_password(const uint8_t *password, size_t password_len) {
    if (password == NULL || password_len == 0) {
        return NULL;
    }
    if (password_len > INT32_MAX) {
        return NULL;
    }

    char *copy = OPENSSL_zalloc(password_len + 1);
    jo_assert(copy != NULL);
    memcpy(copy, password, password_len);
    return copy;
}

static ks_entry *find_or_create_entry(ks_ctx *ctx, const char *alias) {
    ks_entry *entry = find_entry(ctx, alias);
    if (entry != NULL) {
        return entry;
    }

    entry = OPENSSL_zalloc(sizeof(ks_entry));
    jo_assert(entry != NULL);
    entry->alias = OPENSSL_strdup(alias);
    jo_assert(entry->alias != NULL);
    entry->creation_time = current_time_ms();
    entry->next = ctx->entries;
    ctx->entries = entry;
    return entry;
}

static void clear_certificate_chain(ks_entry *entry) {
    if (entry == NULL || entry->certificate_chain == NULL) {
        return;
    }
    OPENSSL_clear_free(entry->certificate_chain, entry->certificate_chain_len);
    entry->certificate_chain = NULL;
    entry->certificate_chain_len = 0;
}

static void clear_key_password(ks_entry *entry) {
    if (entry == NULL || entry->key_password == NULL) {
        return;
    }
    OPENSSL_clear_free(entry->key_password, entry->key_password_len);
    entry->key_password = NULL;
    entry->key_password_len = 0;
}

static int32_t set_key_password(ks_entry *entry, const uint8_t *password,
                                size_t password_len) {
    jo_assert(entry != NULL);
    jo_assert(password != NULL || password_len == 0);
    jo_assert(password_len <= INT32_MAX);

    uint8_t *copy = NULL;
    if (password_len != 0) {
        copy = OPENSSL_zalloc(password_len);
        jo_assert(copy != NULL);
        memcpy(copy, password, password_len);
    }

    clear_key_password(entry);
    entry->key_password = copy;
    entry->key_password_len = password_len;
    return JO_SUCCESS;
}

static int password_matches(ks_entry *entry, const uint8_t *password,
                            size_t password_len) {
    if (entry == NULL) {
        return 0;
    }
    if (password == NULL && password_len != 0) {
        return 0;
    }
    if (entry->key_password_len != password_len) {
        return 0;
    }
    if (password_len == 0) {
        return 1;
    }
    if (entry->key_password == NULL || password == NULL) {
        return 0;
    }
    return CRYPTO_memcmp(entry->key_password, password, password_len) == 0;
}

static void free_entry(ks_entry *entry) {
    if (entry == NULL) {
        return;
    }
    if (entry->alias != NULL) {
        OPENSSL_clear_free(entry->alias, strlen(entry->alias) + 1);
    }
    EVP_PKEY_free(entry->key);
    clear_key_password(entry);
    clear_certificate_chain(entry);
    OPENSSL_clear_free(entry, sizeof(*entry));
}

static void clear_entries(ks_ctx *ctx) {
    ks_entry *entry = ctx->entries;
    while (entry != NULL) {
        ks_entry *next = entry->next;
        free_entry(entry);
        entry = next;
    }
    ctx->entries = NULL;
}

static void replace_entries(ks_ctx *ctx, ks_ctx *src) {
    clear_entries(ctx);
    ctx->entries = src->entries;
    src->entries = NULL;
}

static void free_x509_stack(STACK_OF(X509) *stack) {
    if (stack != NULL) {
        sk_X509_pop_free(stack, X509_free);
    }
}

static int32_t decode_certificate_chain(const uint8_t *encoded, size_t encoded_len,
                                        X509 **cert, STACK_OF(X509) **ca) {
    *cert = NULL;
    *ca = NULL;

    if (encoded == NULL || encoded_len == 0) {
        return JO_SUCCESS;
    }
    if (encoded_len < 4) {
        return JO_KS_LOAD_FAILED;
    }

    size_t offset = 0;
    uint32_t count = read_u32_be(encoded);
    offset += 4;
    if (count == 0) {
        return offset == encoded_len ? JO_SUCCESS : JO_KS_LOAD_FAILED;
    }

    STACK_OF(X509) *chain = sk_X509_new_null();
    jo_assert(chain != NULL);

    for (uint32_t i = 0; i < count; i++) {
        if (offset + 4 > encoded_len) {
            free_x509_stack(chain);
            return JO_KS_LOAD_FAILED;
        }
        uint32_t cert_len = read_u32_be(encoded + offset);
        offset += 4;
        if (cert_len == 0 || cert_len > encoded_len - offset) {
            free_x509_stack(chain);
            return JO_KS_LOAD_FAILED;
        }

        const unsigned char *src = encoded + offset;
        X509 *x509 = d2i_X509(NULL, &src, cert_len);
        if (x509 == NULL || src != encoded + offset + cert_len) {
            X509_free(x509);
            free_x509_stack(chain);
            return JO_KS_LOAD_FAILED;
        }
        if (!sk_X509_push(chain, x509)) {
            X509_free(x509);
            free_x509_stack(chain);
            return JO_FAIL;
        }
        offset += cert_len;
    }
    if (offset != encoded_len) {
        free_x509_stack(chain);
        return JO_KS_LOAD_FAILED;
    }

    *cert = sk_X509_shift(chain);
    if (sk_X509_num(chain) > 0) {
        *ca = chain;
    } else {
        sk_X509_free(chain);
    }
    return JO_SUCCESS;
}

static char *entry_alias_from_bag(PKCS12_SAFEBAG *bag, int fallback_index) {
    char *friendly_name = PKCS12_get_friendlyname(bag);
    if (friendly_name != NULL) {
        return friendly_name;
    }

    char fallback[32];
    BIO_snprintf(fallback, sizeof(fallback), "%d", fallback_index);
    return OPENSSL_strdup(fallback);
}

static int32_t append_certificate_der(ks_entry *entry, const uint8_t *certificate,
                                      size_t certificate_len) {
    if (entry == NULL || certificate == NULL || certificate_len == 0) {
        return JO_KS_LOAD_FAILED;
    }
    if (certificate_len > UINT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    uint32_t count = 0;
    size_t new_len = 8 + certificate_len;
    if (entry->certificate_chain != NULL) {
        if (entry->certificate_chain_len < 4) {
            return JO_KS_LOAD_FAILED;
        }
        count = read_u32_be(entry->certificate_chain);
        if (count == UINT32_MAX
                || entry->certificate_chain_len > SIZE_MAX - 4 - certificate_len) {
            return JO_OUTPUT_TOO_LONG_INT32;
        }
        new_len = entry->certificate_chain_len + 4 + certificate_len;
    }

    uint8_t *new_chain = OPENSSL_zalloc(new_len);
    jo_assert(new_chain != NULL);

    if (entry->certificate_chain != NULL) {
        memcpy(new_chain, entry->certificate_chain, entry->certificate_chain_len);
        write_u32_be(new_chain, count + 1);
        write_u32_be(new_chain + entry->certificate_chain_len,
                (uint32_t) certificate_len);
        memcpy(new_chain + entry->certificate_chain_len + 4, certificate,
                certificate_len);
        OPENSSL_clear_free(entry->certificate_chain, entry->certificate_chain_len);
    } else {
        write_u32_be(new_chain, 1);
        write_u32_be(new_chain + 4, (uint32_t) certificate_len);
        memcpy(new_chain + 8, certificate, certificate_len);
    }

    entry->certificate_chain = new_chain;
    entry->certificate_chain_len = new_len;
    if (entry->key == NULL) {
        entry->certificate_entry = 1;
    }
    return JO_SUCCESS;
}

static int32_t append_certificate(ks_entry *entry, X509 *cert) {
    if (entry == NULL || cert == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    int cert_len = i2d_X509(cert, NULL);
    if (cert_len <= 0) {
        return JO_KS_LOAD_FAILED;
    }

    uint8_t *encoded = OPENSSL_zalloc((size_t) cert_len);
    jo_assert(encoded != NULL);

    unsigned char *dst = encoded;
    int written = i2d_X509(cert, &dst);
    if (written != cert_len) {
        OPENSSL_clear_free(encoded, (size_t) cert_len);
        return JO_KS_LOAD_FAILED;
    }

    int32_t ret = append_certificate_der(entry, encoded, (size_t) cert_len);
    OPENSSL_clear_free(encoded, (size_t) cert_len);
    return ret;
}

static int32_t add_certificate_bag(STACK_OF(PKCS12_SAFEBAG) **bags,
                                   const char *alias, X509 *cert) {
    if (bags == NULL || alias == NULL || cert == NULL) {
        return JO_KS_STORE_FAILED;
    }

    PKCS12_SAFEBAG *bag = PKCS12_add_cert(bags, cert);
    if (bag == NULL || !PKCS12_add_friendlyname_utf8(bag, alias, -1)) {
        return JO_KS_STORE_FAILED;
    }
    return JO_SUCCESS;
}

static int32_t add_certificate_chain_bags(STACK_OF(PKCS12_SAFEBAG) **bags,
                                          const char *alias,
                                          const uint8_t *chain,
                                          size_t chain_len) {
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int32_t ret = decode_certificate_chain(chain, chain_len, &cert, &ca);
    if (ret != JO_SUCCESS) {
        return ret;
    }

    if (cert != NULL) {
        ret = add_certificate_bag(bags, alias, cert);
    }
    for (int i = 0; ret == JO_SUCCESS && ca != NULL && i < sk_X509_num(ca); i++) {
        ret = add_certificate_bag(bags, alias, sk_X509_value(ca, i));
    }

    X509_free(cert);
    free_x509_stack(ca);
    return ret;
}

static int32_t add_entry_bags(STACK_OF(PKCS12_SAFEBAG) **bags, ks_entry *entry,
                              const char *store_password) {
    if (bags == NULL || entry == NULL || entry->alias == NULL) {
        return JO_KS_STORE_FAILED;
    }

    if (entry->key != NULL) {
        PKCS12_SAFEBAG *bag = PKCS12_add_key(bags, entry->key, 0,
                PKCS12_DEFAULT_ITER, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                store_password);
        if (bag == NULL || !PKCS12_add_friendlyname_utf8(bag, entry->alias, -1)) {
            return JO_KS_STORE_FAILED;
        }
        return add_certificate_chain_bags(bags, entry->alias,
                entry->certificate_chain, entry->certificate_chain_len);
    }

    if (entry->certificate_entry && entry->certificate_chain != NULL) {
        return add_certificate_chain_bags(bags, entry->alias,
                entry->certificate_chain, entry->certificate_chain_len);
    }

    return JO_SUCCESS;
}

static int32_t load_key_bag(ks_ctx *ctx, const char *alias, PKCS12_SAFEBAG *bag,
                            const char *password, int password_len) {
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const PKCS8_PRIV_KEY_INFO *p8_const = NULL;

    int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
    if (bag_nid == NID_keyBag) {
        p8_const = PKCS12_SAFEBAG_get0_p8inf(bag);
    } else if (bag_nid == NID_pkcs8ShroudedKeyBag) {
        p8 = PKCS12_decrypt_skey(bag, password, password_len);
        p8_const = p8;
    }

    if (p8_const == NULL) {
        PKCS8_PRIV_KEY_INFO_free(p8);
        return JO_KS_LOAD_FAILED;
    }

    EVP_PKEY *pkey = EVP_PKCS82PKEY(p8_const);
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (pkey == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    EVP_PKEY_free(entry->key);
    entry->key = pkey;
    entry->certificate_entry = 0;
    return set_key_password(entry, (const uint8_t *) password, (size_t) password_len);
}

static int32_t load_cert_bag(ks_ctx *ctx, const char *alias, PKCS12_SAFEBAG *bag) {
    if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate) {
        return JO_SUCCESS;
    }

    X509 *cert = PKCS12_SAFEBAG_get1_cert(bag);
    if (cert == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    int32_t ret = append_certificate(entry, cert);
    X509_free(cert);
    return ret;
}

static int32_t load_bags(ks_ctx *ctx, STACK_OF(PKCS12_SAFEBAG) *bags,
                         const char *password, int password_len,
                         int *fallback_index) {
    if (bags == NULL || fallback_index == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, i);
        char *alias = entry_alias_from_bag(bag, (*fallback_index)++);
        if (alias == NULL) {
            return JO_KS_LOAD_FAILED;
        }

        int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
        int32_t ret = JO_SUCCESS;
        if (bag_nid == NID_keyBag || bag_nid == NID_pkcs8ShroudedKeyBag) {
            ret = load_key_bag(ctx, alias, bag, password, password_len);
        } else if (bag_nid == NID_certBag) {
            ret = load_cert_bag(ctx, alias, bag);
        }

        OPENSSL_free(alias);
        if (ret != JO_SUCCESS) {
            return ret;
        }
    }

    return JO_SUCCESS;
}

ks_ctx *ks_allocate(const char *type, int32_t *err) {
    if (err == NULL) {
        return NULL;
    }
    *err = JO_FAIL;

    if (type == NULL) {
        *err = JO_KS_TYPE_IS_NULL;
        return NULL;
    }
    if (!supported_type(type)) {
        *err = JO_KS_TYPE_UNSUPPORTED;
        return NULL;
    }

    ks_ctx *ctx = OPENSSL_zalloc(sizeof(ks_ctx));
    jo_assert(ctx != NULL);

    ctx->type = OPENSSL_strdup(type);
    jo_assert(ctx->type != NULL);

    *err = JO_SUCCESS;
    return ctx;
}

void ks_free(ks_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    clear_entries(ctx);
    OPENSSL_clear_free(ctx->type, strlen(ctx->type) + 1);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

int32_t ks_load(ks_ctx *ctx, const uint8_t *input, size_t input_len,
                const uint8_t *password, size_t password_len) {
    jo_assert(ctx != NULL);
    jo_assert(input != NULL || input_len == 0);
    jo_assert(password != NULL || password_len == 0);

    if (input == NULL) {
        clear_entries(ctx);
        return JO_SUCCESS;
    }
    if (input_len == 0) {
        return JO_KS_LOAD_FAILED;
    }
    if (input_len > INT32_MAX || password_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    BIO *bio = BIO_new_mem_buf(input, (int) input_len);
    if (bio == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
    BIO_free(bio);
    if (p12 == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    char *pass = copy_password(password, password_len);
    if (password != NULL && password_len != 0 && pass == NULL) {
        PKCS12_free(p12);
        return JO_INPUT_TOO_LONG_INT32;
    }

    int pass_len = (int) password_len;
    if (PKCS12_mac_present(p12) && !PKCS12_verify_mac(p12, pass, pass_len)) {
        OPENSSL_clear_free(pass, password_len + 1);
        PKCS12_free(p12);
        return JO_KS_LOAD_FAILED;
    }

    STACK_OF(PKCS7) *safes = PKCS12_unpack_authsafes(p12);
    if (safes == NULL) {
        OPENSSL_clear_free(pass, password_len + 1);
        PKCS12_free(p12);
        return JO_KS_LOAD_FAILED;
    }

    ks_ctx loaded;
    memset(&loaded, 0, sizeof(loaded));

    int32_t ret = JO_SUCCESS;
    int fallback_index = 1;
    for (int i = 0; ret == JO_SUCCESS && i < sk_PKCS7_num(safes); i++) {
        PKCS7 *p7 = sk_PKCS7_value(safes, i);
        STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
        if (PKCS7_type_is_data(p7)) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (PKCS7_type_is_encrypted(p7)) {
            bags = PKCS12_unpack_p7encdata(p7, pass, pass_len);
        }

        if (bags != NULL) {
            ret = load_bags(&loaded, bags, pass, pass_len, &fallback_index);
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        }
    }
    if (ret == JO_SUCCESS) {
        replace_entries(ctx, &loaded);
    }

    clear_entries(&loaded);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    OPENSSL_clear_free(pass, password_len + 1);
    PKCS12_free(p12);
    return ret;
}

int32_t ks_store(ks_ctx *ctx, uint8_t **out, size_t *out_len,
                 const uint8_t *password, size_t password_len) {
    jo_assert(ctx != NULL);
    jo_assert(out != NULL);
    jo_assert(out_len != NULL);
    jo_assert(password != NULL || password_len == 0);

    *out = NULL;
    *out_len = 0;

    if (password_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    char *pass = copy_password(password, password_len);
    if (password != NULL && password_len != 0 && pass == NULL) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    STACK_OF(PKCS12_SAFEBAG) *bags = sk_PKCS12_SAFEBAG_new_null();
    if (bags == NULL) {
        OPENSSL_clear_free(pass, password_len + 1);
        return JO_KS_STORE_FAILED;
    }

    int32_t ret = JO_SUCCESS;
    for (ks_entry *entry = ctx->entries; ret == JO_SUCCESS && entry != NULL; entry = entry->next) {
        ret = add_entry_bags(&bags, entry, pass);
    }
    if (ret != JO_SUCCESS) {
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        OPENSSL_clear_free(pass, password_len + 1);
        return ret;
    }

    STACK_OF(PKCS7) *safes = NULL;
    if (!PKCS12_add_safe(&safes, bags, -1, PKCS12_DEFAULT_ITER, pass)) {
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        OPENSSL_clear_free(pass, password_len + 1);
        return JO_KS_STORE_FAILED;
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);

    PKCS12 *p12 = PKCS12_add_safes(safes, NID_pkcs7_data);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    if (p12 == NULL) {
        OPENSSL_clear_free(pass, password_len + 1);
        return JO_KS_STORE_FAILED;
    }

    if (!PKCS12_set_mac(p12, pass, (int) password_len, NULL, 0,
            PKCS12_DEFAULT_ITER, NULL)) {
        PKCS12_free(p12);
        OPENSSL_clear_free(pass, password_len + 1);
        return JO_KS_STORE_FAILED;
    }

    unsigned char *der = NULL;
    int der_len = i2d_PKCS12(p12, &der);
    PKCS12_free(p12);
    OPENSSL_clear_free(pass, password_len + 1);
    if (der_len <= 0 || der == NULL) {
        OPENSSL_free(der);
        return JO_KS_STORE_FAILED;
    }

    uint8_t *copy = OPENSSL_zalloc((size_t) der_len);
    jo_assert(copy != NULL);
    memcpy(copy, der, (size_t) der_len);
    OPENSSL_free(der);

    *out = copy;
    *out_len = (size_t) der_len;
    return JO_SUCCESS;
}

int32_t ks_get_key(ks_ctx *ctx, const char *alias, uint8_t **out, size_t *out_len,
                   const uint8_t *password, size_t password_len) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);
    jo_assert(out != NULL);
    jo_assert(out_len != NULL);
    jo_assert(password != NULL || password_len == 0);

    *out = NULL;
    *out_len = 0;

    ks_entry *entry = find_entry(ctx, alias);
    if (entry == NULL || entry->key == NULL) {
        return JO_SUCCESS;
    }
    if (!password_matches(entry, password, password_len)) {
        return JO_KS_DECODE_KEY_FAILED;
    }

    key_spec spec;
    spec.key = entry->key;

    int32_t ret = JO_FAIL;
    asn1_ctx *asn1 = asn1_writer_allocate(&ret);
    if (asn1 == NULL || ret != JO_SUCCESS) {
        return ret;
    }

    size_t encoded_len = 0;
    ret = asn1_writer_encode_private_key(asn1, &spec, &encoded_len, PRIVATE_KEY_DEFAULT_ENCODING);
    if (ret != 1) {
        asn1_writer_free(asn1);
        return ret == 0 ? JO_KS_ENCODE_KEY_FAILED : ret;
    }

    uint8_t *encoded = OPENSSL_zalloc(encoded_len);
    jo_assert(encoded != NULL);

    size_t written = 0;
    ret = asn1_writer_get_content(asn1, encoded, &written, encoded_len);
    asn1_writer_free(asn1);
    if (ret != 1) {
        OPENSSL_clear_free(encoded, encoded_len);
        return ret;
    }

    *out = encoded;
    *out_len = written;
    return JO_SUCCESS;
}

int32_t ks_set_key(ks_ctx *ctx, const char *alias, const uint8_t *key, size_t key_len,
                   const uint8_t *password, size_t password_len) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);
    jo_assert(key != NULL);
    jo_assert(password != NULL || password_len == 0);

    if (key_len == 0) {
        return JO_KS_DECODE_KEY_FAILED;
    }
    if (password_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    uint8_t *password_copy = NULL;
    if (password_len != 0) {
        password_copy = OPENSSL_zalloc(password_len);
        jo_assert(password_copy != NULL);
        memcpy(password_copy, password, password_len);
    }

    int32_t ret = JO_FAIL;
    key_spec *spec = asn1_writer_decode_private_key(key, key_len, &ret);
    if (spec == NULL) {
        OPENSSL_clear_free(password_copy, password_len);
        return ret == JO_OPENSSL_ERROR ? JO_KS_DECODE_KEY_FAILED : ret;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    if (entry->key != NULL) {
        EVP_PKEY_free(entry->key);
    }

    entry->key = spec->key;
    entry->certificate_entry = 0;
    spec->key = NULL;
    free_key_spec(spec);
    clear_key_password(entry);
    entry->key_password = password_copy;
    entry->key_password_len = password_len;
    return JO_SUCCESS;
}

int32_t ks_get_certificate_chain(ks_ctx *ctx, const char *alias, uint8_t **out, size_t *out_len) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);
    jo_assert(out != NULL);
    jo_assert(out_len != NULL);

    *out = NULL;
    *out_len = 0;

    ks_entry *entry = find_entry(ctx, alias);
    if (entry == NULL || entry->certificate_chain == NULL || entry->certificate_chain_len == 0) {
        return JO_SUCCESS;
    }

    uint8_t *encoded = OPENSSL_zalloc(entry->certificate_chain_len);
    jo_assert(encoded != NULL);
    memcpy(encoded, entry->certificate_chain, entry->certificate_chain_len);

    *out = encoded;
    *out_len = entry->certificate_chain_len;
    return JO_SUCCESS;
}

int32_t ks_set_certificate_chain(ks_ctx *ctx, const char *alias, const uint8_t *chain, size_t chain_len) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);
    jo_assert(chain != NULL || chain_len == 0);

    if (chain == NULL || chain_len == 0) {
        ks_entry *entry = find_entry(ctx, alias);
        if (entry != NULL) {
            clear_certificate_chain(entry);
        }
        return JO_SUCCESS;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    clear_certificate_chain(entry);
    entry->certificate_chain = OPENSSL_zalloc(chain_len);
    jo_assert(entry->certificate_chain != NULL);
    memcpy(entry->certificate_chain, chain, chain_len);
    entry->certificate_chain_len = chain_len;
    return JO_SUCCESS;
}

int32_t ks_set_certificate_entry(ks_ctx *ctx, const char *alias, const uint8_t *certificate, size_t certificate_len) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);
    jo_assert(certificate != NULL || certificate_len == 0);
    if (certificate_len > UINT32_MAX) {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    if (certificate == NULL || certificate_len == 0) {
        return JO_KS_LOAD_FAILED;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    if (entry->key != NULL) {
        return JO_FAIL;
    }

    clear_certificate_chain(entry);
    entry->certificate_entry = 1;

    uint8_t count_len[8];
    write_u32_be(count_len, 1);
    write_u32_be(count_len + 4, (uint32_t) certificate_len);
    entry->certificate_chain = OPENSSL_zalloc(sizeof(count_len) + certificate_len);
    jo_assert(entry->certificate_chain != NULL);
    memcpy(entry->certificate_chain, count_len, sizeof(count_len));
    memcpy(entry->certificate_chain + sizeof(count_len), certificate, certificate_len);
    entry->certificate_chain_len = sizeof(count_len) + certificate_len;
    return JO_SUCCESS;
}

int32_t ks_delete_entry(ks_ctx *ctx, const char *alias) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);

    ks_entry *prev = NULL;
    ks_entry *entry = ctx->entries;
    while (entry != NULL) {
        if (entry->alias != NULL && strcmp(entry->alias, alias) == 0) {
            if (prev == NULL) {
                ctx->entries = entry->next;
            } else {
                prev->next = entry->next;
            }
            free_entry(entry);
            return JO_SUCCESS;
        }
        prev = entry;
        entry = entry->next;
    }
    return JO_SUCCESS;
}

int32_t ks_get_aliases(ks_ctx *ctx, uint8_t **out, size_t *out_len) {
    jo_assert(ctx != NULL);
    jo_assert(out != NULL);
    jo_assert(out_len != NULL);

    *out = NULL;
    *out_len = 0;

    uint32_t count = 0;
    size_t total = 4;
    for (ks_entry *entry = ctx->entries; entry != NULL; entry = entry->next) {
        if (entry->alias == NULL) {
            continue;
        }
        size_t alias_len = strlen(entry->alias);
        if (alias_len > UINT32_MAX || total > SIZE_MAX - 4 - alias_len) {
            return JO_OUTPUT_TOO_LONG_INT32;
        }
        total += 4 + alias_len;
        count++;
    }

    uint8_t *encoded = OPENSSL_zalloc(total);
    jo_assert(encoded != NULL);
    size_t offset = 0;
    write_u32_be(encoded + offset, count);
    offset += 4;
    for (ks_entry *entry = ctx->entries; entry != NULL; entry = entry->next) {
        if (entry->alias == NULL) {
            continue;
        }
        size_t alias_len = strlen(entry->alias);
        write_u32_be(encoded + offset, (uint32_t) alias_len);
        offset += 4;
        memcpy(encoded + offset, entry->alias, alias_len);
        offset += alias_len;
    }

    *out = encoded;
    *out_len = total;
    return JO_SUCCESS;
}

int32_t ks_contains_alias(ks_ctx *ctx, const char *alias) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);

    return find_entry(ctx, alias) == NULL ? 0 : 1;
}

int32_t ks_size(ks_ctx *ctx) {
    jo_assert(ctx != NULL);

    int32_t size = 0;
    for (ks_entry *entry = ctx->entries; entry != NULL; entry = entry->next) {
        size++;
    }
    return size;
}

int32_t ks_is_key_entry(ks_ctx *ctx, const char *alias) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);

    ks_entry *entry = find_entry(ctx, alias);
    return entry != NULL && entry->key != NULL ? 1 : 0;
}

int32_t ks_is_certificate_entry(ks_ctx *ctx, const char *alias) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);

    ks_entry *entry = find_entry(ctx, alias);
    return entry != NULL && entry->key == NULL && entry->certificate_entry ? 1 : 0;
}

int64_t ks_get_creation_date(ks_ctx *ctx, const char *alias, int32_t *err) {
    jo_assert(err != NULL);
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);

    ks_entry *entry = find_entry(ctx, alias);
    if (entry == NULL) {
        *err = JO_SUCCESS;
        return 0;
    }

    *err = JO_SUCCESS;
    return entry->creation_time;
}
