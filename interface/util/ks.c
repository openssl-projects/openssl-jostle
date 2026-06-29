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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "asn1_util.h"
#include "bc_err_codes.h"
#include "jo_assert.h"
#include "key_spec.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"

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
    sk_X509_pop_free(entry->certificate_chain, X509_free);
    entry->certificate_chain = NULL;
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
    OPENSSL_free(entry->local_key_id);
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

static char *entry_alias_from_bag(PKCS12_SAFEBAG *bag, int fallback_index) {
    char *friendly_name = PKCS12_get_friendlyname(bag);
    if (friendly_name != NULL) {
        return friendly_name;
    }

    char fallback[32];
    BIO_snprintf(fallback, sizeof(fallback), "%d", fallback_index);
    return OPENSSL_strdup(fallback);
}

/*
 * Borrowed view of a bag's PKCS#12 localKeyId attribute (an OCTET STRING). The
 * returned pointer is owned by the bag and valid for the bag's lifetime.
 * Returns 1 if a non-empty localKeyId is present, 0 otherwise.
 */
static int bag_local_key_id(const PKCS12_SAFEBAG *bag, const unsigned char **id,
                            int *id_len) {
    *id = NULL;
    *id_len = 0;

    const STACK_OF(X509_ATTRIBUTE) *attrs = PKCS12_SAFEBAG_get0_attrs(bag);
    if (attrs == NULL) {
        return 0;
    }
    const ASN1_TYPE *attr = PKCS12_get_attr_gen(attrs, NID_localKeyID);
    if (attr == NULL || ASN1_TYPE_get(attr) != V_ASN1_OCTET_STRING) {
        return 0;
    }
    const ASN1_OCTET_STRING *oct = attr->value.octet_string;
    if (oct == NULL || ASN1_STRING_length(oct) <= 0) {
        return 0;
    }
    *id = ASN1_STRING_get0_data(oct);
    *id_len = ASN1_STRING_length(oct);
    return 1;
}

static ks_entry *find_entry_by_local_key_id(ks_ctx *ctx, const unsigned char *id,
                                            int id_len) {
    if (id == NULL || id_len <= 0) {
        return NULL;
    }
    for (ks_entry *entry = ctx->entries; entry != NULL; entry = entry->next) {
        if (entry->local_key_id != NULL && entry->local_key_id_len == id_len
                && memcmp(entry->local_key_id, id, (size_t) id_len) == 0) {
            return entry;
        }
    }
    return NULL;
}

static int32_t add_certificate_bag(STACK_OF(PKCS12_SAFEBAG) **bags,
                                   const char *alias, X509 *cert,
                                   const char *local_key_id) {
    if (bags == NULL || alias == NULL || cert == NULL) {
        return JO_KS_STORE_FAILED;
    }

    PKCS12_SAFEBAG *bag = PKCS12_add_cert(bags, cert);
    if (bag == NULL || !PKCS12_add_friendlyname_utf8(bag, alias, -1)) {
        return JO_KS_STORE_FAILED;
    }
    /*
     * Tag the cert with the owning key's localKeyId so strict readers
     * (BouncyCastle, keytool) associate the chain with the private key; Jostle
     * itself groups by friendlyName, but the PKCS#12 convention is localKeyId.
     */
    if (local_key_id != NULL
            && !PKCS12_add_localkeyid(bag, (unsigned char *) local_key_id,
                    (int) strlen(local_key_id))) {
        return JO_KS_STORE_FAILED;
    }
    return JO_SUCCESS;
}

static int32_t add_certificate_chain_bags(STACK_OF(PKCS12_SAFEBAG) **bags,
                                          const char *alias,
                                          STACK_OF(X509) *chain,
                                          const char *local_key_id) {
    if (chain == NULL) {
        return JO_SUCCESS;
    }

    for (int i = 0; i < sk_X509_num(chain); i++) {
        /* Only the leaf (first) cert carries the localKeyId; CA certs are
         * chained by issuer/subject. */
        const char *id = (i == 0) ? local_key_id : NULL;
        int32_t ret = add_certificate_bag(bags, alias, sk_X509_value(chain, i), id);
        if (ret != JO_SUCCESS) {
            return ret;
        }
    }
    return JO_SUCCESS;
}

/*
 * Map a Jostle PBE selector to the OpenSSL nid passed to PKCS12_add_key_ex /
 * PKCS12_add_safe_ex. A raw cipher nid (the AES selectors) drives a PBES2 /
 * PBKDF2 structure (PRF defaults to HMAC-SHA256); KS_PBE_3DES is the classic
 * PKCS#12 PBES1 nid; -1 means "no encryption" (a cleartext safe). Returns
 * NID_undef for an unrecognised selector.
 */
static int pbe_alg_to_nid(int32_t pbe) {
    switch (pbe) {
        case KS_PBE_NONE:
            return -1;
        case KS_PBE_3DES:
            return NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
        case KS_PBE_AES_128_CBC:
            return NID_aes_128_cbc;
        case KS_PBE_AES_256_CBC:
            return NID_aes_256_cbc;
        case KS_PBE_AES_128_GCM:
            return NID_aes_128_gcm;
        case KS_PBE_AES_256_GCM:
            return NID_aes_256_gcm;
        default:
            return NID_undef;
    }
}

static const EVP_MD *ks_md_to_evp(int32_t md) {
    switch (md) {
        case KS_MD_SHA1:
            return EVP_sha1();
        case KS_MD_SHA256:
            return EVP_sha256();
        case KS_MD_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

static int32_t load_key_bag(ks_ctx *ctx, const char *alias, PKCS12_SAFEBAG *bag,
                            const char *password, int password_len) {
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const PKCS8_PRIV_KEY_INFO *p8_const = NULL;

    int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
    if (bag_nid == NID_keyBag) {
        p8_const = PKCS12_SAFEBAG_get0_p8inf(bag);
    } else if (bag_nid == NID_pkcs8ShroudedKeyBag) {
        p8 = PKCS12_decrypt_skey_ex(bag, password, password_len,
                get_global_jostle_ossl_lib_ctx(), NULL);
        p8_const = p8;
    }

    if (p8_const == NULL) {
        PKCS8_PRIV_KEY_INFO_free(p8);
        return JO_KS_LOAD_FAILED;
    }

    EVP_PKEY *pkey = EVP_PKCS82PKEY_ex(p8_const,
            get_global_jostle_ossl_lib_ctx(), NULL);
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

    X509 *cert = PKCS12_SAFEBAG_get1_cert_ex(bag,
            get_global_jostle_ossl_lib_ctx(), NULL);
    if (cert == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    if (entry->certificate_chain == NULL) {
        entry->certificate_chain = sk_X509_new_null();
        jo_assert(entry->certificate_chain != NULL);
    }
    if (!sk_X509_push(entry->certificate_chain, cert)) {
        X509_free(cert);
        return JO_FAIL;
    }
    if (entry->key == NULL) {
        entry->certificate_entry = 1;
    }
    return JO_SUCCESS;
}

/*
 * Two-pass load over every bag collected from all safes. Pass 1 loads the key
 * bags (each becomes an entry keyed by friendlyName, or a numeric fallback) and
 * records each key's localKeyId. Pass 2 attaches every cert bag to the key that
 * shares its localKeyId -- the association convention strict PKCS#12 readers
 * (BouncyCastle, keytool, `openssl pkcs12`) use -- falling back to friendlyName
 * grouping when no localKeyId match exists (trusted certs, or producers that
 * associate purely by friendlyName). Processing keys before certs makes the
 * association order-independent across bags and safes.
 */
static int32_t load_collected_bags(ks_ctx *ctx, STACK_OF(PKCS12_SAFEBAG) *bags,
                                   const char *password, int password_len) {
    if (bags == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    int fallback_index = 1;

    for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, i);
        int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
        if (bag_nid != NID_keyBag && bag_nid != NID_pkcs8ShroudedKeyBag) {
            continue;
        }

        char *alias = entry_alias_from_bag(bag, fallback_index++);
        if (alias == NULL) {
            return JO_KS_LOAD_FAILED;
        }

        int32_t ret = load_key_bag(ctx, alias, bag, password, password_len);
        if (ret == JO_SUCCESS) {
            ks_entry *entry = find_entry(ctx, alias);
            const unsigned char *id;
            int id_len;
            if (entry != NULL && entry->local_key_id == NULL
                    && bag_local_key_id(bag, &id, &id_len)) {
                entry->local_key_id = OPENSSL_memdup(id, (size_t) id_len);
                jo_assert(entry->local_key_id != NULL);
                entry->local_key_id_len = id_len;
            }
        }

        OPENSSL_free(alias);
        if (ret != JO_SUCCESS) {
            return ret;
        }
    }

    for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, i);
        if (PKCS12_SAFEBAG_get_nid(bag) != NID_certBag) {
            continue;
        }

        const unsigned char *id;
        int id_len;
        ks_entry *owner = NULL;
        if (bag_local_key_id(bag, &id, &id_len)) {
            owner = find_entry_by_local_key_id(ctx, id, id_len);
        }

        char *alias;
        int alias_owned;
        if (owner != NULL) {
            alias = owner->alias;
            alias_owned = 0;
        } else {
            alias = entry_alias_from_bag(bag, fallback_index++);
            alias_owned = 1;
            if (alias == NULL) {
                return JO_KS_LOAD_FAILED;
            }
        }

        int32_t ret = load_cert_bag(ctx, alias, bag);
        if (alias_owned) {
            OPENSSL_free(alias);
        }
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
    OPENSSL_clear_free(ctx->pending_store, ctx->pending_store_len);
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

    /*
     * Single exit: every owned resource is declared and NULL-initialised up
     * front, and every failure path branches to the `exit` label whose
     * NULL-tolerant freers run unconditionally. This is what makes the OpenSSL
     * calls below OPS-instrumentable -- an OPS-forced failure branch still frees
     * the handle the call actually returned.
     */
    BIO *bio = NULL;
    PKCS12 *p12 = NULL;
    char *pass = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *all_bags = NULL;
    ks_ctx loaded;
    int pass_len = (int) password_len;
    int32_t ret = JO_KS_LOAD_FAILED;

    memset(&loaded, 0, sizeof(loaded));

    ERR_clear_error();

    bio = BIO_new_mem_buf(input, (int) input_len);
    if (bio == NULL) {
        goto exit;
    }

    p12 = d2i_PKCS12_bio(bio, NULL);
    if (OPS_OPENSSL_ERROR_4 p12 == NULL) {
        goto exit;
    }

    pass = copy_password(password, password_len);
    if (password != NULL && password_len != 0 && pass == NULL) {
        ret = JO_INPUT_TOO_LONG_INT32;
        goto exit;
    }

    /*
     * A failed MAC means a wrong integrity password or tampered data -- an
     * expected, non-error outcome -- so scrub the "mac verify failed" noise off
     * the thread-local ERR queue (mark/pop) and surface a dedicated code the
     * bridge maps to an UnrecoverableKeyException cause, distinct from the
     * generic malformed-file JO_KS_LOAD_FAILED.
     */
    ERR_set_mark();
    if (PKCS12_mac_present(p12) && !PKCS12_verify_mac(p12, pass, pass_len)) {
        ERR_pop_to_mark();
        ret = JO_KS_MAC_VERIFY_FAILED;
        goto exit;
    }
    ERR_clear_last_mark();

    safes = PKCS12_unpack_authsafes(p12);
    if (OPS_OPENSSL_ERROR_5 safes == NULL) {
        goto exit;
    }

    /*
     * Collect every bag from every safe (decrypting encrypted safes with the
     * password) into one stack. localKeyId-based cert<->key association needs
     * all key bags visible before any cert is attached, so a single collected
     * stack processed in two passes by load_collected_bags is simpler and
     * order-independent.
     */
    all_bags = sk_PKCS12_SAFEBAG_new_null();
    jo_assert(all_bags != NULL);

    ret = JO_SUCCESS;
    for (int i = 0; ret == JO_SUCCESS && i < sk_PKCS7_num(safes); i++) {
        PKCS7 *p7 = sk_PKCS7_value(safes, i);
        STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
        if (PKCS7_type_is_data(p7)) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (PKCS7_type_is_encrypted(p7)) {
            bags = PKCS12_unpack_p7encdata(p7, pass, pass_len);
        }

        if (bags != NULL) {
            while (sk_PKCS12_SAFEBAG_num(bags) > 0) {
                PKCS12_SAFEBAG *moved = sk_PKCS12_SAFEBAG_shift(bags);
                if (!sk_PKCS12_SAFEBAG_push(all_bags, moved)) {
                    PKCS12_SAFEBAG_free(moved);
                    ret = JO_FAIL;
                    break;
                }
            }
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        }
    }

    if (ret == JO_SUCCESS) {
        ret = load_collected_bags(&loaded, all_bags, pass, pass_len);
    }
    if (ret == JO_SUCCESS) {
        replace_entries(ctx, &loaded);
    }

exit:
    clear_entries(&loaded);
    sk_PKCS12_SAFEBAG_pop_free(all_bags, PKCS12_SAFEBAG_free);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    OPENSSL_clear_free(pass, password_len + 1);
    PKCS12_free(p12);
    BIO_free(bio);
    return ret;
}

int32_t ks_store(ks_ctx *ctx, uint8_t **out, size_t *out_len,
                 const uint8_t *password, size_t password_len,
                 int32_t key_pbe, int32_t cert_pbe, int32_t mac_scheme,
                 int32_t mac_digest, int32_t pbe_iter, int32_t mac_iter,
                 void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(out != NULL);
    jo_assert(out_len != NULL);
    jo_assert(password != NULL || password_len == 0);
    jo_assert(pbe_iter >= 0);
    jo_assert(mac_iter >= 0);

    *out = NULL;
    *out_len = 0;

    if (password_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ERR_clear_error();

    int key_nid = pbe_alg_to_nid(key_pbe);
    int cert_nid = pbe_alg_to_nid(cert_pbe);
    const EVP_MD *mac_md = NULL;

    /* Keys must be encrypted: NONE/unknown is not a valid key PBE. */
    if (key_nid == NID_undef || key_nid == -1) {
        return JO_KS_STORE_FAILED;
    }
    if (cert_nid == NID_undef) {
        return JO_KS_STORE_FAILED;
    }
    if (mac_scheme != KS_MAC_NONE && mac_scheme != KS_MAC_TRADITIONAL
            && mac_scheme != KS_MAC_PBMAC1) {
        return JO_KS_STORE_FAILED;
    }
    if (mac_scheme == KS_MAC_TRADITIONAL || mac_scheme == KS_MAC_PBMAC1) {
        mac_md = ks_md_to_evp(mac_digest);
        if (mac_md == NULL) {
            return JO_KS_STORE_FAILED;
        }
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    int pass_len = (int) password_len;

    char *pass = copy_password(password, password_len);
    if (password != NULL && password_len != 0 && pass == NULL) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    STACK_OF(PKCS12_SAFEBAG) *key_bags = sk_PKCS12_SAFEBAG_new_null();
    STACK_OF(PKCS12_SAFEBAG) *cert_bags = sk_PKCS12_SAFEBAG_new_null();
    STACK_OF(PKCS7) *safes = NULL;
    PKCS12 *p12 = NULL;
    unsigned char *der = NULL;
    uint8_t *copy = NULL;
    int32_t ret = JO_KS_STORE_FAILED;
    int32_t cret;

    if (key_bags == NULL || cert_bags == NULL) {
        goto end;
    }

    /*
     * The EVP calls below (key shrouding, cert-safe encryption, MAC) draw
     * random salts from the Jostle lib ctx, which up-calls Java for entropy.
     * rnd_src is the RandSource the bridge validated as non-NULL; bind it to
     * the thread-local here, right before the first entropy-consuming call, so
     * the requirement is obvious at the point of use.
     */
    jo_assert(rnd_src != NULL);
    rand_set_java_srand_call(rnd_src);

    /*
     * Private keys -> individually shrouded key bags (placed in a cleartext
     * safe below); certificates -> cert bags (placed in a separate, possibly
     * encrypted, safe). This mirrors the canonical / BouncyCastle PKCS#12
     * layout and routes every crypto call through the Jostle lib ctx so the
     * configured provider and the Java entropy bridge are used.
     */
    for (ks_entry *entry = ctx->entries; entry != NULL; entry = entry->next) {
        if (entry->alias == NULL) {
            continue;
        }
        if (entry->key != NULL) {
            PKCS12_SAFEBAG *bag = PKCS12_add_key_ex(&key_bags, entry->key, 0,
                    pbe_iter, key_nid, pass, libctx, NULL);
            if (OPS_OPENSSL_ERROR_1 bag == NULL
                    || !PKCS12_add_friendlyname_utf8(bag, entry->alias, -1)
                    || !PKCS12_add_localkeyid(bag, (unsigned char *) entry->alias,
                            (int) strlen(entry->alias))) {
                goto end;
            }
            if (entry->certificate_chain != NULL) {
                cret = add_certificate_chain_bags(&cert_bags, entry->alias,
                        entry->certificate_chain, entry->alias);
                if (cret != JO_SUCCESS) {
                    ret = cret;
                    goto end;
                }
            }
        } else if (entry->certificate_entry && entry->certificate_chain != NULL) {
            cret = add_certificate_chain_bags(&cert_bags, entry->alias,
                    entry->certificate_chain, NULL);
            if (cret != JO_SUCCESS) {
                ret = cret;
                goto end;
            }
        }
    }

    /*
     * Cleartext safe carrying the (already shrouded) key bags. Also emitted
     * when there are no cert bags, so an empty keystore still produces a valid
     * (empty) authenticated safe rather than a NULL PKCS12.
     */
    if (sk_PKCS12_SAFEBAG_num(key_bags) > 0
            || sk_PKCS12_SAFEBAG_num(cert_bags) == 0) {
        if (!PKCS12_add_safe_ex(&safes, key_bags, -1, pbe_iter, pass,
                libctx, NULL)) {
            goto end;
        }
    }
    /* Cert safe: encrypted under cert_nid, or cleartext when cert_nid == -1. */
    if (sk_PKCS12_SAFEBAG_num(cert_bags) > 0) {
        if (!PKCS12_add_safe_ex(&safes, cert_bags, cert_nid, pbe_iter, pass,
                libctx, NULL)) {
            goto end;
        }
    }

    p12 = PKCS12_add_safes_ex(safes, NID_pkcs7_data, libctx, NULL);
    if (OPS_OPENSSL_ERROR_2 p12 == NULL) {
        goto end;
    }

    if (mac_scheme == KS_MAC_TRADITIONAL) {
        if (!PKCS12_set_mac(p12, pass, pass_len, NULL, PKCS12_SALT_LEN,
                mac_iter, mac_md)) {
            goto end;
        }
    } else if (mac_scheme == KS_MAC_PBMAC1) {
        /*
         * RFC 9579 PBMAC1: HMAC message-auth digest = mac_md, PBKDF2 PRF =
         * HMAC-SHA256 (the BouncyCastle PKCS12-PBMAC1 profile). The salt
         * length MUST be explicit -- PKCS12_set_pbmac1_pbkdf2 does not default
         * it the way PKCS12_set_mac does.
         */
        if (!PKCS12_set_pbmac1_pbkdf2(p12, pass, pass_len, NULL,
                PKCS12_SALT_LEN, mac_iter, mac_md, "SHA256")) {
            goto end;
        }
    }
    /* KS_MAC_NONE: no integrity MAC (AES-GCM content is self-authenticating). */

    {
        int der_len = i2d_PKCS12(p12, &der);
        if (OPS_OPENSSL_ERROR_3 der_len <= 0 || der == NULL) {
            goto end;
        }

        copy = OPENSSL_zalloc((size_t) der_len);
        jo_assert(copy != NULL);
        memcpy(copy, der, (size_t) der_len);

        *out = copy;
        *out_len = (size_t) der_len;
        copy = NULL;
        ret = JO_SUCCESS;
    }

end:
    OPENSSL_free(der);
    PKCS12_free(p12);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(key_bags, PKCS12_SAFEBAG_free);
    sk_PKCS12_SAFEBAG_pop_free(cert_bags, PKCS12_SAFEBAG_free);
    OPENSSL_clear_free(pass, password_len + 1);
    return ret;
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

    ERR_clear_error();

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

    ERR_clear_error();

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
    if (entry == NULL || entry->certificate_chain == NULL
            || sk_X509_num(entry->certificate_chain) <= 0) {
        return JO_SUCCESS;
    }

    /*
     * Serialise the chain as concatenated DER: each certificate's ASN.1
     * SEQUENCE is self-delimiting, so the Java side reconstructs the list with
     * CertificateFactory.generateCertificates without any framing.
     */
    int64_t total = 0;
    for (int i = 0; i < sk_X509_num(entry->certificate_chain); i++) {
        int len = i2d_X509(sk_X509_value(entry->certificate_chain, i), NULL);
        if (len <= 0) {
            return JO_FAIL;
        }
        total += len;
        if (total > INT32_MAX) {
            return JO_OUTPUT_TOO_LONG_INT32;
        }
    }

    uint8_t *encoded = OPENSSL_zalloc((size_t) total);
    jo_assert(encoded != NULL);

    unsigned char *p = encoded;
    for (int i = 0; i < sk_X509_num(entry->certificate_chain); i++) {
        if (i2d_X509(sk_X509_value(entry->certificate_chain, i), &p) <= 0) {
            OPENSSL_free(encoded);
            return JO_FAIL;
        }
    }

    *out = encoded;
    *out_len = (size_t) total;
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
    if (chain_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    /* Parse the concatenated-DER run into a STACK_OF(X509), preserving order. */
    STACK_OF(X509) *parsed = sk_X509_new_null();
    jo_assert(parsed != NULL);

    const unsigned char *p = chain;
    const unsigned char *end = chain + chain_len;
    while (p < end) {
        X509 *cert = d2i_X509(NULL, &p, (long) (end - p));
        if (cert == NULL) {
            sk_X509_pop_free(parsed, X509_free);
            return JO_KS_LOAD_FAILED;
        }
        if (!sk_X509_push(parsed, cert)) {
            X509_free(cert);
            sk_X509_pop_free(parsed, X509_free);
            return JO_FAIL;
        }
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    clear_certificate_chain(entry);
    entry->certificate_chain = parsed;
    return JO_SUCCESS;
}

int32_t ks_set_certificate_entry(ks_ctx *ctx, const char *alias, const uint8_t *certificate, size_t certificate_len) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);
    jo_assert(certificate != NULL || certificate_len == 0);
    if (certificate == NULL || certificate_len == 0) {
        return JO_KS_LOAD_FAILED;
    }
    if (certificate_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    if (entry->key != NULL) {
        return JO_FAIL;
    }

    const unsigned char *p = certificate;
    X509 *cert = d2i_X509(NULL, &p, (long) certificate_len);
    if (cert == NULL || p != certificate + certificate_len) {
        X509_free(cert);
        return JO_KS_LOAD_FAILED;
    }

    STACK_OF(X509) *stack = sk_X509_new_null();
    jo_assert(stack != NULL);
    if (!sk_X509_push(stack, cert)) {
        X509_free(cert);
        sk_X509_free(stack);
        return JO_FAIL;
    }

    clear_certificate_chain(entry);
    entry->certificate_chain = stack;
    entry->certificate_entry = 1;
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
