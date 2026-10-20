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
#include <openssl/x509v3.h>

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

static void clear_secret(ks_entry *entry) {
    if (entry == NULL) {
        return;
    }
    OPENSSL_clear_free(entry->secret, entry->secret_len);
    entry->secret = NULL;
    entry->secret_len = 0;
    OPENSSL_free(entry->secret_rfc_oid);
    entry->secret_rfc_oid = NULL;
    OPENSSL_free(entry->secret_sun_oid);
    entry->secret_sun_oid = NULL;
    entry->secret_any_password = 0;
    OPENSSL_free(entry->pending_secret);
    entry->pending_secret = NULL;
    entry->pending_secret_len = 0;
}

/* The entry holds a secret key, decrypted or still encrypted. */
static int holds_secret(const ks_entry *entry) {
    return entry->secret != NULL || entry->pending_secret != NULL;
}

/* The entry holds a private key, decrypted or still encrypted. */
static int holds_key(const ks_entry *entry) {
    return entry->key != NULL || entry->pending_key != NULL;
}

/* Drops the private key in either form. */
static void drop_key(ks_entry *entry) {
    EVP_PKEY_free(entry->key);
    entry->key = NULL;
    OPENSSL_free(entry->pending_key);
    entry->pending_key = NULL;
    entry->pending_key_len = 0;
}

static void free_entry(ks_entry *entry) {
    if (entry == NULL) {
        return;
    }
    if (entry->alias != NULL) {
        OPENSSL_clear_free(entry->alias, strlen(entry->alias) + 1);
    }
    drop_key(entry);
    clear_key_password(entry);
    clear_certificate_chain(entry);
    clear_secret(entry);
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

/*
 * Drop any DER cached by JoKS_StoreLen for the FFM Len-then-fetch split. The
 * cache is only valid for the entry set present when it was built, so every
 * entry mutation (and load) must invalidate it. The SPI issues StoreLen and
 * Store back-to-back with no mutation in between, so this is defence in depth
 * against a future caller that interleaves a mutation -- which would otherwise
 * hand back the stale pre-mutation keystore.
 */
static void clear_pending_store(ks_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    OPENSSL_clear_free(ctx->pending_store, ctx->pending_store_len);
    ctx->pending_store = NULL;
    ctx->pending_store_len = 0;
}

static void replace_entries(ks_ctx *ctx, ks_ctx *src) {
    clear_entries(ctx);
    clear_pending_store(ctx);
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
                                   const char *local_key_id, int trusted) {
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
    /*
     * A certificate entry carries Oracle's trusted-key-usage attribute
     * (anyExtendedKeyUsage), as the JDK and BouncyCastle write it: the JDK
     * reads a certificate bag as a trusted entry only when it is present.
     * Never on a key entry's chain.
     */
    if (trusted
            && !PKCS12_add1_attr_by_NID(bag, NID_oracle_jdk_trustedkeyusage, V_ASN1_OBJECT,
                    (const unsigned char *) OBJ_nid2obj(NID_anyExtendedKeyUsage), -1)) {
        return JO_KS_STORE_FAILED;
    }
    return JO_SUCCESS;
}

static int32_t add_certificate_chain_bags(STACK_OF(PKCS12_SAFEBAG) **bags,
                                          const char *alias,
                                          STACK_OF(X509) *chain,
                                          const char *local_key_id, int trusted) {
    if (chain == NULL) {
        return JO_SUCCESS;
    }

    for (int i = 0; i < sk_X509_num(chain); i++) {
        /* Only the leaf (first) cert carries the localKeyId; CA certs are
         * chained by issuer/subject. */
        const char *id = (i == 0) ? local_key_id : NULL;
        int32_t ret = add_certificate_bag(bags, alias, sk_X509_value(chain, i), id, trusted);
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

/*
 * Diagnosis after a failure, never a pre-check: whether the algorithm is one
 * this build cannot run (no provider serves the cipher, or PBES2 names an AEAD
 * cipher, which OpenSSL's PBES2 does not do), rather than a wrong password or
 * malformed input. It re-probes the algorithm itself, so an OPS-injected
 * failure on a supported algorithm stays generic. On yes, the error queue
 * carries OpenSSL's "unsupported" reason with the algorithm's OID.
 */
static int cipher_nid_unsupported(int cipher_nid, const ASN1_OBJECT *named) {
    ERR_set_mark();
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(get_global_jostle_ossl_lib_ctx(), OBJ_nid2sn(cipher_nid), NULL);
    int unsupported = cipher == NULL || (EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0;
    EVP_CIPHER_free(cipher);
    ERR_pop_to_mark();
    if (unsupported) {
        char oid[128];
        OBJ_obj2txt(oid, sizeof(oid), named != NULL ? named : OBJ_nid2obj(cipher_nid), 1);
        ERR_raise_data(ERR_LIB_EVP, ERR_R_UNSUPPORTED, "algorithm %s", oid);
    }
    return unsupported;
}

/* A PKCS#12 PBE nid or, for the PBES2 selectors, a raw cipher nid. */
static int pbe_nid_unsupported(int nid) {
    int cipher_nid = NID_undef;
    int md_nid = NID_undef;
    if (EVP_PBE_find_ex(EVP_PBE_TYPE_OUTER, nid, &cipher_nid, &md_nid, NULL, NULL) && cipher_nid != NID_undef) {
        return cipher_nid_unsupported(cipher_nid, OBJ_nid2obj(nid));
    }
    return cipher_nid_unsupported(nid, NULL);
}

static int pbe_algor_unsupported(const X509_ALGOR *alg) {
    const ASN1_OBJECT *oid = NULL;
    X509_ALGOR_get0(&oid, NULL, NULL, alg);
    if (OBJ_obj2nid(oid) != NID_pbes2) {
        return pbe_nid_unsupported(OBJ_obj2nid(oid));
    }
    PBE2PARAM *p2 = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), alg->parameter);
    if (p2 == NULL || p2->encryption == NULL) {
        PBE2PARAM_free(p2);
        return 0;
    }
    int unsupported = cipher_nid_unsupported(OBJ_obj2nid(p2->encryption->algorithm), p2->encryption->algorithm);
    PBE2PARAM_free(p2);
    return unsupported;
}

/*
 * A shrouded key read with no store password keeps its encrypted form, as the
 * JDK keeps it: ks_get_key decrypts it with the password the caller gives.
 */
static int32_t defer_key_bag(ks_ctx *ctx, const char *alias, PKCS12_SAFEBAG *bag) {
    const X509_SIG *sig = PKCS12_SAFEBAG_get0_pkcs8(bag);
    unsigned char *der = NULL;
    int der_len = sig == NULL ? 0 : i2d_X509_SIG(sig, &der);
    if (der_len <= 0) {
        OPENSSL_free(der);
        return JO_KS_LOAD_FAILED;
    }
    ks_entry *entry = find_or_create_entry(ctx, alias);
    drop_key(entry);
    entry->pending_key = der;
    entry->pending_key_len = (size_t) der_len;
    entry->certificate_entry = 0;
    clear_key_password(entry);
    return JO_SUCCESS;
}

/* The secret-key twin of defer_key_bag: the EncryptedPrivateKeyInfo DER, decrypted by ks_get_secret. */
static int32_t defer_secret_bag(ks_ctx *ctx, const char *alias, const unsigned char *epki, int epki_len) {
    ks_entry *entry = find_or_create_entry(ctx, alias);
    clear_secret(entry);
    drop_key(entry);
    entry->certificate_entry = 0;
    clear_key_password(entry);
    entry->pending_secret = OPENSSL_memdup(epki, (size_t) epki_len);
    jo_assert(entry->pending_secret != NULL);
    entry->pending_secret_len = (size_t) epki_len;
    return JO_SUCCESS;
}

static int32_t load_key_bag(ks_ctx *ctx, const char *alias, PKCS12_SAFEBAG *bag,
                            const char *password, int password_len, int deferred) {
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const PKCS8_PRIV_KEY_INFO *p8_const = NULL;

    int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
    if (deferred && bag_nid == NID_pkcs8ShroudedKeyBag) {
        return defer_key_bag(ctx, alias, bag);
    }
    if (bag_nid == NID_keyBag) {
        p8_const = PKCS12_SAFEBAG_get0_p8inf(bag);
    } else if (bag_nid == NID_pkcs8ShroudedKeyBag) {
        ERR_set_mark();
        p8 = PKCS12_decrypt_skey_ex(bag, password, password_len,
                get_global_jostle_ossl_lib_ctx(), NULL);
        p8_const = p8;
        if (p8 == NULL) {
            const X509_ALGOR *alg = NULL;
            X509_SIG_get0(PKCS12_SAFEBAG_get0_pkcs8(bag), &alg, NULL);
            ERR_pop_to_mark();
            if (alg != NULL && pbe_algor_unsupported(alg)) {
                return JO_KS_ALGORITHM_UNSUPPORTED;
            }
            /*
             * A key under its own password, not the store's: kept encrypted for
             * getKey with that password, as the JDK reads every key. A MAC-less
             * file whose safes are unencrypted, opened with a wrong store
             * password, therefore loads with every key deferred and fails only
             * at getKey; an encrypted safe under the wrong password still fails
             * the load, here and on the JDK.
             */
            return defer_key_bag(ctx, alias, bag);
        }
        ERR_clear_last_mark();
    }

    if (p8_const == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    EVP_PKEY *pkey = EVP_PKCS82PKEY_ex(p8_const,
            get_global_jostle_ossl_lib_ctx(), NULL);
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (pkey == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    drop_key(entry);
    entry->key = pkey;
    entry->certificate_entry = 0;
    return set_key_password(entry, (const uint8_t *) password, (size_t) password_len);
}

/*
 * A secretBag in either form. RFC 7292 (BouncyCastle): secretTypeId is the key
 * OID and secretValue the raw key; the bag has no per-entry protection, so the
 * entry is marked any-password. SunJCE: secretTypeId is pkcs8ShroudedKeyBag and
 * secretValue an EncryptedPrivateKeyInfo, decrypted here with the store
 * password, whose PKCS#8 names the key OID and holds the raw key; the entry
 * keeps that password, as a private key does. Both OIDs are set to the one
 * read; the SPI re-sets them for the form it writes.
 */
static int32_t load_secret_bag(ks_ctx *ctx, const char *alias, PKCS12_SAFEBAG *bag,
                               const char *password, int password_len, int deferred) {
    const ASN1_OBJECT *type = PKCS12_SAFEBAG_get0_bag_type(bag);
    const ASN1_TYPE *value = PKCS12_SAFEBAG_get0_bag_obj(bag);
    if (type == NULL || value == NULL || ASN1_TYPE_get(value) != V_ASN1_OCTET_STRING
            || value->value.octet_string == NULL) {
        return JO_KS_LOAD_FAILED;
    }
    const unsigned char *octets = ASN1_STRING_get0_data(value->value.octet_string);
    int octets_len = ASN1_STRING_length(value->value.octet_string);
    if (octets == NULL || octets_len <= 0) {
        return JO_KS_LOAD_FAILED;
    }

    int32_t ret = JO_KS_LOAD_FAILED;
    X509_SIG *epki = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const unsigned char *key = octets;
    int key_len = octets_len;
    const ASN1_OBJECT *key_oid = type;
    int shrouded = OBJ_obj2nid(type) == NID_pkcs8ShroudedKeyBag;
    if (shrouded && deferred) {
        /* Kept encrypted, as the JDK keeps it: ks_get_secret decrypts with the password given. */
        return defer_secret_bag(ctx, alias, octets, octets_len);
    }
    char oid_text[128];

    if (shrouded) {
        const unsigned char *q = octets;
        epki = d2i_X509_SIG(NULL, &q, octets_len);
        if (epki == NULL || q - octets != octets_len) {
            goto exit;
        }
        ERR_set_mark();
        p8 = PKCS8_decrypt_ex(epki, password, password_len,
                get_global_jostle_ossl_lib_ctx(), NULL);
        if (p8 == NULL) {
            const X509_ALGOR *alg = NULL;
            X509_SIG_get0(epki, &alg, NULL);
            ERR_pop_to_mark();
            if (alg != NULL && pbe_algor_unsupported(alg)) {
                ret = JO_KS_ALGORITHM_UNSUPPORTED;
                goto exit;
            }
            /* A secret under its own password, not the store's: kept encrypted, as a key is. */
            ret = defer_secret_bag(ctx, alias, octets, octets_len);
            goto exit;
        }
        ERR_clear_last_mark();
        if (OPS_OPENSSL_ERROR_8 p8 == NULL) {
            goto exit;
        }
        if (!PKCS8_pkey_get0(&key_oid, &key, &key_len, NULL, p8)
                || key_oid == NULL || key == NULL || key_len <= 0) {
            goto exit;
        }
    }

    if (key_len > KS_SECRET_MAX_LEN) {
        ret = JO_KS_SECRET_TOO_LONG;
        goto exit;
    }
    int oid_len = OBJ_obj2txt(oid_text, sizeof(oid_text), key_oid, 1);
    if (oid_len <= 0 || oid_len >= (int) sizeof(oid_text)) {
        goto exit;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    clear_secret(entry);
    drop_key(entry);
    entry->certificate_entry = 0;
    entry->secret = OPENSSL_memdup(key, (size_t) key_len);
    jo_assert(entry->secret != NULL);
    entry->secret_len = (size_t) key_len;
    entry->secret_rfc_oid = OPENSSL_strdup(oid_text);
    entry->secret_sun_oid = OPENSSL_strdup(oid_text);
    jo_assert(entry->secret_rfc_oid != NULL && entry->secret_sun_oid != NULL);
    if (shrouded) {
        ret = set_key_password(entry, (const uint8_t *) password, (size_t) password_len);
    } else {
        clear_key_password(entry);
        entry->secret_any_password = 1;
        ret = JO_SUCCESS;
    }

exit:
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_SIG_free(epki);
    return ret;
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
        return JO_OPENSSL_ERROR;
    }
    if (!holds_key(entry) && !holds_secret(entry)) {
        entry->certificate_entry = 1;
    }
    return JO_SUCCESS;
}

/*
 * A certificate bag no key claims by localKeyId is an entry of its own when it
 * carries Oracle's trusted-key-usage attribute or a friendlyName; a bare one,
 * the shape `openssl pkcs12 -export` gives a key's chain certificates, is
 * loose. Every unclaimed bag is a chain candidate either way.
 */
static int is_entry_cert_bag(const PKCS12_SAFEBAG *bag) {
    const STACK_OF(X509_ATTRIBUTE) *attrs = PKCS12_SAFEBAG_get0_attrs(bag);
    return PKCS12_get_attr_gen(attrs, NID_oracle_jdk_trustedkeyusage) != NULL
           || PKCS12_get_attr_gen(attrs, NID_friendlyName) != NULL;
}

/* Marks a candidate already loaded as an entry, in the names parallel to the candidates. */
static char entry_marker[] = "";

static int chain_holds(STACK_OF(X509) *chain, X509 *cert) {
    for (int i = 0; i < sk_X509_num(chain); i++) {
        if (X509_cmp(sk_X509_value(chain, i), cert) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Extend a key entry's chain from its last certificate by issuer, from every
 * certificate no key claims, as the JDK and BouncyCastle do. Each step adds a
 * certificate the chain does not hold, so the walk ends within n steps.
 */
static int32_t extend_chain(ks_entry *entry, STACK_OF(X509) *loose, unsigned char *used) {
    int n = sk_X509_num(loose);
    for (int step = 0; step < n; step++) {
        X509 *last = sk_X509_value(entry->certificate_chain, sk_X509_num(entry->certificate_chain) - 1);
        if (X509_check_issued(last, last) == X509_V_OK) {
            break;
        }
        int found = -1;
        for (int i = 0; i < n && found < 0; i++) {
            X509 *cand = sk_X509_value(loose, i);
            if (!chain_holds(entry->certificate_chain, cand) && X509_check_issued(cand, last) == X509_V_OK) {
                found = i;
            }
        }
        if (found < 0) {
            break;
        }
        X509 *issuer = sk_X509_value(loose, found);
        if (!X509_up_ref(issuer)) {
            return JO_OPENSSL_ERROR;
        }
        if (!sk_X509_push(entry->certificate_chain, issuer)) {
            X509_free(issuer);
            return JO_OPENSSL_ERROR;
        }
        used[found] = 1;
    }
    return JO_SUCCESS;
}

/*
 * Attach the unclaimed certificates to the key entries' chains. A loose one no
 * chain uses becomes an entry under a numeric alias; an attributed or named
 * one is an entry already.
 */
static int32_t place_loose_certs(ks_ctx *ctx, STACK_OF(X509) *loose, STACK_OF(OPENSSL_STRING) *names,
                                 int *fallback_index) {
    int n = sk_X509_num(loose);
    int32_t ret = JO_SUCCESS;
    if (n == 0) {
        return JO_SUCCESS;
    }
    /* n is bounded by the bags parsed from the store's bytes. */
    unsigned char *used = OPENSSL_zalloc((size_t) n);
    jo_assert(used != NULL);

    for (ks_entry *entry = ctx->entries; entry != NULL && ret == JO_SUCCESS; entry = entry->next) {
        if (holds_key(entry) && sk_X509_num(entry->certificate_chain) > 0) {
            ret = extend_chain(entry, loose, used);
        }
    }
    for (int i = 0; i < n && ret == JO_SUCCESS; i++) {
        char *name = sk_OPENSSL_STRING_value(names, i);
        if (used[i] || name == entry_marker) {
            continue;
        }
        char fallback[32];
        if (name == NULL) {
            BIO_snprintf(fallback, sizeof(fallback), "%d", (*fallback_index)++);
            name = fallback;
        }
        ks_entry *entry = find_or_create_entry(ctx, name);
        if (entry->certificate_chain == NULL) {
            entry->certificate_chain = sk_X509_new_null();
            jo_assert(entry->certificate_chain != NULL);
        }
        X509 *cert = sk_X509_value(loose, i);
        if (!X509_up_ref(cert)) {
            ret = JO_OPENSSL_ERROR;
            break;
        }
        if (!sk_X509_push(entry->certificate_chain, cert)) {
            X509_free(cert);
            ret = JO_OPENSSL_ERROR;
            break;
        }
        if (!holds_key(entry) && !holds_secret(entry)) {
            entry->certificate_entry = 1;
        }
    }
    OPENSSL_free(used);
    return ret;
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
                                   const char *password, int password_len, int deferred) {
    if (bags == NULL) {
        return JO_KS_LOAD_FAILED;
    }

    int fallback_index = 1;

    for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, i);
        int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
        if (bag_nid != NID_keyBag && bag_nid != NID_pkcs8ShroudedKeyBag
                && bag_nid != NID_secretBag) {
            continue;
        }

        char *alias = entry_alias_from_bag(bag, fallback_index++);
        if (alias == NULL) {
            return JO_KS_LOAD_FAILED;
        }

        int32_t ret = bag_nid == NID_secretBag
                ? load_secret_bag(ctx, alias, bag, password, password_len, deferred)
                : load_key_bag(ctx, alias, bag, password, password_len, deferred);
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

    STACK_OF(X509) *loose = sk_X509_new_null();
    STACK_OF(OPENSSL_STRING) *names = sk_OPENSSL_STRING_new_null();
    jo_assert(loose != NULL && names != NULL);
    int32_t ret = JO_SUCCESS;
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
        int entry_bag = is_entry_cert_bag(bag);
        if (owner == NULL && PKCS12_SAFEBAG_get_bag_nid(bag) == NID_x509Certificate) {
            X509 *cert = PKCS12_SAFEBAG_get1_cert_ex(bag, get_global_jostle_ossl_lib_ctx(), NULL);
            if (cert == NULL) {
                ret = JO_KS_LOAD_FAILED;
                break;
            }
            /* Every unclaimed certificate is a chain candidate; an entry bag is also loaded as an entry below. */
            char *name = entry_bag ? entry_marker : PKCS12_get_friendlyname(bag);
            if (!sk_X509_push(loose, cert)) {
                X509_free(cert);
                if (name != entry_marker) {
                    OPENSSL_free(name);
                }
                ret = JO_OPENSSL_ERROR;
                break;
            }
            if (!sk_OPENSSL_STRING_push(names, name)) {
                if (name != entry_marker) {
                    OPENSSL_free(name);
                }
                ret = JO_OPENSSL_ERROR;
                break;
            }
            if (!entry_bag) {
                continue;
            }
        }
        if (owner != NULL) {
            alias = owner->alias;
            alias_owned = 0;
        } else {
            alias = entry_alias_from_bag(bag, fallback_index++);
            alias_owned = 1;
            if (alias == NULL) {
                ret = JO_KS_LOAD_FAILED;
                break;
            }
        }

        ret = load_cert_bag(ctx, alias, bag);
        if (alias_owned) {
            OPENSSL_free(alias);
        }
        if (ret != JO_SUCCESS) {
            break;
        }
    }

    if (ret == JO_SUCCESS) {
        ret = place_loose_certs(ctx, loose, names, &fallback_index);
    }
    for (int i = 0; i < sk_OPENSSL_STRING_num(names); i++) {
        char *name = sk_OPENSSL_STRING_value(names, i);
        if (name != entry_marker) {
            OPENSSL_free(name);
        }
    }
    sk_OPENSSL_STRING_free(names);
    sk_X509_pop_free(loose, X509_free);
    return ret;
}

ks_ctx *ks_allocate(const char *type, int32_t *err) {
    /* err is jostle's own: assert, never return. */
    jo_assert(err != NULL);

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
    ctx->kind = KS_CTX_KIND;

    ctx->type = OPENSSL_strdup(type);
    jo_assert(ctx->type != NULL);

    *err = JO_SUCCESS;
    JO_LEDGER_CREATED(JO_LEDGER_KS_CTX);
    return ctx;
}

int32_t ks_ctx_check(const ks_ctx *ctx) {
    jo_assert(ctx != NULL);
    return ctx->kind == KS_CTX_KIND ? JO_SUCCESS : JO_KS_CTX_WRONG_KIND;
}

int32_t ks_free(ks_ctx *ctx) {
    if (ctx == NULL) {
        return JO_SUCCESS;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        /* Frees NOTHING: freeing another kind's memory as a keystore is the fault the tag stops. */
        return JO_KS_CTX_WRONG_KIND;
    }
    JO_LEDGER_DESTROYED(JO_LEDGER_KS_CTX);
    clear_entries(ctx);
    OPENSSL_clear_free(ctx->pending_store, ctx->pending_store_len);
    OPENSSL_clear_free(ctx->type, strlen(ctx->type) + 1);
    ctx->kind = KS_KIND_NONE;
    OPENSSL_clear_free(ctx, sizeof(*ctx));
    return JO_SUCCESS;
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
    /*
     * Bound: the SPI refuses a store over its ceiling (PKCS12Limits, 64 MiB by default) before this call, and
     * every bag, entry and stack below is parsed from these bytes, so their counts are bounded by them.
     */
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
    PKCS12 *p12 = NULL;
    char *pass = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *all_bags = NULL;
    ks_ctx loaded;
    int pass_len = (int) password_len;
    /* NULL is the JCA's null password; an empty one is a password (see ks.h). */
    int no_password = password == NULL;
    int32_t ret = JO_KS_LOAD_FAILED;
    OSSL_LIB_CTX *prev_default = NULL;
    int default_swapped = 0;

    memset(&loaded, 0, sizeof(loaded));

    ERR_clear_error();

    /*
     * PKCS#12 MAC verification (pkcs12_gen_mac) and encrypted-safe decryption
     * (PKCS12_unpack_p7encdata) fetch their digest / cipher through the lib ctx
     * embedded in the decoded PKCS12 -- which d2i leaves NULL, i.e. the process
     * default -- while the key-decrypt path (PKCS12_decrypt_skey_ex,
     * EVP_PKCS82PKEY_ex) is handed the Jostle ctx explicitly. Make the whole
     * load use one provider configuration by switching the thread default to
     * the Jostle lib ctx for the duration; the NULL-ctx fetches then resolve to
     * it. Load consumes no entropy, so the fail-loud bridge RAND (no
     * thread-local up-call target is bound on this path) is never invoked.
     * Restored on every exit path below.
     */
    prev_default = OSSL_LIB_CTX_set0_default(get_global_jostle_ossl_lib_ctx());
    default_swapped = 1;

    {
        /*
         * Buffer-based decode so trailing bytes can be detected: d2i consumes
         * exactly one TLV and advances the pointer past it, so a well-formed
         * PKCS#12 with appended junk otherwise decodes "successfully". Reject
         * the trailing data (strict readers do, and silent acceptance can mask
         * corruption) -- mirroring ks_set_key / ks_set_certificate_entry and
         * the asn1_util decode paths.
         */
        const unsigned char *p = input;
        p12 = d2i_PKCS12(NULL, &p, (long) input_len);
        if (OPS_OPENSSL_ERROR_4 p12 == NULL) {
            goto exit;
        }
        if ((size_t) (p - input) != input_len) {
            ret = JO_DER_TRAILING_DATA;
            goto exit;
        }
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
     *
     * PKCS#12 seeds the MAC/KDF differently for a NULL password and a
     * zero-length one, and copy_password collapses an empty caller password to
     * NULL. When the NULL form fails, retry the "" form before declaring
     * failure (mirroring OpenSSL's own PKCS12_parse) and adopt "" for the
     * safe-decryption below so both stages use the same form -- this lets
     * Jostle read a foreign keystore protected with an explicit empty password.
     */
    if (PKCS12_mac_present(p12) && !no_password) {
        ERR_set_mark();
        int mac_ok = PKCS12_verify_mac(p12, pass, pass_len);
        if (!mac_ok && pass == NULL && PKCS12_verify_mac(p12, "", 0)) {
            pass = OPENSSL_strdup("");
            jo_assert(pass != NULL);
            mac_ok = 1;
        }
        ERR_pop_to_mark();
        if (!mac_ok) {
            ret = JO_KS_MAC_VERIFY_FAILED;
            goto exit;
        }
    }

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
            if (no_password) {
                /* The JCA's load(stream, null): an encrypted safe needs the password it was not given. */
                continue;
            }
            bags = PKCS12_unpack_p7encdata(p7, pass, pass_len);
        } else {
            /*
             * Unrecognised safe content type (e.g. envelopedData): not
             * something we produce or understand. Skip it, as OpenSSL's own
             * PKCS#12 parse loop does, rather than failing an otherwise-valid
             * file.
             */
            continue;
        }

        /*
         * A recognised (data / encrypted) safe that fails to unpack means a
         * wrong safe-encryption password, an unsupported legacy PBE, or
         * corruption. Silently skipping it would surface a partial -- or, on a
         * MAC-less wrong-password file, an EMPTY -- keystore as success. Fail
         * loud, matching OpenSSL's parser (which treats a NULL unpack as a hard
         * error), rather than dropping entries.
         */
        if (bags == NULL) {
            ret = PKCS7_type_is_encrypted(p7) && p7->d.encrypted != NULL
                          && pbe_algor_unsupported(p7->d.encrypted->enc_data->algorithm)
                  ? JO_KS_ALGORITHM_UNSUPPORTED : JO_KS_LOAD_FAILED;
            break;
        }

        while (sk_PKCS12_SAFEBAG_num(bags) > 0) {
            PKCS12_SAFEBAG *moved = sk_PKCS12_SAFEBAG_shift(bags);
            if (!sk_PKCS12_SAFEBAG_push(all_bags, moved)) {
                PKCS12_SAFEBAG_free(moved);
                ret = JO_OPENSSL_ERROR;
                break;
            }
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }

    if (ret == JO_SUCCESS) {
        ret = load_collected_bags(&loaded, all_bags, pass, pass_len, no_password);
    }
    if (ret == JO_SUCCESS) {
        replace_entries(ctx, &loaded);
    }

exit:
    if (default_swapped) {
        OSSL_LIB_CTX_set0_default(prev_default);
    }
    clear_entries(&loaded);
    sk_PKCS12_SAFEBAG_pop_free(all_bags, PKCS12_SAFEBAG_free);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    OPENSSL_clear_free(pass, password_len + 1);
    PKCS12_free(p12);
    return ret;
}

/*
 * Write one secret-key entry. RFC7292: a secretBag of (key OID, raw key) in the
 * certificate safe, which the store encrypts, as BouncyCastle writes it; the
 * OID must have an OpenSSL NID, which ks_set_secret requires and only an
 * unknown OID read from a file can lack. SUNJCE: the raw key as a PKCS#8
 * (version 0, the key OID, absent parameters) encrypted under the entry
 * password with the key PBE, carried as secretBag { pkcs8ShroudedKeyBag,
 * EncryptedPrivateKeyInfo } in the cleartext safe, as SunJCE writes it.
 */
static int32_t add_secret_bag(STACK_OF(PKCS12_SAFEBAG) **key_bags,
                              STACK_OF(PKCS12_SAFEBAG) **cert_bags,
                              ks_entry *entry, int32_t secret_form, int key_nid,
                              int cert_nid, int32_t pbe_iter, const char *pass,
                              int pass_len, OSSL_LIB_CTX *libctx) {
    jo_assert(entry->secret_len <= KS_SECRET_MAX_LEN);
    jo_assert(entry->secret != NULL || entry->pending_secret != NULL);

    PKCS12_SAFEBAG *bag = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    PKCS12_SAFEBAG *shrouded = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *penc = NULL;
    unsigned char *epki_der = NULL;
    char *entry_pass = NULL;
    int32_t ret = JO_KS_STORE_FAILED;

    if (entry->secret == NULL) {
        /* Still encrypted from a null-password load: the bag it was read from, verbatim. */
        bag = PKCS12_SAFEBAG_create_secret(NID_pkcs8ShroudedKeyBag, V_ASN1_OCTET_STRING,
                entry->pending_secret, (int) entry->pending_secret_len);
        if (bag == NULL || !sk_PKCS12_SAFEBAG_push(*key_bags, bag)) {
            PKCS12_SAFEBAG_free(bag);
            bag = NULL;
            goto exit;
        }
    } else if (secret_form == KS_SECRET_FORM_RFC7292) {
        /* The RFC 7292 bag holds the raw key: never write it into a cleartext safe. */
        int nid = OBJ_txt2nid(entry->secret_rfc_oid);
        if (cert_nid == -1 || nid == NID_undef) {
            goto exit;
        }
        bag = PKCS12_add_secret(cert_bags, nid, entry->secret, (int) entry->secret_len);
        if (OPS_OPENSSL_ERROR_6 bag == NULL) {
            goto exit;
        }
    } else {
        oid = OBJ_txt2obj(entry->secret_sun_oid, 1);
        p8 = PKCS8_PRIV_KEY_INFO_new();
        penc = OPENSSL_memdup(entry->secret, entry->secret_len);
        if (oid == NULL || p8 == NULL || penc == NULL
                || !PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, penc,
                        (int) entry->secret_len)) {
            goto exit;
        }
        oid = NULL;
        penc = NULL;

        /* The entry's own password, as SunJCE; the store password when none was set. */
        const char *bag_pass = pass;
        int bag_pass_len = pass_len;
        if (entry->key_password != NULL && entry->key_password_len != 0) {
            entry_pass = copy_password(entry->key_password, entry->key_password_len);
            jo_assert(entry_pass != NULL);
            bag_pass = entry_pass;
            bag_pass_len = (int) entry->key_password_len;
        }
        shrouded = PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(key_nid, bag_pass, bag_pass_len,
                NULL, 0, pbe_iter, p8, libctx, NULL);
        if (OPS_OPENSSL_ERROR_7 shrouded == NULL) {
            goto exit;
        }
        const X509_SIG *epki = PKCS12_SAFEBAG_get0_pkcs8(shrouded);
        int der_len = epki == NULL ? -1 : i2d_X509_SIG(epki, &epki_der);
        if (der_len > 0 && epki_der != NULL) {
            bag = PKCS12_SAFEBAG_create_secret(NID_pkcs8ShroudedKeyBag, V_ASN1_OCTET_STRING,
                    epki_der, der_len);
        }
        if (OPS_OPENSSL_ERROR_10 bag == NULL || !sk_PKCS12_SAFEBAG_push(*key_bags, bag)) {
            PKCS12_SAFEBAG_free(bag);
            bag = NULL;
            goto exit;
        }
    }

    if (OPS_OPENSSL_ERROR_11 !PKCS12_add_friendlyname_utf8(bag, entry->alias, -1)
            || !PKCS12_add_localkeyid(bag, (unsigned char *) entry->alias,
                    (int) strlen(entry->alias))) {
        goto exit;
    }
    ret = JO_SUCCESS;

exit:
    ASN1_OBJECT_free(oid);
    OPENSSL_clear_free(penc, entry->secret_len);
    PKCS8_PRIV_KEY_INFO_free(p8);
    PKCS12_SAFEBAG_free(shrouded);
    OPENSSL_free(epki_der);
    if (entry_pass != NULL) {
        OPENSSL_clear_free(entry_pass, entry->key_password_len + 1);
    }
    return ret;
}

/*
 * A key still encrypted from a null-password load is written back as read: its
 * encryption stays its original writer's, and nothing is decrypted without its
 * password.
 */
static PKCS12_SAFEBAG *add_pending_key_bag(STACK_OF(PKCS12_SAFEBAG) **bags, const ks_entry *entry) {
    const unsigned char *p = entry->pending_key;
    X509_SIG *sig = d2i_X509_SIG(NULL, &p, (long) entry->pending_key_len);
    if (sig == NULL) {
        return NULL;
    }
    PKCS12_SAFEBAG *bag = PKCS12_SAFEBAG_create0_pkcs8(sig);
    if (bag == NULL) {
        X509_SIG_free(sig);
        return NULL;
    }
    if (*bags == NULL) {
        *bags = sk_PKCS12_SAFEBAG_new_null();
    }
    if (*bags == NULL || !sk_PKCS12_SAFEBAG_push(*bags, bag)) {
        PKCS12_SAFEBAG_free(bag);
        return NULL;
    }
    return bag;
}

int32_t ks_store(ks_ctx *ctx, uint8_t **out, size_t *out_len,
                 const uint8_t *password, size_t password_len,
                 int32_t key_pbe, int32_t cert_pbe, int32_t mac_scheme,
                 int32_t mac_digest, int32_t pbe_iter, int32_t mac_iter,
                 int32_t secret_form, void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(out != NULL);
    jo_assert(out_len != NULL);
    jo_assert(password != NULL || password_len == 0);
    /* Bridge-validated: OpenSSL would silently replace a count of 0 with its default. */
    jo_assert(pbe_iter > 0);
    jo_assert(mac_iter > 0);

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
    if (secret_form != KS_SECRET_FORM_RFC7292 && secret_form != KS_SECRET_FORM_SUNJCE) {
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
        if (holds_secret(entry)) {
            cret = add_secret_bag(&key_bags, &cert_bags, entry, secret_form,
                    key_nid, cert_nid, pbe_iter, pass, pass_len, libctx);
            if (cret != JO_SUCCESS) {
                ret = cret;
                goto end;
            }
        } else if (holds_key(entry)) {
            PKCS12_SAFEBAG *bag = entry->key != NULL
                    ? PKCS12_add_key_ex(&key_bags, entry->key, 0, pbe_iter, key_nid, pass, libctx, NULL)
                    : add_pending_key_bag(&key_bags, entry);
            if (OPS_OPENSSL_ERROR_1 bag == NULL
                    || !PKCS12_add_friendlyname_utf8(bag, entry->alias, -1)
                    || !PKCS12_add_localkeyid(bag, (unsigned char *) entry->alias,
                            (int) strlen(entry->alias))) {
                goto end;
            }
            if (entry->certificate_chain != NULL) {
                cret = add_certificate_chain_bags(&cert_bags, entry->alias,
                        entry->certificate_chain, entry->alias, 0);
                if (cret != JO_SUCCESS) {
                    ret = cret;
                    goto end;
                }
            }
        } else if (entry->certificate_entry && entry->certificate_chain != NULL) {
            cret = add_certificate_chain_bags(&cert_bags, entry->alias,
                    entry->certificate_chain, NULL, 1);
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
    if (ret == JO_KS_STORE_FAILED
            && (pbe_nid_unsupported(key_nid) || (cert_nid > 0 && pbe_nid_unsupported(cert_nid)))) {
        ret = JO_KS_ALGORITHM_UNSUPPORTED;
    }
    OPENSSL_free(der);
    PKCS12_free(p12);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(key_bags, PKCS12_SAFEBAG_free);
    sk_PKCS12_SAFEBAG_pop_free(cert_bags, PKCS12_SAFEBAG_free);
    OPENSSL_clear_free(pass, password_len + 1);
    rand_clear_java_srand_call();
    return ret;
}

/*
 * Decrypt a key kept encrypted by a null-password load, with the password the
 * caller gives now; the entry keeps its encrypted form. A wrong password is the
 * same refusal as for a decrypted key. PKCS#12 derives differently from a NULL
 * and an empty password, so an empty one is tried both ways, as ks_load does.
 */
static int32_t decrypt_pending_key(const ks_entry *entry, const uint8_t *password, size_t password_len,
                                   EVP_PKEY **out) {
    const unsigned char *p = entry->pending_key;
    X509_SIG *sig = d2i_X509_SIG(NULL, &p, (long) entry->pending_key_len);
    if (sig == NULL) {
        return JO_KS_DECODE_KEY_FAILED;
    }
    char *pass = copy_password(password, password_len);
    if (password != NULL && password_len != 0 && pass == NULL) {
        X509_SIG_free(sig);
        return JO_INPUT_TOO_LONG_INT32;
    }
    ERR_set_mark();
    PKCS8_PRIV_KEY_INFO *p8 = PKCS8_decrypt_ex(sig, pass, (int) password_len,
            get_global_jostle_ossl_lib_ctx(), NULL);
    if (p8 == NULL && pass == NULL) {
        p8 = PKCS8_decrypt_ex(sig, "", 0, get_global_jostle_ossl_lib_ctx(), NULL);
    }
    ERR_pop_to_mark();
    int32_t ret = JO_KS_DECODE_KEY_FAILED;
    if (p8 == NULL) {
        const X509_ALGOR *alg = NULL;
        X509_SIG_get0(sig, &alg, NULL);
        if (alg != NULL && pbe_algor_unsupported(alg)) {
            ret = JO_KS_ALGORITHM_UNSUPPORTED;
        }
    } else {
        *out = EVP_PKCS82PKEY_ex(p8, get_global_jostle_ossl_lib_ctx(), NULL);
        ret = *out != NULL ? JO_SUCCESS : JO_KS_DECODE_KEY_FAILED;
    }
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_SIG_free(sig);
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
    if (entry == NULL || !holds_key(entry)) {
        return JO_SUCCESS;
    }
    EVP_PKEY *pending = NULL;
    if (entry->key == NULL) {
        int32_t dret = decrypt_pending_key(entry, password, password_len, &pending);
        if (dret != JO_SUCCESS) {
            return dret;
        }
    } else if (!password_matches(entry, password, password_len)) {
        return JO_KS_DECODE_KEY_FAILED;
    }

    key_spec spec;
    spec.key = pending != NULL ? pending : entry->key;

    int32_t ret = JO_OPENSSL_ERROR;
    asn1_ctx *asn1 = asn1_writer_allocate(&ret);
    if (asn1 == NULL || ret != JO_SUCCESS) {
        EVP_PKEY_free(pending);
        return ret;
    }

    size_t encoded_len = 0;
    ret = asn1_writer_encode_private_key(asn1, &spec, &encoded_len, PRIVATE_KEY_DEFAULT_ENCODING);
    if (ret != 1) {
        asn1_writer_free(asn1);
        EVP_PKEY_free(pending);
        return ret == 0 ? JO_KS_ENCODE_KEY_FAILED : ret;
    }

    uint8_t *encoded = OPENSSL_zalloc(encoded_len);
    jo_assert(encoded != NULL);

    size_t written = 0;
    ret = asn1_writer_get_content(asn1, encoded, &written, encoded_len);
    asn1_writer_free(asn1);
    EVP_PKEY_free(pending);
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

    clear_pending_store(ctx);
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

    int32_t ret = JO_OPENSSL_ERROR;
    key_spec *spec = asn1_writer_decode_private_key(key, key_len, &ret);
    if (spec == NULL) {
        OPENSSL_clear_free(password_copy, password_len);
        return ret == JO_OPENSSL_ERROR ? JO_KS_DECODE_KEY_FAILED : ret;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    drop_key(entry);

    entry->key = spec->key;
    entry->certificate_entry = 0;
    clear_secret(entry);
    spec->key = NULL;
    free_key_spec(spec);
    clear_key_password(entry);
    entry->key_password = password_copy;
    entry->key_password_len = password_len;
    return JO_SUCCESS;
}

/*
 * Both OIDs must be dotted numeric forms; the RFC 7292 one must also be known
 * to OpenSSL, since the bag it writes is built from a NID. Checked when an OID
 * is set, not at store, so a store never meets an entry it cannot write.
 */
static int secret_oids_valid(const char *rfc_oid, const char *sun_oid) {
    ERR_set_mark();
    ASN1_OBJECT *rfc = OBJ_txt2obj(rfc_oid, 1);
    ASN1_OBJECT *sun = OBJ_txt2obj(sun_oid, 1);
    int valid = rfc != NULL && sun != NULL && OBJ_obj2nid(rfc) != NID_undef;
    ASN1_OBJECT_free(rfc);
    ASN1_OBJECT_free(sun);
    ERR_pop_to_mark();
    return valid;
}

int32_t ks_set_secret(ks_ctx *ctx, const char *alias, const uint8_t *key, size_t key_len,
                      const char *rfc_oid, const char *sun_oid,
                      const uint8_t *password, size_t password_len) {
    /* Bridge-validated: non-null pointers, 0 < key_len <= KS_SECRET_MAX_LEN. */
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);
    jo_assert(key != NULL);
    jo_assert(key_len > 0 && key_len <= KS_SECRET_MAX_LEN);
    jo_assert(rfc_oid != NULL);
    jo_assert(sun_oid != NULL);
    jo_assert(password != NULL || password_len == 0);

    clear_pending_store(ctx);
    ERR_clear_error();

    if (password_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    if (!secret_oids_valid(rfc_oid, sun_oid)) {
        return JO_KS_SECRET_OID_INVALID;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    drop_key(entry);
    clear_certificate_chain(entry);
    entry->certificate_entry = 0;
    clear_secret(entry);
    entry->secret = OPENSSL_memdup(key, key_len);
    entry->secret_rfc_oid = OPENSSL_strdup(rfc_oid);
    entry->secret_sun_oid = OPENSSL_strdup(sun_oid);
    jo_assert(entry->secret != NULL && entry->secret_rfc_oid != NULL
              && entry->secret_sun_oid != NULL);
    entry->secret_len = key_len;
    return set_key_password(entry, password, password_len);
}

int32_t ks_set_secret_oids(ks_ctx *ctx, const char *alias, const char *rfc_oid,
                           const char *sun_oid) {
    /* Bridge-validated: non-null pointers. */
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);
    jo_assert(rfc_oid != NULL);
    jo_assert(sun_oid != NULL);

    clear_pending_store(ctx);
    ERR_clear_error();

    ks_entry *entry = find_entry(ctx, alias);
    if (entry == NULL || entry->secret == NULL) {
        return JO_KS_NOT_SECRET_ENTRY;
    }
    if (!secret_oids_valid(rfc_oid, sun_oid)) {
        return JO_KS_SECRET_OID_INVALID;
    }

    char *rfc = OPENSSL_strdup(rfc_oid);
    char *sun = OPENSSL_strdup(sun_oid);
    jo_assert(rfc != NULL && sun != NULL);
    OPENSSL_free(entry->secret_rfc_oid);
    OPENSSL_free(entry->secret_sun_oid);
    entry->secret_rfc_oid = rfc;
    entry->secret_sun_oid = sun;
    return JO_SUCCESS;
}

/* DER length octets for n, which KS_SECRET_MAX_LEN keeps below 65536. */
static size_t der_len_size(size_t n) {
    return n < 0x80 ? 1 : (n < 0x100 ? 2 : 3);
}

static uint8_t *der_put_len(uint8_t *p, size_t n) {
    if (n < 0x80) {
        *p++ = (uint8_t) n;
    } else if (n < 0x100) {
        *p++ = 0x81;
        *p++ = (uint8_t) n;
    } else {
        *p++ = 0x82;
        *p++ = (uint8_t) (n >> 8);
        *p++ = (uint8_t) n;
    }
    return p;
}

/*
 * SEQUENCE { OBJECT IDENTIFIER, OCTET STRING } of a secret key, written by
 * hand into one buffer the caller clear-frees.
 */
static int32_t encode_secret(const char *rfc_oid, const uint8_t *key, size_t key_len,
                             uint8_t **out, size_t *out_len) {
    unsigned char *oid_der = NULL;
    ASN1_OBJECT *oid = OBJ_txt2obj(rfc_oid, 1);
    int oid_der_len = oid == NULL ? -1 : i2d_ASN1_OBJECT(oid, &oid_der);
    ASN1_OBJECT_free(oid);
    if (OPS_OPENSSL_ERROR_9 oid_der_len <= 0 || oid_der == NULL) {
        OPENSSL_free(oid_der);
        return JO_KS_ENCODE_KEY_FAILED;
    }

    size_t octets_len = 1 + der_len_size(key_len) + key_len;
    size_t content_len = (size_t) oid_der_len + octets_len;
    size_t total = 1 + der_len_size(content_len) + content_len;
    uint8_t *der = OPENSSL_zalloc(total);
    jo_assert(der != NULL);

    uint8_t *p = der;
    *p++ = 0x30;
    p = der_put_len(p, content_len);
    memcpy(p, oid_der, (size_t) oid_der_len);
    p += oid_der_len;
    *p++ = 0x04;
    p = der_put_len(p, key_len);
    memcpy(p, key, key_len);
    p += key_len;
    jo_assert((size_t) (p - der) == total);
    OPENSSL_free(oid_der);

    *out = der;
    *out_len = total;
    return JO_SUCCESS;
}

/*
 * Decrypt a secret kept encrypted by a null-password load, with the password
 * the caller gives now; the entry keeps its encrypted form.
 */
static int32_t decrypt_pending_secret(const ks_entry *entry, const uint8_t *password, size_t password_len,
                                      uint8_t **out, size_t *out_len) {
    const unsigned char *p = entry->pending_secret;
    X509_SIG *sig = d2i_X509_SIG(NULL, &p, (long) entry->pending_secret_len);
    if (sig == NULL) {
        return JO_KS_DECODE_KEY_FAILED;
    }
    char *pass = copy_password(password, password_len);
    if (password != NULL && password_len != 0 && pass == NULL) {
        X509_SIG_free(sig);
        return JO_INPUT_TOO_LONG_INT32;
    }
    ERR_set_mark();
    PKCS8_PRIV_KEY_INFO *p8 = PKCS8_decrypt_ex(sig, pass, (int) password_len,
            get_global_jostle_ossl_lib_ctx(), NULL);
    if (p8 == NULL && pass == NULL) {
        p8 = PKCS8_decrypt_ex(sig, "", 0, get_global_jostle_ossl_lib_ctx(), NULL);
    }
    ERR_pop_to_mark();
    int32_t ret = JO_KS_DECODE_KEY_FAILED;
    const ASN1_OBJECT *key_oid = NULL;
    const unsigned char *key = NULL;
    int key_len = 0;
    char oid_text[128];
    if (p8 == NULL) {
        const X509_ALGOR *alg = NULL;
        X509_SIG_get0(sig, &alg, NULL);
        if (alg != NULL && pbe_algor_unsupported(alg)) {
            ret = JO_KS_ALGORITHM_UNSUPPORTED;
        }
    } else if (PKCS8_pkey_get0(&key_oid, &key, &key_len, NULL, p8) && key_oid != NULL && key != NULL
               && key_len > 0 && key_len <= KS_SECRET_MAX_LEN) {
        int oid_len = OBJ_obj2txt(oid_text, sizeof(oid_text), key_oid, 1);
        if (oid_len > 0 && oid_len < (int) sizeof(oid_text)) {
            ret = encode_secret(oid_text, key, (size_t) key_len, out, out_len);
        }
    }
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_SIG_free(sig);
    OPENSSL_clear_free(pass, password_len + 1);
    return ret;
}

int32_t ks_get_secret(ks_ctx *ctx, const char *alias, uint8_t **out, size_t *out_len,
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
    if (entry == NULL || !holds_secret(entry)) {
        return JO_SUCCESS;
    }
    if (entry->secret == NULL) {
        return decrypt_pending_secret(entry, password, password_len, out, out_len);
    }
    if (!entry->secret_any_password && !password_matches(entry, password, password_len)) {
        return JO_KS_DECODE_KEY_FAILED;
    }
    jo_assert(entry->secret_len <= KS_SECRET_MAX_LEN);

    return encode_secret(entry->secret_rfc_oid, entry->secret, entry->secret_len, out, out_len);
}

int32_t ks_is_secret_entry(ks_ctx *ctx, const char *alias) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);

    ks_entry *entry = find_entry(ctx, alias);
    return entry != NULL && holds_secret(entry) ? 1 : 0;
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
            return JO_OPENSSL_ERROR;
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
            return JO_OPENSSL_ERROR;
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

    clear_pending_store(ctx);

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
        /* Bound to this library's context, not the process default. */
        X509 *cert = X509_new_ex(get_global_jostle_ossl_lib_ctx(), NULL);
        if (cert == NULL || d2i_X509(&cert, &p, (long) (end - p)) == NULL) {
            X509_free(cert);
            sk_X509_pop_free(parsed, X509_free);
            return JO_KS_LOAD_FAILED;
        }
        if (!sk_X509_push(parsed, cert)) {
            X509_free(cert);
            sk_X509_pop_free(parsed, X509_free);
            return JO_OPENSSL_ERROR;
        }
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    clear_certificate_chain(entry);
    entry->certificate_chain = parsed;
    if (!holds_key(entry) && !holds_secret(entry)) {
        /*
         * A chain attached to an alias with no private key is a trusted-cert
         * entry (matching load_cert_bag's keyless-bag handling). Without this
         * the entry would be neither a key entry nor a cert entry: listed by
         * ks_get_aliases / ks_contains_alias yet silently dropped by ks_store.
         * The SPI always sets the key first (so entry->key != NULL here for a
         * key entry, leaving certificate_entry 0); this only affects direct NI
         * callers who attach a bare chain.
         */
        entry->certificate_entry = 1;
    }
    return JO_SUCCESS;
}

int32_t ks_set_certificate_entry(ks_ctx *ctx, const char *alias, const uint8_t *certificate, size_t certificate_len) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);
    jo_assert(certificate != NULL || certificate_len == 0);

    clear_pending_store(ctx);

    if (certificate == NULL || certificate_len == 0) {
        return JO_KS_LOAD_FAILED;
    }
    if (certificate_len > INT32_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ks_entry *entry = find_or_create_entry(ctx, alias);
    if (holds_key(entry) || holds_secret(entry)) {
        return JO_KS_ALIAS_HOLDS_KEY;
    }

    const unsigned char *p = certificate;
    /* Bound to this library's context, not the process default. */
    X509 *cert = X509_new_ex(get_global_jostle_ossl_lib_ctx(), NULL);
    if (cert == NULL || d2i_X509(&cert, &p, (long) certificate_len) == NULL
        || p != certificate + certificate_len) {
        X509_free(cert);
        return JO_KS_LOAD_FAILED;
    }

    STACK_OF(X509) *stack = sk_X509_new_null();
    jo_assert(stack != NULL);
    if (!sk_X509_push(stack, cert)) {
        X509_free(cert);
        sk_X509_free(stack);
        return JO_OPENSSL_ERROR;
    }

    clear_certificate_chain(entry);
    entry->certificate_chain = stack;
    entry->certificate_entry = 1;
    return JO_SUCCESS;
}

int32_t ks_delete_entry(ks_ctx *ctx, const char *alias) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);

    clear_pending_store(ctx);

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
    return entry != NULL && (holds_key(entry) || holds_secret(entry)) ? 1 : 0;
}

int32_t ks_is_certificate_entry(ks_ctx *ctx, const char *alias) {
    jo_assert(ctx != NULL);
    jo_assert(alias != NULL);

    ks_entry *entry = find_entry(ctx, alias);
    return entry != NULL && !holds_key(entry) && !holds_secret(entry)
           && entry->certificate_entry ? 1 : 0;
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
