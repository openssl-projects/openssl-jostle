//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"
#include "ops.h"
#include "x509.h"

/*
 * OPS fault-injection offsets for this file occupy the 7000 BLOCK. Blocks
 * 1000-6000 are taken by rsa.c, rsa_oaep.c, rsa_pkcs1.c and their neighbours
 * (measured); reusing one would make two call sites indistinguishable to the
 * test that drives them, since the offset IS how a test names the site.
 */

/* Longest dotted-decimal OID we will render. OBJ_obj2txt truncates rather
 * than overflowing, and an OID this long is already far outside X.509. */
#define OID_TEXT_MAX 128

/*
 * The certificate is decoded into an X509_new_ex object bound to the global lib
 * ctx. The binding is load-bearing twice over: the embedded
 * SubjectPublicKeyInfo decodes through the CERTIFICATE's lib ctx, so an
 * unbound certificate builds its key in the default provider even under a
 * fips=yes ctx, and X509_verify resolves the signature algorithm the same way.
 * Measured: plain d2i_X509 under a FIPS ctx yields an ED25519 key the module
 * does not serve.
 */
/*
 * Handle plumbing. The wrapper exists so an accessor can tell a certificate
 * handle from a CRL handle; a raw pointer cannot, and the mismatch used to
 * reach libcrypto and fault. See x509.h for the measured crashes.
 */
static x509_handle *handle_new(uint32_t kind, void *obj)
{
    x509_handle *h = OPENSSL_malloc(sizeof(x509_handle));
    if (h == NULL)
    {
        return NULL;
    }
    h->kind = kind;
    h->obj = obj;
    return h;
}

/*
 * Null and kind, in that order, BEFORE the object is touched. Checked here
 * rather than in the two bridges so both inherit it once and neither can
 * forget; the glue only unwraps.
 */
static int32_t handle_unwrap(x509_handle *h, uint32_t kind, void **out)
{
    if (h == NULL)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (h->kind != kind)
    {
        return JO_CERT_CTX_WRONG_KIND;
    }
    *out = h->obj;
    return JO_SUCCESS;
}

int32_t x509_cert_decode(const uint8_t *der, size_t der_len, size_t max_bytes,
                         x509_handle **out, int32_t *consumed)
{
    const unsigned char *p = der;
    X509 *cert;

    jo_assert(der != NULL);
    jo_assert(out != NULL);
    jo_assert(consumed != NULL);
    jo_assert(der_len > 0);
    /* The ceiling the CALLER chose, asserted as an invariant because the bridge
     * has already refused anything above it typed. Asserting a fixed macro here
     * instead would abort the JVM for a deployment that raised the property. */
    jo_assert(max_bytes > 0 && der_len <= max_bytes);

    *out = NULL;
    *consumed = 0;

    ERR_clear_error();

    cert = X509_new_ex(get_global_jostle_ossl_lib_ctx(), NULL);
    if (OPS_OPENSSL_ERROR_1 cert == NULL)
    {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(7000);
    }
    if (OPS_OPENSSL_ERROR_2 d2i_X509(&cert, &p, (long) der_len) == NULL)
    {
        X509_free(cert);
        return JO_CERT_DECODE_FAILED;
    }

    /*
     * Trailing octets are NOT an error here. The JCA contract reads ONE object
     * from a stream and leaves the remainder for the next call, which is the
     * opposite of the whole-blob decoders in asn1_util.c that refuse trailing
     * data. Reporting what was consumed is what lets the Java layer position
     * the stream.
     */
    *consumed = (int32_t) (p - der);
    *out = handle_new(X509_KIND_CERT, cert);
    if (*out == NULL)
    {
        X509_free(cert);
        *consumed = 0;
        return JO_OPENSSL_ERROR;
    }
    return JO_SUCCESS;
}

int32_t x509_cert_free(x509_handle *h)
{
    X509 *cert = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CERT, (void **) &cert);
    if (kind_rc != JO_SUCCESS)
    {
        /* Frees NOTHING on the wrong kind: freeing through the other type is
         * the fault this wrapper exists to stop. A correct dispose still
         * works afterwards. */
        return kind_rc;
    }
    X509_free(cert);
    /* Scrubbed before release as defence in depth; a dispose after dispose is
     * still a caller fault. */
    h->kind = 0;
    h->obj = NULL;
    OPENSSL_free(h);
    return JO_SUCCESS;
}

/*
 * The signature AlgorithmIdentifier and the signature BIT STRING, as DER.
 * Neither X509_ALGOR nor ASN1_BIT_STRING caches an encoding, so these are
 * always freshly encoded and always DER.
 */
static int32_t sig_parts(X509 *cert, uint8_t **alg_der, int *alg_len,
                         uint8_t **sig_der, int *sig_len)
{
    const ASN1_BIT_STRING *sig;
    const X509_ALGOR *alg;

    X509_get0_signature(&sig, &alg, cert);
    if (sig == NULL || alg == NULL)
    {
        return JO_OPENSSL_ERROR;
    }
    *alg_len = i2d_X509_ALGOR((X509_ALGOR *) alg, alg_der);
    if (OPS_OPENSSL_ERROR_3 *alg_len <= 0)
    {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(7001);
    }
    *sig_len = i2d_ASN1_BIT_STRING((ASN1_BIT_STRING *) sig, sig_der);
    if (OPS_OPENSSL_ERROR_4 *sig_len <= 0)
    {
        OPENSSL_free(*alg_der);
        *alg_der = NULL;
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(7002);
    }
    return JO_SUCCESS;
}

/*
 * DER definite-length SEQUENCE header for `len` content octets. Writes into
 * `out` when it is non-NULL and returns the header size either way, so the
 * size query and the write cannot disagree about the encoding.
 */
static size_t seq_header(size_t len, uint8_t *out)
{
    size_t n = 0;
    size_t t = len;
    size_t i;

    if (len < 0x80)
    {
        if (out != NULL)
        {
            out[0] = 0x30;
            out[1] = (uint8_t) len;
        }
        return 2;
    }
    while (t > 0)
    {
        n++;
        t >>= 8;
    }
    if (out != NULL)
    {
        out[0] = 0x30;
        out[1] = (uint8_t) (0x80 | n);
        for (i = 0; i < n; i++)
        {
            out[2 + i] = (uint8_t) (len >> (8 * (n - 1 - i)));
        }
    }
    return 2 + n;
}

/*
 * The certificate's encoding, COMPOSED rather than taken from i2d_X509.
 *
 * i2d_X509 re-emits X509_CINF's cached octets, so for an input whose TBS was
 * BER it would hand back BER beside a DER TBS — an object whose two encodings
 * describe the same certificate in different languages. Composing from the
 * forced re-encode is what makes the normalisation actually normalise.
 *
 * Caller frees with OPENSSL_free.
 */
static int32_t compose_encoding(X509 *cert, uint8_t **out, size_t *out_len,
                                uint8_t **tbs_out, int *tbs_out_len)
{
    uint8_t *tbs = NULL;
    uint8_t *alg = NULL;
    uint8_t *sig = NULL;
    int tbs_len;
    int alg_len = 0;
    int sig_len = 0;
    int32_t ret;
    size_t content;
    size_t hdr;
    uint8_t *buf;

    *out = NULL;
    *out_len = 0;

    tbs_len = i2d_re_X509_tbs(cert, &tbs);
    if (OPS_OPENSSL_ERROR_5 tbs_len <= 0)
    {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(7003);
    }
    ret = sig_parts(cert, &alg, &alg_len, &sig, &sig_len);
    if (ret != JO_SUCCESS)
    {
        OPENSSL_free(tbs);
        return ret;
    }

    content = (size_t) tbs_len + (size_t) alg_len + (size_t) sig_len;
    hdr = seq_header(content, NULL);
    if (OPS_INT32_OVERFLOW_1 content > (size_t) INT32_MAX - hdr)
    {
        OPENSSL_free(tbs);
        OPENSSL_free(alg);
        OPENSSL_free(sig);
        return JO_OUTPUT_TOO_LONG_INT32;
    }

    buf = OPENSSL_malloc(hdr + content);
    if (OPS_OPENSSL_ERROR_6 buf == NULL)
    {
        OPENSSL_free(tbs);
        OPENSSL_free(alg);
        OPENSSL_free(sig);
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(7004);
    }
    seq_header(content, buf);
    memcpy(buf + hdr, tbs, (size_t) tbs_len);
    memcpy(buf + hdr + tbs_len, alg, (size_t) alg_len);
    memcpy(buf + hdr + tbs_len + alg_len, sig, (size_t) sig_len);

    OPENSSL_free(alg);
    OPENSSL_free(sig);

    /* The TBS travels out rather than being re-encoded a second time by the
     * caller: i2d_re_X509_tbs is not free, and two encodes of the same value
     * are two chances to disagree. */
    *tbs_out = tbs;
    *tbs_out_len = tbs_len;
    *out = buf;
    *out_len = hdr + content;
    return JO_SUCCESS;
}

/*
 * Every variable-length field, gathered once so both the length query and the
 * fill share one code path. A second implementation for the length would be a
 * second source of truth for how big the answer is.
 */
typedef struct {
    uint8_t *data[X509_SLOT_COUNT];
    int32_t len[X509_SLOT_COUNT];
    int      owned[X509_SLOT_COUNT];   /* 1 when OPENSSL_free must be called */
    uint8_t  oid_text[OID_TEXT_MAX];
    uint8_t  spki_oid_text[OID_TEXT_MAX];
} cert_slots;

static void slots_free(cert_slots *s)
{
    int i;

    for (i = 0; i < X509_SLOT_COUNT; i++)
    {
        if (s->owned[i] && s->data[i] != NULL)
        {
            OPENSSL_free(s->data[i]);
        }
        s->data[i] = NULL;
        s->len[i] = 0;
        s->owned[i] = 0;
    }
}

static int32_t take(cert_slots *s, int slot, uint8_t *p, int len)
{
    if (len < 0)
    {
        return JO_OPENSSL_ERROR;
    }
    s->data[slot] = p;
    s->len[slot] = len;
    s->owned[slot] = 1;
    return JO_SUCCESS;
}

static int32_t gather(X509 *cert, cert_slots *s)
{
    uint8_t *tmp = NULL;
    int len;
    int32_t ret;
    size_t enc_len = 0;
    uint8_t *enc = NULL;
    const ASN1_BIT_STRING *sig;
    const X509_ALGOR *alg;
    const ASN1_OBJECT *alg_oid;
    int ptype = 0;
    const void *pval = NULL;

    memset(s, 0, sizeof(*s));

    ret = compose_encoding(cert, &enc, &enc_len, &tmp, &len);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    if (enc_len > (size_t) INT32_MAX)
    {
        OPENSSL_free(enc);
        OPENSSL_free(tmp);
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    (void) take(s, X509_SLOT_ENCODED, enc, (int) enc_len);
    if (len <= 0 || take(s, X509_SLOT_TBS, tmp, len) != JO_SUCCESS)
    {
        goto fail;
    }

    /*
     * The serial as its whole INTEGER TLV. ASN1_INTEGER_to_BN loses the sign —
     * OpenSSL stores a magnitude plus a type flag — and PKITS carries a
     * genuinely negative serial, so the Java side reads the content octets as
     * two's complement instead.
     */
    tmp = NULL;
    len = i2d_ASN1_INTEGER((ASN1_INTEGER *) X509_get0_serialNumber(cert), &tmp);
    if (len <= 0 || take(s, X509_SLOT_SERIAL, tmp, len) != JO_SUCCESS)
    {
        goto fail;
    }

    tmp = NULL;
    len = i2d_X509_NAME(X509_get_issuer_name(cert), &tmp);
    if (len <= 0 || take(s, X509_SLOT_ISSUER, tmp, len) != JO_SUCCESS)
    {
        goto fail;
    }

    tmp = NULL;
    len = i2d_X509_NAME(X509_get_subject_name(cert), &tmp);
    if (len <= 0 || take(s, X509_SLOT_SUBJECT, tmp, len) != JO_SUCCESS)
    {
        goto fail;
    }

    X509_get0_signature(&sig, &alg, cert);
    if (sig == NULL || alg == NULL)
    {
        goto fail;
    }
    /* The BIT STRING's CONTENT, which is what getSignature() returns — not the
     * encoded TLV, and not affected by a non-octet-aligned unused-bit count. */
    s->data[X509_SLOT_SIGNATURE] = (uint8_t *) ASN1_STRING_get0_data((const ASN1_STRING *) sig);
    s->len[X509_SLOT_SIGNATURE] = ASN1_STRING_length((const ASN1_STRING *) sig);
    s->owned[X509_SLOT_SIGNATURE] = 0;
    if (s->len[X509_SLOT_SIGNATURE] < 0)
    {
        goto fail;
    }

    X509_ALGOR_get0(&alg_oid, &ptype, &pval, alg);
    len = OBJ_obj2txt((char *) s->oid_text, OID_TEXT_MAX, alg_oid, 1);
    if (len <= 0 || len >= OID_TEXT_MAX)
    {
        goto fail;
    }
    s->data[X509_SLOT_SIGALG_OID] = s->oid_text;
    s->len[X509_SLOT_SIGALG_OID] = len;
    s->owned[X509_SLOT_SIGALG_OID] = 0;

    /*
     * Parameters. An ABSENT parameter and an explicit ASN.1 NULL are both
     * reported as "no parameters", which is SUN's reading and the one ruled
     * for; BouncyCastle returns the encoded NULL instead, and that divergence
     * is pinned on the Java side.
     */
    if (ptype != V_ASN1_UNDEF && ptype != V_ASN1_NULL)
    {
        ASN1_TYPE *param = ASN1_TYPE_new();

        if (param == NULL)
        {
            goto fail;
        }
        if (ASN1_TYPE_set1(param, ptype, pval) != 1)
        {
            ASN1_TYPE_free(param);
            goto fail;
        }
        tmp = NULL;
        len = i2d_ASN1_TYPE(param, &tmp);
        ASN1_TYPE_free(param);
        if (len <= 0 || take(s, X509_SLOT_SIGALG_PARAMS, tmp, len) != JO_SUCCESS)
        {
            goto fail;
        }
    }

    /*
     * The SubjectPublicKeyInfo algorithm OID, read from X509_PUBKEY WITHOUT
     * decoding the key. Measured: on a module that does not serve the
     * algorithm, X509_get0_pubkey returns NULL while this still answers — so
     * the Java layer can say "this provider does not serve 1.3.101.112" rather
     * than the same sentence for a key that is simply malformed.
     */
    {
        X509_PUBKEY *pub = X509_get_X509_PUBKEY(cert);
        ASN1_OBJECT *spki_alg = NULL;

        /* The whole SubjectPublicKeyInfo. i2d_X509_PUBKEY is a fresh encode --
         * X509_PUBKEY carries no encoding cache -- so this is DER like every
         * other slot, and it is what the public key is rebuilt from. */
        tmp = NULL;
        len = (pub != NULL) ? i2d_X509_PUBKEY(pub, &tmp) : 0;
        if (len > 0 && take(s, X509_SLOT_SPKI, tmp, len) != JO_SUCCESS)
        {
            goto fail;
        }

        if (pub != NULL && X509_PUBKEY_get0_param(&spki_alg, NULL, NULL, NULL, pub) == 1
                && spki_alg != NULL)
        {
            len = OBJ_obj2txt((char *) s->spki_oid_text, OID_TEXT_MAX, spki_alg, 1);
            if (len > 0 && len < OID_TEXT_MAX)
            {
                s->data[X509_SLOT_SPKI_ALG_OID] = s->spki_oid_text;
                s->len[X509_SLOT_SPKI_ALG_OID] = len;
                s->owned[X509_SLOT_SPKI_ALG_OID] = 0;
            }
        }
    }

    {
        const ASN1_BIT_STRING *iuid = NULL;
        const ASN1_BIT_STRING *suid = NULL;

        X509_get0_uids(cert, &iuid, &suid);
        if (iuid != NULL)
        {
            s->data[X509_SLOT_ISSUER_UID] = (uint8_t *) ASN1_STRING_get0_data((const ASN1_STRING *) iuid);
            s->len[X509_SLOT_ISSUER_UID] = ASN1_STRING_length((const ASN1_STRING *) iuid);
        }
        if (suid != NULL)
        {
            s->data[X509_SLOT_SUBJECT_UID] = (uint8_t *) ASN1_STRING_get0_data((const ASN1_STRING *) suid);
            s->len[X509_SLOT_SUBJECT_UID] = ASN1_STRING_length((const ASN1_STRING *) suid);
        }
    }

    return JO_SUCCESS;

fail:
    slots_free(s);
    return JO_OPENSSL_ERROR;
}

int32_t x509_cert_fields_len(x509_handle *h)
{
    X509 *cert = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CERT, (void **) &cert);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    cert_slots s;
    int32_t ret;
    size_t total = 0;
    int i;

    jo_assert(cert != NULL);

    ERR_clear_error();
    ret = gather(cert, &s);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    for (i = 0; i < X509_SLOT_COUNT; i++)
    {
        total += (size_t) s.len[i];
    }
    slots_free(&s);

    if (total > (size_t) INT32_MAX)
    {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    return (int32_t) total;
}

/*
 * Seconds since the epoch for an ASN1_TIME.
 *
 * Via ASN1_TIME_diff against a zero ASN1_TIME rather than ASN1_TIME_to_tm plus
 * timegm: timegm is absent on MSVC, and Windows is a shipped bundle
 * (resources/native/windows), so the tm route would build everywhere we test
 * and fail on a platform we ship. No other util file converts an ASN1_TIME, so
 * there was no precedent to copy.
 */
static int32_t time_secs(const ASN1_TIME *t, int64_t *out)
{
    ASN1_TIME *epoch;
    int days = 0;
    int secs = 0;
    int ok;

    if (t == NULL)
    {
        return JO_OPENSSL_ERROR;
    }
    epoch = ASN1_TIME_set(NULL, 0);
    if (epoch == NULL)
    {
        return JO_OPENSSL_ERROR;
    }
    ok = ASN1_TIME_diff(&days, &secs, epoch, t);
    ASN1_TIME_free(epoch);
    if (ok != 1)
    {
        return JO_OPENSSL_ERROR;
    }
    *out = (int64_t) days * 86400 + (int64_t) secs;
    return JO_SUCCESS;
}

/*
 * Unused trailing bits of a BIT STRING, which the JCA needs because it returns
 * a boolean[] whose LENGTH is the declared bit count. The low three flag bits
 * only carry that count when ASN1_STRING_FLAG_BITS_LEFT says so.
 */
static int bits_of(const ASN1_BIT_STRING *bs)
{
    int bits = ASN1_STRING_length((const ASN1_STRING *) bs) * 8;

    if (bs->flags & ASN1_STRING_FLAG_BITS_LEFT)
    {
        bits -= (int) (bs->flags & 0x07);
    }
    return bits < 0 ? 0 : bits;
}

/*
 * X509_get_ext_d2i returns NULL for three different situations and the caller
 * must not conflate them (measured from OpenSSL's own doc for X509V3_get_d2i):
 * crit == -1 is ABSENT, crit == -2 is the extension occurring MORE THAN ONCE,
 * and NULL with crit >= 0 is present-but-undecodable. Reading the last two as
 * "absent" makes a malformed certificate read as "not a CA" or "no key usage"
 * — a certificate SUN refuses at parse would silently lose its constraints.
 */
static int32_t ext_lookup(X509 *cert, int nid, void **out)
{
    int crit = -1;

    *out = X509_get_ext_d2i(cert, nid, &crit, NULL);
    if (*out != NULL)
    {
        return JO_SUCCESS;
    }
    if (crit == -1)
    {
        return JO_SUCCESS;      /* genuinely absent */
    }
    return JO_CERT_EXTENSION_INVALID;
}

int32_t x509_cert_fields(x509_handle *h, uint8_t *blob, size_t blob_len,
                         int32_t *sizes, int32_t *info)
{
    X509 *cert = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CERT, (void **) &cert);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    cert_slots s;
    int32_t ret;
    size_t off = 0;
    int i;
    int64_t nb = 0;
    int64_t na = 0;
    BASIC_CONSTRAINTS *bc = NULL;
    ASN1_BIT_STRING *ku = NULL;

    jo_assert(cert != NULL);
    jo_assert(blob != NULL);
    jo_assert(sizes != NULL);
    jo_assert(info != NULL);

    ERR_clear_error();
    ret = gather(cert, &s);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    for (i = 0; i < X509_SLOT_COUNT; i++)
    {
        if (s.len[i] > 0)
        {
            if (off + (size_t) s.len[i] > blob_len)
            {
                slots_free(&s);
                return JO_OUTPUT_TOO_SMALL;
            }
            memcpy(blob + off, s.data[i], (size_t) s.len[i]);
            off += (size_t) s.len[i];
        }
        sizes[i] = s.len[i];
    }

    memset(info, 0, sizeof(int32_t) * X509_INFO_COUNT);

    /* OpenSSL's version is 0-based on the wire (RFC 5280 4.1.2.1); the JCA
     * reports 1, 2 or 3. */
    info[X509_INFO_VERSION] = (int32_t) X509_get_version(cert) + 1;

    if (time_secs(X509_get0_notBefore(cert), &nb) != JO_SUCCESS ||
        time_secs(X509_get0_notAfter(cert), &na) != JO_SUCCESS)
    {
        slots_free(&s);
        return JO_OPENSSL_ERROR;
    }
    /* Split high-then-low rather than truncated: a root expiring in 9999 is
     * past the int32 second cliff, and truncation there is silent. */
    info[X509_INFO_NOT_BEFORE_HI] = (int32_t) ((uint64_t) nb >> 32);
    info[X509_INFO_NOT_BEFORE_LO] = (int32_t) ((uint64_t) nb & 0xFFFFFFFFu);
    info[X509_INFO_NOT_AFTER_HI] = (int32_t) ((uint64_t) na >> 32);
    info[X509_INFO_NOT_AFTER_LO] = (int32_t) ((uint64_t) na & 0xFFFFFFFFu);

    /*
     * basicConstraints in JCA terms: -1 when not a CA, the pathlen when a CA
     * with one, INT32_MAX when a CA without. X509_get_pathlen cannot express
     * the three cases on its own.
     */
    info[X509_INFO_BASIC_CONSTRAINTS] = -1;
    ret = ext_lookup(cert, NID_basic_constraints, (void **) &bc);
    if (ret != JO_SUCCESS)
    {
        slots_free(&s);
        return ret;
    }
    if (bc != NULL)
    {
        if (bc->ca)
        {
            if (bc->pathlen != NULL)
            {
                long pl = ASN1_INTEGER_get(bc->pathlen);

                info[X509_INFO_BASIC_CONSTRAINTS] = (pl < 0 || pl > INT32_MAX) ? INT32_MAX : (int32_t) pl;
            }
            else
            {
                info[X509_INFO_BASIC_CONSTRAINTS] = INT32_MAX;
            }
        }
        BASIC_CONSTRAINTS_free(bc);
    }

    /*
     * keyUsage as a bit count plus the bits, rather than X509_get_key_usage's
     * flags word, because the JCA returns a boolean[] whose LENGTH is the
     * declared bit count and a flags word loses it.
     */
    ret = ext_lookup(cert, NID_key_usage, (void **) &ku);
    if (ret != JO_SUCCESS)
    {
        slots_free(&s);
        return ret;
    }
    if (ku != NULL)
    {
        int bits = bits_of(ku);
        const unsigned char *d = ASN1_STRING_get0_data(ku);
        int32_t value = 0;
        int b;

        /* Refused, not truncated. A truncated keyUsage reads as a permission
         * the certificate did not grant, which is the one failure direction
         * that must never be silent. */
        if (bits > X509_MAX_KEY_USAGE_BITS)
        {
            ASN1_BIT_STRING_free(ku);
            slots_free(&s);
            return JO_CERT_EXTENSION_INVALID;
        }
        for (b = 0; b < bits; b++)
        {
            if ((d[b / 8] >> (7 - (b % 8))) & 1)
            {
                value |= (int32_t) (1u << (31 - b));
            }
        }
        info[X509_INFO_KEY_USAGE_BITS] = bits;
        info[X509_INFO_KEY_USAGE_VALUE] = value;
        ASN1_BIT_STRING_free(ku);
    }

    {
        const ASN1_BIT_STRING *iuid = NULL;
        const ASN1_BIT_STRING *suid = NULL;

        X509_get0_uids(cert, &iuid, &suid);
        /* The DECLARED bit count, not length * 8: an earlier draft used the
         * latter and lost the unused-bit count that the keyUsage path takes
         * care to honour. */
        info[X509_INFO_ISSUER_UID_BITS] = (iuid != NULL) ? bits_of(iuid) : 0;
        info[X509_INFO_SUBJECT_UID_BITS] = (suid != NULL) ? bits_of(suid) : 0;
    }
    info[X509_INFO_EXT_COUNT] = (int32_t) X509_get_ext_count(cert);

    slots_free(&s);
    return JO_SUCCESS;
}

/*
 * Extensions. One pass produces the OID text and the extension VALUE for each,
 * concatenated in index order: all the OIDs, then all the values. The JCA
 * returns getExtensionValue() as the OCTET STRING still wrapped, so the value
 * here is the whole ASN1_OCTET_STRING TLV rather than its contents.
 */
/*
 * Extensions of a certificate OR a CRL. X509_get0_extensions and
 * X509_CRL_get0_extensions hand back the same stack type, so one
 * implementation serves both rather than a copy per object that would drift.
 */
static int32_t each_extension(const STACK_OF(X509_EXTENSION) *exts,
                              uint8_t *blob, size_t blob_len, size_t capacity,
                              int32_t *oid_sizes, int32_t *val_sizes, int32_t *critical,
                              size_t *needed)
{
    int count = (exts == NULL) ? 0 : sk_X509_EXTENSION_num(exts);
    int i;
    int j;
    size_t off = 0;
    char oid[OID_TEXT_MAX];
    char (*seen)[OID_TEXT_MAX] = NULL;

    *needed = 0;

    if (count < 0)
    {
        return JO_OPENSSL_ERROR;
    }
    /*
     * Refused BEFORE any write. The per-extension loop indexes the three
     * caller arrays by i, so a capacity below the extension count is a heap
     * overflow rather than a short answer.
     */
    if (blob != NULL && capacity < (size_t) count)
    {
        return JO_OUTPUT_TOO_SMALL;
    }

    /*
     * EVERY OID must be unique, not merely the two we decode. An earlier draft
     * caught a repeat only through X509_get_ext_d2i's crit == -2, which fires
     * for basicConstraints and keyUsage and nothing else — so a duplicated
     * authorityKeyIdentifier was ACCEPTED here while SUN refused it with
     * "Duplicate extensions not allowed" and BouncyCastle with "repeated
     * extension found". Measured on a built certificate before this was
     * written. O(n^2) over a handful of extensions costs nothing.
     */
    if (count > 1)
    {
        seen = OPENSSL_malloc(sizeof(*seen) * (size_t) count);
        if (seen == NULL)
        {
            return JO_OPENSSL_ERROR;
        }
    }

    for (i = 0; i < count; i++)
    {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT *obj;
        ASN1_OCTET_STRING *data;
        uint8_t *der = NULL;
        int oid_len;
        int val_len;

        if (ext == NULL)
        {
            OPENSSL_free(seen);
            return JO_OPENSSL_ERROR;
        }
        obj = X509_EXTENSION_get_object(ext);
        data = X509_EXTENSION_get_data(ext);
        if (obj == NULL || data == NULL)
        {
            OPENSSL_free(seen);
            return JO_OPENSSL_ERROR;
        }
        oid_len = OBJ_obj2txt(oid, OID_TEXT_MAX, obj, 1);
        if (oid_len <= 0 || oid_len >= OID_TEXT_MAX)
        {
            OPENSSL_free(seen);
            return JO_OPENSSL_ERROR;
        }
        if (seen != NULL)
        {
            for (j = 0; j < i; j++)
            {
                if (strcmp(seen[j], oid) == 0)
                {
                    OPENSSL_free(seen);
                    return JO_CERT_EXTENSION_INVALID;
                }
            }
            OPENSSL_strlcpy(seen[i], oid, OID_TEXT_MAX);
        }
        val_len = i2d_ASN1_OCTET_STRING(data, &der);
        if (OPS_OPENSSL_ERROR_3 val_len <= 0)
        {
            OPENSSL_free(seen);
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(7008);
        }

        *needed += (size_t) oid_len + (size_t) val_len;

        if (blob != NULL)
        {
            if (off + (size_t) oid_len > blob_len)
            {
                OPENSSL_free(der);
                OPENSSL_free(seen);
                return JO_OUTPUT_TOO_SMALL;
            }
            memcpy(blob + off, oid, (size_t) oid_len);
            off += (size_t) oid_len;
            oid_sizes[i] = oid_len;
            val_sizes[i] = val_len;
            critical[i] = X509_EXTENSION_get_critical(ext) ? 1 : 0;
        }
        OPENSSL_free(der);
    }

    OPENSSL_free(seen);

    if (blob == NULL)
    {
        return JO_SUCCESS;
    }

    /* Second pass for the values, so all OIDs sit before all values and the
     * Java side can walk each run with one offset. */
    for (i = 0; i < count; i++)
    {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(ext);
        uint8_t *der = NULL;
        int val_len = i2d_ASN1_OCTET_STRING(data, &der);

        if (val_len <= 0)
        {
            return JO_OPENSSL_ERROR;
        }
        if (off + (size_t) val_len > blob_len)
        {
            OPENSSL_free(der);
            return JO_OUTPUT_TOO_SMALL;
        }
        memcpy(blob + off, der, (size_t) val_len);
        off += (size_t) val_len;
        OPENSSL_free(der);
    }
    return JO_SUCCESS;
}

int32_t x509_cert_extensions_len(x509_handle *h)
{
    X509 *cert = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CERT, (void **) &cert);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    size_t needed = 0;
    int32_t ret;

    jo_assert(cert != NULL);

    ERR_clear_error();
    ret = each_extension(X509_get0_extensions(cert), NULL, 0, 0, NULL, NULL, NULL, &needed);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    if (needed > (size_t) INT32_MAX)
    {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    return (int32_t) needed;
}

int32_t x509_cert_extensions(x509_handle *h, uint8_t *blob, size_t blob_len, size_t count,
                             int32_t *oid_sizes, int32_t *val_sizes, int32_t *critical)
{
    X509 *cert = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CERT, (void **) &cert);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    size_t needed = 0;

    jo_assert(cert != NULL);
    jo_assert(blob != NULL);
    jo_assert(oid_sizes != NULL);
    jo_assert(val_sizes != NULL);
    jo_assert(critical != NULL);

    ERR_clear_error();
    return each_extension(X509_get0_extensions(cert), blob, blob_len, count,
                          oid_sizes, val_sizes, critical, &needed);
}

/* ---------------------------------------------------------------- CRLs --- */

/*
 * Same lib ctx binding rule as a certificate: X509_CRL_verify resolves the
 * signature algorithm through the CRL's OWN lib ctx, so an unbound CRL would
 * have its signature checked in the default provider even under a fips=yes
 * ctx.
 */
int32_t x509_crl_decode(const uint8_t *der, size_t der_len, size_t max_bytes,
                        x509_handle **out, int32_t *consumed)
{
    const unsigned char *p = der;
    X509_CRL *crl;

    jo_assert(der != NULL);
    jo_assert(out != NULL);
    jo_assert(consumed != NULL);
    jo_assert(der_len > 0);
    jo_assert(max_bytes > 0 && der_len <= max_bytes);

    *out = NULL;
    *consumed = 0;

    ERR_clear_error();

    crl = X509_CRL_new_ex(get_global_jostle_ossl_lib_ctx(), NULL);
    if (OPS_OPENSSL_ERROR_1 crl == NULL)
    {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(7005);
    }
    if (OPS_OPENSSL_ERROR_2 d2i_X509_CRL(&crl, &p, (long) der_len) == NULL)
    {
        X509_CRL_free(crl);
        return JO_CRL_DECODE_FAILED;
    }
    *consumed = (int32_t) (p - der);
    *out = handle_new(X509_KIND_CRL, crl);
    if (*out == NULL)
    {
        X509_CRL_free(crl);
        *consumed = 0;
        return JO_OPENSSL_ERROR;
    }
    return JO_SUCCESS;
}

int32_t x509_crl_free(x509_handle *h)
{
    X509_CRL *crl = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CRL, (void **) &crl);
    if (kind_rc != JO_SUCCESS)
    {
        /* Frees NOTHING on the wrong kind -- see x509_cert_free. */
        return kind_rc;
    }
    X509_CRL_free(crl);
    h->kind = 0;
    h->obj = NULL;
    OPENSSL_free(h);
    return JO_SUCCESS;
}

/*
 * The CRL's encoding, composed exactly as the certificate's and for the same
 * reason: i2d_X509_CRL re-emits X509_CRL_INFO's cached octets.
 */
static int32_t compose_crl_encoding(X509_CRL *crl, uint8_t **out, size_t *out_len,
                                    uint8_t **tbs_out, int *tbs_out_len)
{
    uint8_t *tbs = NULL;
    uint8_t *alg = NULL;
    uint8_t *sig = NULL;
    int tbs_len;
    int alg_len;
    int sig_len;
    size_t content;
    size_t hdr;
    uint8_t *buf;
    const ASN1_BIT_STRING *sigbs;
    const X509_ALGOR *algor;

    *out = NULL;
    *out_len = 0;

    tbs_len = i2d_re_X509_CRL_tbs(crl, &tbs);
    if (OPS_OPENSSL_ERROR_5 tbs_len <= 0)
    {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(7006);
    }
    X509_CRL_get0_signature(crl, &sigbs, &algor);
    if (sigbs == NULL || algor == NULL)
    {
        OPENSSL_free(tbs);
        return JO_OPENSSL_ERROR;
    }
    alg_len = i2d_X509_ALGOR((X509_ALGOR *) algor, &alg);
    if (alg_len <= 0)
    {
        OPENSSL_free(tbs);
        return JO_OPENSSL_ERROR;
    }
    sig_len = i2d_ASN1_BIT_STRING((ASN1_BIT_STRING *) sigbs, &sig);
    if (sig_len <= 0)
    {
        OPENSSL_free(tbs);
        OPENSSL_free(alg);
        return JO_OPENSSL_ERROR;
    }

    content = (size_t) tbs_len + (size_t) alg_len + (size_t) sig_len;
    hdr = seq_header(content, NULL);
    if (OPS_INT32_OVERFLOW_2 content > (size_t) INT32_MAX - hdr)
    {
        OPENSSL_free(tbs);
        OPENSSL_free(alg);
        OPENSSL_free(sig);
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    buf = OPENSSL_malloc(hdr + content);
    if (OPS_OPENSSL_ERROR_6 buf == NULL)
    {
        OPENSSL_free(tbs);
        OPENSSL_free(alg);
        OPENSSL_free(sig);
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_6(7007);
    }
    seq_header(content, buf);
    memcpy(buf + hdr, tbs, (size_t) tbs_len);
    memcpy(buf + hdr + tbs_len, alg, (size_t) alg_len);
    memcpy(buf + hdr + tbs_len + alg_len, sig, (size_t) sig_len);

    OPENSSL_free(alg);
    OPENSSL_free(sig);

    *tbs_out = tbs;
    *tbs_out_len = tbs_len;
    *out = buf;
    *out_len = hdr + content;
    return JO_SUCCESS;
}

typedef struct {
    uint8_t *data[X509_CRL_SLOT_COUNT];
    int32_t len[X509_CRL_SLOT_COUNT];
    int      owned[X509_CRL_SLOT_COUNT];
    uint8_t  oid_text[OID_TEXT_MAX];
} crl_slots;

static void crl_slots_free(crl_slots *s)
{
    int i;

    for (i = 0; i < X509_CRL_SLOT_COUNT; i++)
    {
        if (s->owned[i] && s->data[i] != NULL)
        {
            OPENSSL_free(s->data[i]);
        }
        s->data[i] = NULL;
        s->len[i] = 0;
        s->owned[i] = 0;
    }
}

static int32_t crl_gather(X509_CRL *crl, crl_slots *s)
{
    uint8_t *tmp = NULL;
    uint8_t *enc = NULL;
    size_t enc_len = 0;
    int len = 0;
    int32_t ret;
    const ASN1_BIT_STRING *sigbs;
    const X509_ALGOR *algor;
    const ASN1_OBJECT *alg_oid;
    int ptype = 0;
    const void *pval = NULL;

    memset(s, 0, sizeof(*s));

    ret = compose_crl_encoding(crl, &enc, &enc_len, &tmp, &len);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    if (enc_len > (size_t) INT32_MAX)
    {
        OPENSSL_free(enc);
        OPENSSL_free(tmp);
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    s->data[X509_CRL_SLOT_ENCODED] = enc;
    s->len[X509_CRL_SLOT_ENCODED] = (int32_t) enc_len;
    s->owned[X509_CRL_SLOT_ENCODED] = 1;
    s->data[X509_CRL_SLOT_TBS] = tmp;
    s->len[X509_CRL_SLOT_TBS] = len;
    s->owned[X509_CRL_SLOT_TBS] = 1;

    tmp = NULL;
    len = i2d_X509_NAME(X509_CRL_get_issuer(crl), &tmp);
    if (len <= 0)
    {
        crl_slots_free(s);
        return JO_OPENSSL_ERROR;
    }
    s->data[X509_CRL_SLOT_ISSUER] = tmp;
    s->len[X509_CRL_SLOT_ISSUER] = len;
    s->owned[X509_CRL_SLOT_ISSUER] = 1;

    X509_CRL_get0_signature(crl, &sigbs, &algor);
    if (sigbs == NULL || algor == NULL)
    {
        crl_slots_free(s);
        return JO_OPENSSL_ERROR;
    }
    s->data[X509_CRL_SLOT_SIGNATURE] = (uint8_t *) ASN1_STRING_get0_data((const ASN1_STRING *) sigbs);
    s->len[X509_CRL_SLOT_SIGNATURE] = ASN1_STRING_length((const ASN1_STRING *) sigbs);
    s->owned[X509_CRL_SLOT_SIGNATURE] = 0;

    X509_ALGOR_get0(&alg_oid, &ptype, &pval, algor);
    len = OBJ_obj2txt((char *) s->oid_text, OID_TEXT_MAX, alg_oid, 1);
    if (len <= 0 || len >= OID_TEXT_MAX)
    {
        crl_slots_free(s);
        return JO_OPENSSL_ERROR;
    }
    s->data[X509_CRL_SLOT_SIGALG_OID] = s->oid_text;
    s->len[X509_CRL_SLOT_SIGALG_OID] = len;
    s->owned[X509_CRL_SLOT_SIGALG_OID] = 0;

    /* Absent and explicit NULL both report "no parameters", as SUN does. */
    if (ptype != V_ASN1_UNDEF && ptype != V_ASN1_NULL)
    {
        ASN1_TYPE *param = ASN1_TYPE_new();

        if (param == NULL || ASN1_TYPE_set1(param, ptype, pval) != 1)
        {
            ASN1_TYPE_free(param);
            crl_slots_free(s);
            return JO_OPENSSL_ERROR;
        }
        tmp = NULL;
        len = i2d_ASN1_TYPE(param, &tmp);
        ASN1_TYPE_free(param);
        if (len <= 0)
        {
            crl_slots_free(s);
            return JO_OPENSSL_ERROR;
        }
        s->data[X509_CRL_SLOT_SIGALG_PARAMS] = tmp;
        s->len[X509_CRL_SLOT_SIGALG_PARAMS] = len;
        s->owned[X509_CRL_SLOT_SIGALG_PARAMS] = 1;
    }

    return JO_SUCCESS;
}

int32_t x509_crl_fields_len(x509_handle *h)
{
    X509_CRL *crl = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CRL, (void **) &crl);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    crl_slots s;
    int32_t ret;
    size_t total = 0;
    int i;

    jo_assert(crl != NULL);

    ERR_clear_error();
    ret = crl_gather(crl, &s);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    for (i = 0; i < X509_CRL_SLOT_COUNT; i++)
    {
        total += (size_t) s.len[i];
    }
    crl_slots_free(&s);
    if (total > (size_t) INT32_MAX)
    {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    return (int32_t) total;
}

int32_t x509_crl_fields(x509_handle *h, uint8_t *blob, size_t blob_len,
                        int32_t *sizes, int32_t *info)
{
    X509_CRL *crl = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CRL, (void **) &crl);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    crl_slots s;
    int32_t ret;
    size_t off = 0;
    int i;
    int64_t t = 0;
    const ASN1_TIME *next;

    jo_assert(crl != NULL);
    jo_assert(blob != NULL);
    jo_assert(sizes != NULL);
    jo_assert(info != NULL);

    ERR_clear_error();
    ret = crl_gather(crl, &s);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    for (i = 0; i < X509_CRL_SLOT_COUNT; i++)
    {
        if (s.len[i] > 0)
        {
            if (off + (size_t) s.len[i] > blob_len)
            {
                crl_slots_free(&s);
                return JO_OUTPUT_TOO_SMALL;
            }
            memcpy(blob + off, s.data[i], (size_t) s.len[i]);
            off += (size_t) s.len[i];
        }
        sizes[i] = s.len[i];
    }
    crl_slots_free(&s);

    memset(info, 0, sizeof(int32_t) * X509_CRL_INFO_COUNT);
    info[X509_CRL_INFO_VERSION] = (int32_t) X509_CRL_get_version(crl) + 1;

    if (time_secs(X509_CRL_get0_lastUpdate(crl), &t) != JO_SUCCESS)
    {
        return JO_OPENSSL_ERROR;
    }
    info[X509_CRL_INFO_THIS_UPDATE_HI] = (int32_t) ((uint64_t) t >> 32);
    info[X509_CRL_INFO_THIS_UPDATE_LO] = (int32_t) ((uint64_t) t & 0xFFFFFFFFu);

    /* nextUpdate is OPTIONAL (RFC 5280 5.1.2.5), so its ABSENCE is reported
     * rather than encoded as a sentinel date a caller could also supply. */
    next = X509_CRL_get0_nextUpdate(crl);
    if (next != NULL)
    {
        if (time_secs(next, &t) != JO_SUCCESS)
        {
            return JO_OPENSSL_ERROR;
        }
        info[X509_CRL_INFO_NEXT_UPDATE_HI] = (int32_t) ((uint64_t) t >> 32);
        info[X509_CRL_INFO_NEXT_UPDATE_LO] = (int32_t) ((uint64_t) t & 0xFFFFFFFFu);
        info[X509_CRL_INFO_HAS_NEXT_UPDATE] = 1;
    }

    info[X509_CRL_INFO_EXT_COUNT] = (int32_t) X509_CRL_get_ext_count(crl);
    {
        const STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);

        info[X509_CRL_INFO_ENTRY_COUNT] = (revoked == NULL) ? 0 : sk_X509_REVOKED_num(revoked);
    }
    return JO_SUCCESS;
}

static int32_t each_entry(X509_CRL *crl, uint8_t *blob, size_t blob_len, size_t capacity,
                          int32_t *sizes, int32_t *dates, size_t *needed)
{
    const STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);
    int count = (revoked == NULL) ? 0 : sk_X509_REVOKED_num(revoked);
    int i;
    size_t off = 0;

    *needed = 0;
    if (count < 0)
    {
        return JO_OPENSSL_ERROR;
    }
    if (blob != NULL && capacity < (size_t) count)
    {
        return JO_OUTPUT_TOO_SMALL;
    }

    for (i = 0; i < count; i++)
    {
        X509_REVOKED *entry = sk_X509_REVOKED_value(revoked, i);
        uint8_t *der = NULL;
        int len;
        int64_t when = 0;

        if (entry == NULL)
        {
            return JO_OPENSSL_ERROR;
        }
        len = i2d_X509_REVOKED(entry, &der);
        if (OPS_OPENSSL_ERROR_4 len <= 0)
        {
            return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(7009);
        }
        *needed += (size_t) len;

        if (blob != NULL)
        {
            if (off + (size_t) len > blob_len)
            {
                OPENSSL_free(der);
                return JO_OUTPUT_TOO_SMALL;
            }
            memcpy(blob + off, der, (size_t) len);
            off += (size_t) len;
            sizes[i] = len;

            if (time_secs(X509_REVOKED_get0_revocationDate(entry), &when) != JO_SUCCESS)
            {
                OPENSSL_free(der);
                return JO_OPENSSL_ERROR;
            }
            dates[2 * i] = (int32_t) ((uint64_t) when >> 32);
            dates[2 * i + 1] = (int32_t) ((uint64_t) when & 0xFFFFFFFFu);
        }
        OPENSSL_free(der);
    }
    return JO_SUCCESS;
}

int32_t x509_crl_entries_len(x509_handle *h)
{
    X509_CRL *crl = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CRL, (void **) &crl);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    size_t needed = 0;
    int32_t ret;

    jo_assert(crl != NULL);

    ERR_clear_error();
    ret = each_entry(crl, NULL, 0, 0, NULL, NULL, &needed);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    if (needed > (size_t) INT32_MAX)
    {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    return (int32_t) needed;
}

int32_t x509_crl_entries(x509_handle *h, uint8_t *blob, size_t blob_len, size_t count,
                         int32_t *sizes, int32_t *dates)
{
    X509_CRL *crl = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CRL, (void **) &crl);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    size_t needed = 0;

    jo_assert(crl != NULL);
    jo_assert(blob != NULL);
    jo_assert(sizes != NULL);
    jo_assert(dates != NULL);

    ERR_clear_error();
    return each_entry(crl, blob, blob_len, count, sizes, dates, &needed);
}

int32_t x509_crl_extensions_len(x509_handle *h)
{
    X509_CRL *crl = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CRL, (void **) &crl);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    size_t needed = 0;
    int32_t ret;

    jo_assert(crl != NULL);

    ERR_clear_error();
    ret = each_extension(X509_CRL_get0_extensions(crl), NULL, 0, 0, NULL, NULL, NULL, &needed);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    if (needed > (size_t) INT32_MAX)
    {
        return JO_OUTPUT_TOO_LONG_INT32;
    }
    return (int32_t) needed;
}

int32_t x509_crl_extensions(x509_handle *h, uint8_t *blob, size_t blob_len, size_t count,
                            int32_t *oid_sizes, int32_t *val_sizes, int32_t *critical)
{
    X509_CRL *crl = NULL;
    int32_t kind_rc = handle_unwrap(h, X509_KIND_CRL, (void **) &crl);
    if (kind_rc != JO_SUCCESS)
    {
        return kind_rc;
    }

    size_t needed = 0;

    jo_assert(crl != NULL);
    jo_assert(blob != NULL);
    jo_assert(oid_sizes != NULL);
    jo_assert(val_sizes != NULL);
    jo_assert(critical != NULL);

    ERR_clear_error();
    return each_extension(X509_CRL_get0_extensions(crl), blob, blob_len, count,
                          oid_sizes, val_sizes, critical, &needed);
}
