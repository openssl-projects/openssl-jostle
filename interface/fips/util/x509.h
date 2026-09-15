//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef JOSTLE_X509_H
#define JOSTLE_X509_H

#include <stdint.h>
#include <stddef.h>

#include <openssl/x509.h>

/*
 * X.509 certificate parsing over OpenSSL.
 *
 * Every field a JCA accessor needs crosses in ONE call: a concatenated buffer
 * plus a lengths array, as certpath.c does for a path. Per-getter entry points
 * would multiply the bridge surface and the reachability-fence surface for no
 * gain, since a caller reading one field almost always reads several.
 *
 * Non-DER input is ACCEPTED and normalised. The encoding handed back is
 * COMPOSED — a re-encoded TBS, the signature AlgorithmIdentifier and the
 * signature BIT STRING wrapped in a fresh definite-length SEQUENCE — and never
 * i2d_X509, which re-emits the cached raw octets of the TBS and would return
 * BER for a BER input. X509_CINF is declared ASN1_SEQUENCE_enc and therefore
 * caches; X509, X509_ALGOR and X509_REVOKED are not and do not.
 */

/* Slots in the fields blob, in order. Java's X509NI carries the same list. */
#define X509_SLOT_ENCODED       0   /* composed DER of the whole certificate */
#define X509_SLOT_TBS           1   /* i2d_re_X509_tbs */
#define X509_SLOT_SERIAL        2   /* the serialNumber INTEGER, whole TLV */
#define X509_SLOT_ISSUER        3   /* i2d_X509_NAME of the issuer */
#define X509_SLOT_SUBJECT       4   /* i2d_X509_NAME of the subject */
#define X509_SLOT_SIGNATURE     5   /* signature BIT STRING contents */
#define X509_SLOT_SIGALG_OID    6   /* dotted decimal, NOT NUL-terminated */
#define X509_SLOT_SIGALG_PARAMS 7   /* DER of the parameters; empty when absent
                                     * OR when an explicit ASN.1 NULL, which is
                                     * what SUN reports as null */
#define X509_SLOT_ISSUER_UID    8   /* issuerUniqueID bits; empty when absent */
#define X509_SLOT_SUBJECT_UID   9   /* subjectUniqueID bits; empty when absent */
#define X509_SLOT_SPKI         10   /* the whole SubjectPublicKeyInfo, DER.
                                     * The public key is rebuilt from THIS
                                     * through the provider's own KeyFactory,
                                     * which is what binds it to the provider
                                     * instance; the certificate keeps no key
                                     * of its own. */
#define X509_SLOT_SPKI_ALG_OID 11   /* SubjectPublicKeyInfo algorithm, dotted.
                                     * Readable even when the key itself cannot
                                     * be built, which is what lets the Java
                                     * layer tell "this provider does not serve
                                     * the algorithm" from "this key is
                                     * malformed" and word the refusal
                                     * accordingly. */
#define X509_SLOT_COUNT        12

/* Fixed-width results, returned in the info array alongside the blob. */
#define X509_INFO_VERSION           0   /* 1, 2 or 3 -- already +1 from OpenSSL */
/*
 * notBefore / notAfter as seconds since the epoch, split HIGH then LOW across
 * two int32 slots. A certificate may legitimately expire in 9999, which is
 * past the int32 second cliff in 2038, so a single slot would silently wrap on
 * exactly the long-dated roots this has to read.
 */
#define X509_INFO_NOT_BEFORE_HI     1
#define X509_INFO_NOT_BEFORE_LO     2
#define X509_INFO_NOT_AFTER_HI      3
#define X509_INFO_NOT_AFTER_LO      4
#define X509_INFO_BASIC_CONSTRAINTS 5   /* JCA semantics: -1 when not a CA,
                                         * INT32_MAX when a CA with no pathlen */
#define X509_INFO_KEY_USAGE_BITS    6   /* declared bit count, 0 when absent;
                                         * never more than X509_MAX_KEY_USAGE_BITS,
                                         * which is refused rather than truncated */
#define X509_INFO_KEY_USAGE_VALUE   7   /* the bits, MSB first from bit 0 */
#define X509_INFO_ISSUER_UID_BITS   8   /* bit count, so trailing bits survive */
#define X509_INFO_SUBJECT_UID_BITS  9
#define X509_INFO_EXT_COUNT        10
#define X509_INFO_COUNT            11

/*
 * Default ceiling on one certificate. A certificate is normally 1-4 KiB.
 *
 * The ceiling is a PARAMETER of x509_cert_decode, not a constant util enforces:
 * the Java layer reads the configurable property and passes what it decided on,
 * and the BRIDGE range-checks der_len against it and refuses typed. An earlier
 * draft had util jo_assert this macro while the header promised the property
 * governed, so a deployment raising the property above it would have reached a
 * JVM abort from pure Java -- caller input reaching an assert, which is the one
 * thing the bridge rules forbid.
 */
#define X509_DEFAULT_MAX_CERT_BYTES (1024 * 1024)

/*
 * KeyUsage is a BIT STRING the JCA returns as a boolean[]. RFC 5280 4.2.1.3
 * defines nine bits; anything beyond this bound is refused typed rather than
 * silently truncated, because a truncated key usage reads as a PERMISSION the
 * certificate did not grant.
 */
#define X509_MAX_KEY_USAGE_BITS 32

/*
 * Decode one certificate. der/der_len may carry trailing octets — the JCA
 * contract reads ONE object from a stream and leaves the rest — so *consumed
 * reports what this certificate occupied, which is what positions the stream.
 *
 * Returns JO_SUCCESS with *out set, or a negative JO_* with *out NULL.
 */
int32_t x509_cert_decode(const uint8_t *der, size_t der_len, size_t max_bytes,
                         X509 **out, int32_t *consumed);

/*
 * Total bytes the fields blob needs. Call, allocate, then call x509_cert_fields.
 * Returns a byte count >= 0, or a negative JO_*.
 */
int32_t x509_cert_fields_len(X509 *cert);

/*
 * Fill blob/sizes/info. blob must be at least x509_cert_fields_len bytes and
 * sizes at least X509_SLOT_COUNT entries, info at least X509_INFO_COUNT.
 */
int32_t x509_cert_fields(X509 *cert, uint8_t *blob, size_t blob_len,
                         int32_t *sizes, int32_t *info);

/*
 * Extensions, again in one call: concatenated OIDs then concatenated values,
 * with one length each and a criticality flag each.
 *
 * oid_sizes, val_sizes and critical each hold ext_count entries, as reported
 * by X509_INFO_EXT_COUNT.
 */
int32_t x509_cert_extensions_len(X509 *cert);

/*
 * count is the CAPACITY of oid_sizes / val_sizes / critical, and is checked
 * against the certificate's extension count BEFORE the first write. Without
 * it util would write one entry per extension into buffers the bridge sized
 * from the caller's arrays: a caller that sized them short -- a stale
 * INFO_EXT_COUNT, a second thread -- would get a heap overflow, and a count of
 * zero against a certificate with extensions would write through NULL.
 */
int32_t x509_cert_extensions(X509 *cert, uint8_t *blob, size_t blob_len, size_t count,
                             int32_t *oid_sizes, int32_t *val_sizes, int32_t *critical);

void x509_cert_free(X509 *cert);

/* ---------------------------------------------------------------- CRLs --- */

/*
 * The CRL mirrors the certificate exactly: one call for the fixed fields, one
 * for the variable-length part, the encoding COMPOSED from a forced re-encode
 * rather than i2d_X509_CRL. X509_CRL_INFO is declared ASN1_SEQUENCE_enc and so
 * caches its octets, the same trap as X509_CINF.
 */
#define X509_CRL_SLOT_ENCODED       0   /* composed DER of the whole CRL */
#define X509_CRL_SLOT_TBS           1   /* i2d_re_X509_CRL_tbs */
#define X509_CRL_SLOT_ISSUER        2   /* i2d_X509_NAME of the issuer */
#define X509_CRL_SLOT_SIGNATURE     3   /* signature BIT STRING contents */
#define X509_CRL_SLOT_SIGALG_OID    4   /* dotted decimal, NOT NUL-terminated */
#define X509_CRL_SLOT_SIGALG_PARAMS 5   /* empty when absent OR an explicit NULL */
#define X509_CRL_SLOT_COUNT         6

#define X509_CRL_INFO_VERSION          0   /* 1 or 2 -- already +1 from OpenSSL */
#define X509_CRL_INFO_THIS_UPDATE_HI   1
#define X509_CRL_INFO_THIS_UPDATE_LO   2
#define X509_CRL_INFO_NEXT_UPDATE_HI   3
#define X509_CRL_INFO_NEXT_UPDATE_LO   4
#define X509_CRL_INFO_HAS_NEXT_UPDATE  5   /* nextUpdate is OPTIONAL */
#define X509_CRL_INFO_EXT_COUNT        6
#define X509_CRL_INFO_ENTRY_COUNT      7
#define X509_CRL_INFO_COUNT            8

/*
 * A CRL is legitimately far larger than a certificate -- a production CRL runs
 * to tens of MiB -- so it carries its own ceiling rather than sharing the
 * certificate's, which would refuse real input.
 */
#define X509_DEFAULT_MAX_CRL_BYTES (64 * 1024 * 1024)

int32_t x509_crl_decode(const uint8_t *der, size_t der_len, size_t max_bytes,
                        X509_CRL **out, int32_t *consumed);

int32_t x509_crl_fields_len(X509_CRL *crl);
int32_t x509_crl_fields(X509_CRL *crl, uint8_t *blob, size_t blob_len,
                        int32_t *sizes, int32_t *info);

/*
 * Revoked entries. Each crosses as its own DER (i2d_X509_REVOKED, which is a
 * fresh encode since X509_REVOKED carries no cache) plus its revocationDate as
 * a high/low pair; the Java side reads the serial and the entry extensions out
 * of that DER with the project's own reader rather than through a second
 * native surface.
 *
 * count is the CAPACITY of sizes (entries) and dates (2 * entries), checked
 * against the CRL's entry count before the first write.
 */
int32_t x509_crl_entries_len(X509_CRL *crl);
int32_t x509_crl_entries(X509_CRL *crl, uint8_t *blob, size_t blob_len, size_t count,
                         int32_t *sizes, int32_t *dates);

int32_t x509_crl_extensions_len(X509_CRL *crl);
int32_t x509_crl_extensions(X509_CRL *crl, uint8_t *blob, size_t blob_len, size_t count,
                            int32_t *oid_sizes, int32_t *val_sizes, int32_t *critical);

void x509_crl_free(X509_CRL *crl);

#endif
