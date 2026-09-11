//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef JOSTLE_CERTPATH_H
#define JOSTLE_CERTPATH_H

#include <stdint.h>
#include <stddef.h>

/*
 * Certification path validation over X509_verify_cert.
 *
 * Certificates cross as ONE concatenated DER buffer plus a lengths array, so a
 * whole path is a single call: anchors first, then untrusted, then the target
 * as the last entry. The caller says how many of the entries are anchors.
 *
 * CRLs follow the certificates in the SAME buffer, so sizes holds
 * count + crl_count entries: [0, count) are certificates and the target stays
 * at count - 1, [count, count + crl_count) are CRLs.
 *
 * The result carries the built chain back the same way, so the Java side can
 * assert that the chain OpenSSL built is the path it was given.
 */
/* No representable Date equals this, so it cannot collide with a caller's. */
#define CERTPATH_TIME_NOW INT64_MIN

typedef struct {
    int32_t error;        /* X509_V_* code; 0 is X509_V_OK */
    int32_t depth;        /* error depth, -1 when there was no error */
    int32_t chain_count;  /* certificates in the built chain, anchor last */
    uint8_t *chain_der;   /* concatenated DER of the built chain */
    size_t   chain_len;
    int32_t *chain_sizes; /* chain_count entries */
} certpath_result;

/*
 * time_secs:  seconds since the epoch to validate at, or CERTPATH_TIME_NOW.
 *             NOT 0 — the epoch is a legitimate date, and a sentinel a caller
 *             can supply by accident is a bug waiting for one.
 * strict:     non-zero adds X509_V_FLAG_X509_STRICT.
 * revocation: non-zero adds CRL_CHECK | CRL_CHECK_ALL | EXTENDED_CRL_SUPPORT.
 *             The three go together; see certpath.c for what each decides.
 *
 * Returns JO_SUCCESS when the verification RAN (whatever its verdict — read
 * result->error for that) and a JO_* error when it could not be attempted.
 */
int32_t certpath_verify(const uint8_t *der, size_t der_len,
                        const int32_t *sizes, int32_t count, int32_t crl_count,
                        int32_t anchor_count,
                        int64_t time_secs, int32_t strict, int32_t revocation,
                        certpath_result *result);

void certpath_result_free(certpath_result *result);

#endif
