//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <stdint.h>
#include <string.h>

#include <openssl/crypto.h>

#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/x509.h"
#include "types.h"

/*
 * FFI bridge for X.509 certificate parsing. Symbols Jo-prefixed so they cannot
 * clash with a libcrypto export, and every entry point returns the same error
 * code as its twin in x509_ni_jni.c for the same input — the two are driven by
 * the same limit tests on both legs.
 *
 * Unlike JNI the caller's array sizes are not discoverable here, so every
 * OUTPUT capacity is a PARAMETER and is range-checked before anything is
 * written. That is the same check the JNI side derives from GetArrayLength;
 * stating it twice is the cost of the two bridges validating independently.
 *
 * JoX509_allocate is the exception, and deliberately so: its off/len range
 * check against the caller's array lives in X509ServiceFFI, because this
 * function receives an already-copied slice and never sees off at all. The
 * copy itself is what bounds the slice. The sibling FFI bridges use
 * check_in_range(size, off, len) here instead, so a reader comparing them
 * should know this one is not missing the check — it is on the other side of
 * the copy, and it returns the same codes as the JNI twin for the same input.
 */

int32_t JoX509_allocate(const uint8_t *der, int32_t der_len, int32_t max_bytes,
                        int64_t *out_ref, int32_t *out_consumed)
{
    x509_handle *cert = NULL;
    int32_t consumed = 0;
    int32_t ret;

    if (out_ref == NULL || out_consumed == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    *out_ref = 0;
    *out_consumed = 0;

    if (der == NULL)
    {
        return JO_INPUT_IS_NULL;
    }
    if (der_len < 0)
    {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (max_bytes <= 0)
    {
        return JO_CERT_MAX_BYTES_INVALID;
    }
    /* An empty input IS a failed certificate decode, and that is the wording a
     * generateCertificate caller needs; the JNI twin maps it identically. */
    if (der_len == 0)
    {
        return JO_CERT_DECODE_FAILED;
    }
    /* The ceiling, refused typed HERE. util asserts it, so this is the only
     * thing standing between a raised property and an abort. */
    if (der_len > max_bytes)
    {
        return JO_CERT_TOO_LARGE;
    }

    ret = x509_cert_decode(der, (size_t) der_len, (size_t) max_bytes, &cert, &consumed);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    *out_ref = (int64_t) (intptr_t) cert;
    *out_consumed = consumed;
    return JO_SUCCESS;
}

int32_t JoX509_fieldsLen(int64_t ref)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_cert_fields_len((x509_handle *) (intptr_t) ref);
}

int32_t JoX509_fields(int64_t ref, uint8_t *blob, int32_t blob_len,
                      int32_t *sizes, int32_t sizes_len,
                      int32_t *info, int32_t info_len)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (blob == NULL || sizes == NULL || info == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    if (blob_len < 0 || sizes_len < X509_SLOT_COUNT || info_len < X509_INFO_COUNT)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    return x509_cert_fields((x509_handle *) (intptr_t) ref, blob, (size_t) blob_len, sizes, info);
}

int32_t JoX509_extensionsLen(int64_t ref)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_cert_extensions_len((x509_handle *) (intptr_t) ref);
}

int32_t JoX509_extensions(int64_t ref, uint8_t *blob, int32_t blob_len, int32_t count,
                          int32_t *oid_sizes, int32_t *val_sizes, int32_t *critical)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (blob == NULL || oid_sizes == NULL || val_sizes == NULL || critical == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    /* util asserts the three arrays non-NULL, so a zero capacity is refused
     * here rather than handed down; the capacity itself is checked against the
     * certificate's extension count inside util, before the first write. */
    if (blob_len < 0 || count <= 0)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    return x509_cert_extensions((x509_handle *) (intptr_t) ref, blob, (size_t) blob_len,
                                (size_t) count, oid_sizes, val_sizes, critical);
}

void JoX509_dispose(int64_t ref)
{
    if (ref == 0)
    {
        return;
    }
    x509_cert_free((x509_handle *) (intptr_t) ref);
}

/* ---------------------------------------------------------------- CRLs --- */

int32_t JoX509_allocateCrl(const uint8_t *der, int32_t der_len, int32_t max_bytes,
                           int64_t *out_ref, int32_t *out_consumed)
{
    x509_handle *crl = NULL;
    int32_t consumed = 0;
    int32_t ret;

    if (out_ref == NULL || out_consumed == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    *out_ref = 0;
    *out_consumed = 0;

    if (der == NULL)
    {
        return JO_INPUT_IS_NULL;
    }
    if (der_len < 0)
    {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (max_bytes <= 0)
    {
        return JO_CERT_MAX_BYTES_INVALID;
    }
    if (der_len == 0)
    {
        return JO_CRL_DECODE_FAILED;
    }
    if (der_len > max_bytes)
    {
        /* The CRL bound, named as its own — see the JNI twin. */
        return JO_CRL_TOO_LARGE;
    }

    ret = x509_crl_decode(der, (size_t) der_len, (size_t) max_bytes, &crl, &consumed);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    *out_ref = (int64_t) (intptr_t) crl;
    *out_consumed = consumed;
    return JO_SUCCESS;
}

int32_t JoX509_crlFieldsLen(int64_t ref)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_crl_fields_len((x509_handle *) (intptr_t) ref);
}

int32_t JoX509_crlFields(int64_t ref, uint8_t *blob, int32_t blob_len,
                         int32_t *sizes, int32_t sizes_len,
                         int32_t *info, int32_t info_len)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (blob == NULL || sizes == NULL || info == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    if (blob_len < 0 || sizes_len < X509_CRL_SLOT_COUNT || info_len < X509_CRL_INFO_COUNT)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    return x509_crl_fields((x509_handle *) (intptr_t) ref, blob, (size_t) blob_len, sizes, info);
}

int32_t JoX509_crlExtensionsLen(int64_t ref)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_crl_extensions_len((x509_handle *) (intptr_t) ref);
}

int32_t JoX509_crlExtensions(int64_t ref, uint8_t *blob, int32_t blob_len, int32_t count,
                             int32_t *oid_sizes, int32_t *val_sizes, int32_t *critical)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (blob == NULL || oid_sizes == NULL || val_sizes == NULL || critical == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    if (blob_len < 0 || count <= 0)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    return x509_crl_extensions((x509_handle *) (intptr_t) ref, blob, (size_t) blob_len,
                               (size_t) count, oid_sizes, val_sizes, critical);
}

int32_t JoX509_crlEntriesLen(int64_t ref)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_crl_entries_len((x509_handle *) (intptr_t) ref);
}

int32_t JoX509_crlEntries(int64_t ref, uint8_t *blob, int32_t blob_len, int32_t count,
                          int32_t *sizes, int32_t *dates, int32_t dates_len)
{
    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (blob == NULL || sizes == NULL || dates == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    /* dates carries a high/low pair per entry; the JNI twin derives the same
     * check from GetArrayLength. */
    if (blob_len < 0 || count <= 0 || dates_len != 2 * count)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    return x509_crl_entries((x509_handle *) (intptr_t) ref, blob, (size_t) blob_len,
                            (size_t) count, sizes, dates);
}

void JoX509_disposeCrl(int64_t ref)
{
    if (ref == 0)
    {
        return;
    }
    x509_crl_free((x509_handle *) (intptr_t) ref);
}
