/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.cert;

import org.openssl.jostle.jcajce.provider.CertificateParseException;
import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;

/**
 * X.509 certificate parsing over OpenSSL.
 *
 * <p>Every field a JCA accessor needs crosses in ONE call — a concatenated
 * buffer plus a lengths array — as the certification-path bridge does for a
 * path. Per-getter entry points would multiply both the bridge surface and the
 * reachability-fence surface for no gain, since a caller reading one field
 * almost always reads several.
 *
 * <p>The encoding handed back is COMPOSED from a forced re-encode of the TBS,
 * the signature AlgorithmIdentifier and the signature BIT STRING. It is never
 * {@code i2d_X509}, which re-emits the cached raw octets of the TBS and so
 * would return BER for a BER input.
 */
public interface X509NI
    extends DefaultServiceNI
{
    /*
     * Slots in the fields blob, in order. x509.h carries the same list; the two
     * are one contract and must move together.
     */
    int SLOT_ENCODED = 0;
    int SLOT_TBS = 1;
    int SLOT_SERIAL = 2;
    int SLOT_ISSUER = 3;
    int SLOT_SUBJECT = 4;
    int SLOT_SIGNATURE = 5;
    int SLOT_SIGALG_OID = 6;
    int SLOT_SIGALG_PARAMS = 7;
    int SLOT_ISSUER_UID = 8;
    int SLOT_SUBJECT_UID = 9;
    int SLOT_SPKI = 10;
    int SLOT_SPKI_ALG_OID = 11;
    int SLOT_COUNT = 12;

    /* Fixed-width results. */
    int INFO_VERSION = 0;
    int INFO_NOT_BEFORE_HI = 1;
    int INFO_NOT_BEFORE_LO = 2;
    int INFO_NOT_AFTER_HI = 3;
    int INFO_NOT_AFTER_LO = 4;
    int INFO_BASIC_CONSTRAINTS = 5;
    int INFO_KEY_USAGE_BITS = 6;
    int INFO_KEY_USAGE_VALUE = 7;
    int INFO_ISSUER_UID_BITS = 8;
    int INFO_SUBJECT_UID_BITS = 9;
    int INFO_EXT_COUNT = 10;
    int INFO_COUNT = 11;

    /** Default ceiling on one certificate; mirrors {@code X509_DEFAULT_MAX_CERT_BYTES}. */
    int DEFAULT_MAX_CERT_BYTES = 1024 * 1024;

    /**
     * Property that moves the ceiling, read per call in the BouncyCastle
     * convention. Named in the refusal message: a bound a deployment cannot
     * find is a bound it cannot raise.
     */
    String MAX_CERT_BYTES_PROPERTY = "org.openssl.jostle.x509.max_certificate_bytes";

    /**
     * The configured ceiling, clamped to {@code [1, Integer.MAX_VALUE]}.
     *
     * <p>Clamped HERE so the bridge's {@code maxBytes <= 0} arm stays
     * unreachable from a property value: a deployment writing {@code 0} or a
     * negative would otherwise get the bridge's generic refusal instead of one
     * naming the property it just set. Read per call, which is the
     * BouncyCastle convention and costs nothing on a parse path.
     */
    static int maxCertificateBytes()
    {
        int configured = org.openssl.jostle.util.Properties.asInteger(
                MAX_CERT_BYTES_PROPERTY, DEFAULT_MAX_CERT_BYTES);
        if (configured < 1)
        {
            return DEFAULT_MAX_CERT_BYTES;
        }
        return configured;
    }

    /**
     * Decode one certificate, leaving any trailing octets alone.
     *
     * @param der      the input, which MAY carry more than one object
     * @param off      offset of the first octet
     * @param len      octets available from {@code off}
     * @param maxBytes ceiling this call will accept; the bridge refuses a
     *                 longer input typed rather than letting util assert
     * @param consumed receives the octets this certificate occupied, which is
     *                 what positions a stream for the next read
     * @param err      receives the {@code JO_*} code
     * @return the native handle, or 0 when {@code err[0]} is negative
     */
    long ni_allocate(byte[] der, int off, int len, int maxBytes, int[] consumed, int[] err);

    int ni_fieldsLen(long ref);

    int ni_fields(long ref, byte[] blob, int[] sizes, int[] info);

    int ni_extensionsLen(long ref);

    int ni_extensions(long ref, byte[] blob, int[] oidSizes, int[] valSizes, int[] critical);

    void ni_dispose(long ref);

    /* ------------------------------------------------------------- CRLs --- */

    int CRL_SLOT_ENCODED = 0;
    int CRL_SLOT_TBS = 1;
    int CRL_SLOT_ISSUER = 2;
    int CRL_SLOT_SIGNATURE = 3;
    int CRL_SLOT_SIGALG_OID = 4;
    int CRL_SLOT_SIGALG_PARAMS = 5;
    int CRL_SLOT_COUNT = 6;

    int CRL_INFO_VERSION = 0;
    int CRL_INFO_THIS_UPDATE_HI = 1;
    int CRL_INFO_THIS_UPDATE_LO = 2;
    int CRL_INFO_NEXT_UPDATE_HI = 3;
    int CRL_INFO_NEXT_UPDATE_LO = 4;
    int CRL_INFO_HAS_NEXT_UPDATE = 5;
    int CRL_INFO_EXT_COUNT = 6;
    int CRL_INFO_ENTRY_COUNT = 7;
    int CRL_INFO_COUNT = 8;

    /**
     * Default ceiling on one CONTAINER — a CRL, a PKCS#7 bag or a PkiPath.
     * 64 MiB, not the certificate's 1 MiB: a production CRL runs to tens of
     * megabytes, so sharing the certificate's bound would refuse real input.
     */
    int DEFAULT_MAX_CONTAINER_BYTES = 64 * 1024 * 1024;

    /** Property that moves the container ceiling, named in the refusal. */
    String MAX_CONTAINER_BYTES_PROPERTY = "org.openssl.jostle.x509.max_container_bytes";

    static int maxContainerBytes()
    {
        int configured = org.openssl.jostle.util.Properties.asInteger(
                MAX_CONTAINER_BYTES_PROPERTY, DEFAULT_MAX_CONTAINER_BYTES);
        return configured < 1 ? DEFAULT_MAX_CONTAINER_BYTES : configured;
    }

    /**
     * Members in a bag or a plural call. A COUNT, not a byte size: the
     * container ceiling bounds the bytes, and a 64 MiB bag of minimal
     * certificates still holds a great many of them.
     */
    int DEFAULT_MAX_MEMBERS = 4096;

    String MAX_MEMBERS_PROPERTY = "org.openssl.jostle.x509.max_members";

    static int maxMembers()
    {
        int configured = org.openssl.jostle.util.Properties.asInteger(
                MAX_MEMBERS_PROPERTY, DEFAULT_MAX_MEMBERS);
        return configured < 1 ? DEFAULT_MAX_MEMBERS : configured;
    }

    long ni_allocateCrl(byte[] der, int off, int len, int maxBytes, int[] consumed, int[] err);

    int ni_crlFieldsLen(long ref);

    int ni_crlFields(long ref, byte[] blob, int[] sizes, int[] info);

    int ni_crlExtensionsLen(long ref);

    int ni_crlExtensions(long ref, byte[] blob, int[] oidSizes, int[] valSizes, int[] critical);

    int ni_crlEntriesLen(long ref);

    /** @param dates two ints per entry, high then low seconds since the epoch */
    int ni_crlEntries(long ref, byte[] blob, int[] sizes, int[] dates);

    void ni_disposeCrl(long ref);

    default long allocateCrl(byte[] der, int off, int len, int maxBytes, int[] consumed)
    {
        int[] err = new int[1];
        long ref = ni_allocateCrl(der, off, len, maxBytes, consumed, err);
        handleErrors(err[0]);
        return ref;
    }

    default int crlFieldsLen(long ref)
    {
        return (int) handleErrors(ni_crlFieldsLen(ref));
    }

    default void crlFields(long ref, byte[] blob, int[] sizes, int[] info)
    {
        handleErrors(ni_crlFields(ref, blob, sizes, info));
    }

    default int crlExtensionsLen(long ref)
    {
        return (int) handleErrors(ni_crlExtensionsLen(ref));
    }

    default void crlExtensions(long ref, byte[] blob, int[] oidSizes, int[] valSizes, int[] critical)
    {
        handleErrors(ni_crlExtensions(ref, blob, oidSizes, valSizes, critical));
    }

    default int crlEntriesLen(long ref)
    {
        return (int) handleErrors(ni_crlEntriesLen(ref));
    }

    default void crlEntries(long ref, byte[] blob, int[] sizes, int[] dates)
    {
        handleErrors(ni_crlEntries(ref, blob, sizes, dates));
    }

    default void disposeCrl(long ref)
    {
        ni_disposeCrl(ref);
    }

    default long allocate(byte[] der, int off, int len, int maxBytes, int[] consumed)
    {
        int[] err = new int[1];
        long ref = ni_allocate(der, off, len, maxBytes, consumed, err);
        handleErrors(err[0]);
        return ref;
    }

    default int fieldsLen(long ref)
    {
        return (int) handleErrors(ni_fieldsLen(ref));
    }

    default void fields(long ref, byte[] blob, int[] sizes, int[] info)
    {
        handleErrors(ni_fields(ref, blob, sizes, info));
    }

    default int extensionsLen(long ref)
    {
        return (int) handleErrors(ni_extensionsLen(ref));
    }

    default void extensions(long ref, byte[] blob, int[] oidSizes, int[] valSizes, int[] critical)
    {
        handleErrors(ni_extensions(ref, blob, oidSizes, valSizes, critical));
    }

    default void dispose(long ref)
    {
        ni_dispose(ref);
    }

    /**
     * The two certificate-specific codes, ahead of the shared handler.
     *
     * <p>Both are runtime exceptions because an NI surface cannot throw the
     * JCE's checked types; the CertificateFactory SPI translates them at the
     * parse boundary, which is the "distinct C code, typed runtime exception,
     * JCE-canonical checked exception" shape the OAEP path already uses.
     */
    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }
        ErrorCode ec = ErrorCode.forCode(code);
        if (ec == ErrorCode.JO_CERT_EXTENSION_INVALID)
        {
            throw new CertificateParseException(
                    "certificate extension is duplicated, undecodable, or declares too many key usage bits");
        }
        if (ec == ErrorCode.JO_CERT_DECODE_FAILED)
        {
            throw new CertificateParseException("input did not decode as an X.509 certificate");
        }
        if (ec == ErrorCode.JO_CRL_DECODE_FAILED)
        {
            throw new CertificateParseException("input did not decode as an X.509 CRL");
        }
        if (ec == ErrorCode.JO_CERT_CTX_IS_NULL)
        {
            throw new IllegalArgumentException("certificate handle is null");
        }
        if (ec == ErrorCode.JO_CERT_TOO_LARGE)
        {
            throw new CertificateParseException(
                    "certificate exceeds the configured ceiling; raise "
                            + MAX_CERT_BYTES_PROPERTY);
        }
        return baseErrorHandler(code);
    }
}
