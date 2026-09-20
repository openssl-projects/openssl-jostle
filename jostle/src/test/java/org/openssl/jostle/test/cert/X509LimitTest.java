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

package org.openssl.jostle.test.cert;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.openssl.jostle.jcajce.provider.CertificateParseException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cert.X509NI;
import org.openssl.jostle.test.certpath.PkitsCertificates;

import java.security.Security;

/**
 * Input validation at the X.509 NI surface, driven directly so the bridge and
 * util checks are reached rather than the CertificateFactory SPI's.
 * <p>
 * <b>The handle-kind cells are the reason this class exists.</b> Every
 * accessor takes a {@code long}; before the handle carried a kind, one of the
 * other family was dereferenced as the wrong struct and faulted inside
 * libcrypto — three SIGBUSes, and a {@code crlFieldsLen} on a certificate that
 * refused typed and left the object unsafe to free, so a caller cleaning up in
 * a {@code finally} crashed on the dispose. Each of those is a cell here.
 * <p>
 * Range probes sit at exactly {@code boundary + 1}, each with its positive
 * companion at the boundary: an arbitrary large value passes a check written
 * with an off-by-100.
 * <p>
 * Runs on both bridges. They validate separately and in C on both: the offset
 * and range checks are the bridge's own, and must answer the same code.
 * <p>
 * {@code err} and {@code consumed} are jostle's own; a null or empty one
 * aborts on both bridges, so no cell pins them.
 */
public class X509LimitTest
{
    private final X509NI ni = NISelector.X509NI;

    private static final int MAX = X509NI.DEFAULT_MAX_CERT_BYTES;
    private static final int CRL_MAX = X509NI.DEFAULT_MAX_CONTAINER_BYTES;

    /** A CRL with revoked entries, so the entries accessors have something to fill. */
    private static final String CRL_WITH_ENTRIES = "indirectCRLCA5CRL.crl";

    @BeforeAll
    static void before()
    {
        // The Loader runs on PROVIDER construction, not on a static read of
        // NISelector, so touching the NI alone would leave no native library
        // loaded and every call below would UnsatisfiedLinkError.
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static byte[] certDer() throws Exception
    {
        return PkitsCertificates.der(PkitsCertificates.ANCHOR);
    }

    private static byte[] crlDer() throws Exception
    {
        return PkitsCertificates.crlDer(CRL_WITH_ENTRIES);
    }

    private long cert() throws Exception
    {
        byte[] der = certDer();
        return ni.allocate(der, 0, der.length, MAX, new int[1]);
    }

    private long crl() throws Exception
    {
        byte[] der = crlDer();
        return ni.allocateCrl(der, 0, der.length, CRL_MAX, new int[1]);
    }

    // -----------------------------------------------------------------
    // Handle kind
    // -----------------------------------------------------------------

    /**
     * A certificate handle is refused by every CRL accessor, and a CRL handle
     * by every certificate accessor. Driven under {@code assertAll} so one
     * refusal cannot mask the next.
     */
    @Test
    public void aHandleOfTheOtherKindIsRefusedAtEveryAccessor() throws Exception
    {
        long c = cert();
        long r = crl();
        try
        {
            Assertions.assertAll(
                    () -> wrongKind(() -> ni.crlFieldsLen(c)),
                    () -> wrongKind(() -> ni.crlFields(c, new byte[1], new int[X509NI.CRL_SLOT_COUNT],
                            new int[X509NI.CRL_INFO_COUNT])),
                    () -> wrongKind(() -> ni.crlExtensionsLen(c)),
                    () -> wrongKind(() -> ni.crlExtensions(c, new byte[1], new int[1], new int[1], new int[1])),
                    () -> wrongKind(() -> ni.crlEntriesLen(c)),
                    () -> wrongKind(() -> ni.crlEntries(c, new byte[1], new int[1], new int[2])),
                    () -> wrongKind(() -> ni.fieldsLen(r)),
                    () -> wrongKind(() -> ni.fields(r, new byte[1], new int[X509NI.SLOT_COUNT],
                            new int[X509NI.INFO_COUNT])),
                    () -> wrongKind(() -> ni.extensionsLen(r)),
                    () -> wrongKind(() -> ni.extensions(r, new byte[1], new int[1], new int[1], new int[1])));
        }
        finally
        {
            ni.dispose(c);
            ni.disposeCrl(r);
        }
    }

    /**
     * A refusal must not damage the object. This is the sequence that used to
     * SIGBUS in {@code x509_pubkey_ex_free}: the wrong-kind call returned a
     * typed exception, so it LOOKED handled, and the {@code finally} that a
     * correct caller writes then crashed on the dispose.
     */
    @Test
    public void aRefusedCrossKindCallLeavesTheHandleSafeToDispose() throws Exception
    {
        long c = cert();
        wrongKind(() -> ni.crlFieldsLen(c));
        // The property: this returns rather than faulting.
        ni.dispose(c);

        long r = crl();
        wrongKind(() -> ni.fieldsLen(r));
        ni.disposeCrl(r);
    }

    /**
     * Disposing through the wrong family frees NOTHING, so the handle is still
     * live and its own dispose still works. Asserted by USING the handle after
     * the refused dispose: a free that happened anyway would fault or answer
     * rubbish here, where a bare "it did not throw" would not notice.
     */
    @Test
    public void aWrongKindDisposeFreesNothingAndTheCorrectOneStillWorks() throws Exception
    {
        long c = cert();
        ni.disposeCrl(c);
        Assertions.assertTrue(ni.fieldsLen(c) > 0,
                "the certificate was damaged by a CRL dispose");
        ni.dispose(c);

        long r = crl();
        ni.dispose(r);
        Assertions.assertTrue(ni.crlFieldsLen(r) > 0,
                "the CRL was damaged by a certificate dispose");
        ni.disposeCrl(r);
    }

    // -----------------------------------------------------------------
    // Null handle
    // -----------------------------------------------------------------

    @Test
    public void aNullHandleIsRefusedAtEveryAccessor()
    {
        Assertions.assertAll(
                () -> nullHandle(() -> ni.fieldsLen(0)),
                () -> nullHandle(() -> ni.fields(0, new byte[1], new int[X509NI.SLOT_COUNT],
                        new int[X509NI.INFO_COUNT])),
                () -> nullHandle(() -> ni.extensionsLen(0)),
                () -> nullHandle(() -> ni.extensions(0, new byte[1], new int[1], new int[1], new int[1])),
                () -> nullHandle(() -> ni.crlFieldsLen(0)),
                () -> nullHandle(() -> ni.crlFields(0, new byte[1], new int[X509NI.CRL_SLOT_COUNT],
                        new int[X509NI.CRL_INFO_COUNT])),
                () -> nullHandle(() -> ni.crlExtensionsLen(0)),
                () -> nullHandle(() -> ni.crlExtensions(0, new byte[1], new int[1], new int[1], new int[1])),
                () -> nullHandle(() -> ni.crlEntriesLen(0)),
                () -> nullHandle(() -> ni.crlEntries(0, new byte[1], new int[1], new int[2])));
    }

    /** Disposing a zero handle is what every finally block does; it must be a no-op. */
    @Test
    public void disposingAZeroHandleIsHarmless()
    {
        ni.dispose(0);
        ni.disposeCrl(0);
    }

    // -----------------------------------------------------------------
    // allocate — input validation
    // -----------------------------------------------------------------

    @Test
    public void allocate_nullInput_atZeroOffsetAndLength_rejectedTyped()
    {
        // A null array with off == len == 0 passes every range check, so only
        // an explicit null check catches it.
        assertTyped(NullPointerException.class, "input is null",
                () -> ni.allocate(null, 0, 0, MAX, new int[1]));
        assertTyped(NullPointerException.class, "input is null",
                () -> ni.allocateCrl(null, 0, 0, CRL_MAX, new int[1]));
    }

    /**
     * The offset and the length have their own codes. They did not until the
     * handle-kind commit: a negative offset reported "input len is negative",
     * which names the wrong argument.
     */
    @Test
    public void allocate_negativeOffsetAndLength_areNamedSeparately() throws Exception
    {
        byte[] der = certDer();
        byte[] cder = crlDer();
        Assertions.assertAll(
                () -> assertTyped(IllegalArgumentException.class, "input offset is negative",
                        () -> ni.allocate(der, -1, der.length, MAX, new int[1])),
                () -> assertTyped(IllegalArgumentException.class, "input offset is negative",
                        () -> ni.allocate(der, Integer.MIN_VALUE, der.length, MAX, new int[1])),
                () -> assertTyped(IllegalArgumentException.class, "input len is negative",
                        () -> ni.allocate(der, 0, -1, MAX, new int[1])),
                () -> assertTyped(IllegalArgumentException.class, "input len is negative",
                        () -> ni.allocate(der, 0, Integer.MIN_VALUE, MAX, new int[1])),
                () -> assertTyped(IllegalArgumentException.class, "input offset is negative",
                        () -> ni.allocateCrl(cder, -1, cder.length, CRL_MAX, new int[1])),
                () -> assertTyped(IllegalArgumentException.class, "input len is negative",
                        () -> ni.allocateCrl(cder, 0, -1, CRL_MAX, new int[1])));
    }

    @Test
    public void allocate_offsetPlusLengthPastEnd_rejectedAtTheBoundary() throws Exception
    {
        byte[] der = certDer();
        assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                () -> ni.allocate(der, 1, der.length, MAX, new int[1]));
        assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                () -> ni.allocate(der, 0, der.length + 1, MAX, new int[1]));
        assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                () -> ni.allocateCrl(der, 1, der.length, CRL_MAX, new int[1]));
    }

    /** A non-positive ceiling has its own message; it used to borrow the length's. */
    @Test
    public void allocate_nonPositiveCeiling_rejectedTyped() throws Exception
    {
        byte[] der = certDer();
        byte[] cder = crlDer();
        Assertions.assertAll(
                () -> assertTyped(IllegalArgumentException.class, "maximum bytes must be positive",
                        () -> ni.allocate(der, 0, der.length, 0, new int[1])),
                () -> assertTyped(IllegalArgumentException.class, "maximum bytes must be positive",
                        () -> ni.allocate(der, 0, der.length, -1, new int[1])),
                () -> assertTyped(IllegalArgumentException.class, "maximum bytes must be positive",
                        () -> ni.allocateCrl(cder, 0, cder.length, 0, new int[1])));
    }

    /**
     * The ceiling is a per-call parameter, so the boundary is exact: the
     * certificate's own length is accepted and one less is refused. The
     * refusal names the property that moves the bound, because one a
     * deployment cannot find is one it cannot raise.
     */
    @Test
    public void allocate_ceiling_acceptsAtTheBoundaryAndRefusesOneBelow() throws Exception
    {
        byte[] der = certDer();
        long ref = ni.allocate(der, 0, der.length, der.length, new int[1]);
        Assertions.assertTrue(ref != 0, "the ceiling must accept a certificate of exactly its size");
        ni.dispose(ref);

        assertTyped(CertificateParseException.class,
                "certificate exceeds the configured ceiling; raise "
                        + X509NI.MAX_CERT_BYTES_PROPERTY,
                () -> ni.allocate(der, 0, der.length, der.length - 1, new int[1]));
    }

    /** The CRL ceiling names the CRL property, not the certificate's. */
    @Test
    public void allocateCrl_ceiling_acceptsAtTheBoundaryAndNamesItsOwnProperty() throws Exception
    {
        byte[] der = crlDer();
        long ref = ni.allocateCrl(der, 0, der.length, der.length, new int[1]);
        Assertions.assertTrue(ref != 0, "the ceiling must accept a CRL of exactly its size");
        ni.disposeCrl(ref);

        assertTyped(CertificateParseException.class,
                "CRL exceeds the configured ceiling; raise " + X509NI.MAX_CONTAINER_BYTES_PROPERTY,
                () -> ni.allocateCrl(der, 0, der.length, der.length - 1, new int[1]));
    }

    @Test
    public void allocate_undecodableInput_rejectedTyped() throws Exception
    {
        byte[] junk = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        assertTyped(CertificateParseException.class, "input did not decode as an X.509 certificate",
                () -> ni.allocate(junk, 0, junk.length, MAX, new int[1]));
        assertTyped(CertificateParseException.class, "input did not decode as an X.509 CRL",
                () -> ni.allocateCrl(junk, 0, junk.length, CRL_MAX, new int[1]));
        // A well-formed object of the OTHER type is not a decode of this one.
        byte[] cert = certDer();
        assertTyped(CertificateParseException.class, "input did not decode as an X.509 CRL",
                () -> ni.allocateCrl(cert, 0, cert.length, CRL_MAX, new int[1]));
    }

    /**
     * Trailing octets are NOT an error: the JCA contract reads one object and
     * leaves the rest, and {@code consumed} is what positions the stream. The
     * opposite of the whole-blob decoders, which refuse trailing data.
     */
    @Test
    public void allocate_trailingOctets_areConsumedNotRefused() throws Exception
    {
        byte[] der = certDer();
        byte[] withTail = new byte[der.length + 16];
        System.arraycopy(der, 0, withTail, 0, der.length);

        int[] consumed = new int[1];
        long ref = ni.allocate(withTail, 0, withTail.length, MAX, consumed);
        try
        {
            Assertions.assertEquals(der.length, consumed[0],
                    "consumed must report the certificate's length, not the buffer's");
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // The output arrays: fill_int_arrays and the blob
    // -----------------------------------------------------------------

    /**
     * Every {@code int[]} the accessors fill is checked for length BEFORE the
     * pointer is taken. {@code GetIntArrayElements} answers a valid pointer for
     * a short array and the fill would store past its end, which is a JVM
     * SIGBUS rather than an exception — so each site is driven one entry short,
     * with the exact size as its positive companion.
     */
    @Test
    public void shortOutputArrays_refusedAtEveryFillSite() throws Exception
    {
        long c = cert();
        long r = crl();
        try
        {
            final int certLen = ni.fieldsLen(c);
            final int certExtLen = ni.extensionsLen(c);
            final int[] info = new int[X509NI.INFO_COUNT];
            ni.fields(c, new byte[certLen], new int[X509NI.SLOT_COUNT], info);
            final int certExts = info[X509NI.INFO_EXT_COUNT];

            final int crlLen = ni.crlFieldsLen(r);
            final int crlExtLen = ni.crlExtensionsLen(r);
            final int crlEntryLen = ni.crlEntriesLen(r);
            final int[] crlInfo = new int[X509NI.CRL_INFO_COUNT];
            ni.crlFields(r, new byte[crlLen], new int[X509NI.CRL_SLOT_COUNT], crlInfo);
            final int crlExts = crlInfo[X509NI.CRL_INFO_EXT_COUNT];
            final int crlEntries = crlInfo[X509NI.CRL_INFO_ENTRY_COUNT];

            Assertions.assertTrue(certExts > 0 && crlExts > 0 && crlEntries > 0,
                    "the fixtures must carry extensions and revoked entries, or the "
                            + "short-array probes below would be vacuous");

            Assertions.assertAll(
                    () -> tooSmall(() -> ni.fields(c, new byte[certLen - 1],
                            new int[X509NI.SLOT_COUNT], new int[X509NI.INFO_COUNT])),
                    () -> tooSmall(() -> ni.fields(c, new byte[certLen],
                            new int[X509NI.SLOT_COUNT - 1], new int[X509NI.INFO_COUNT])),
                    () -> tooSmall(() -> ni.fields(c, new byte[certLen],
                            new int[X509NI.SLOT_COUNT], new int[X509NI.INFO_COUNT - 1])),
                    () -> tooSmall(() -> ni.extensions(c, new byte[certExtLen], new int[certExts - 1],
                            new int[certExts], new int[certExts])),
                    () -> tooSmall(() -> ni.extensions(c, new byte[certExtLen], new int[certExts],
                            new int[certExts - 1], new int[certExts])),
                    () -> tooSmall(() -> ni.extensions(c, new byte[certExtLen], new int[certExts],
                            new int[certExts], new int[certExts - 1])),
                    () -> tooSmall(() -> ni.crlFields(r, new byte[crlLen - 1],
                            new int[X509NI.CRL_SLOT_COUNT], new int[X509NI.CRL_INFO_COUNT])),
                    () -> tooSmall(() -> ni.crlFields(r, new byte[crlLen],
                            new int[X509NI.CRL_SLOT_COUNT - 1], new int[X509NI.CRL_INFO_COUNT])),
                    () -> tooSmall(() -> ni.crlFields(r, new byte[crlLen],
                            new int[X509NI.CRL_SLOT_COUNT], new int[X509NI.CRL_INFO_COUNT - 1])),
                    () -> tooSmall(() -> ni.crlExtensions(r, new byte[crlExtLen], new int[crlExts - 1],
                            new int[crlExts], new int[crlExts])),
                    () -> tooSmall(() -> ni.crlExtensions(r, new byte[crlExtLen], new int[crlExts],
                            new int[crlExts - 1], new int[crlExts])),
                    () -> tooSmall(() -> ni.crlExtensions(r, new byte[crlExtLen], new int[crlExts],
                            new int[crlExts], new int[crlExts - 1])),
                    () -> tooSmall(() -> ni.crlEntries(r, new byte[crlEntryLen - 1],
                            new int[crlEntries], new int[2 * crlEntries])),
                    () -> tooSmall(() -> ni.crlEntries(r, new byte[crlEntryLen],
                            new int[crlEntries - 1], new int[2 * crlEntries])),
                    () -> tooSmall(() -> ni.crlEntries(r, new byte[crlEntryLen],
                            new int[crlEntries], new int[2 * crlEntries - 1])));

            // The boundary the other way: at the exact sizes every call works.
            ni.fields(c, new byte[certLen], new int[X509NI.SLOT_COUNT], new int[X509NI.INFO_COUNT]);
            ni.extensions(c, new byte[certExtLen], new int[certExts], new int[certExts],
                    new int[certExts]);
            ni.crlFields(r, new byte[crlLen], new int[X509NI.CRL_SLOT_COUNT],
                    new int[X509NI.CRL_INFO_COUNT]);
            ni.crlExtensions(r, new byte[crlExtLen], new int[crlExts], new int[crlExts],
                    new int[crlExts]);
            ni.crlEntries(r, new byte[crlEntryLen], new int[crlEntries], new int[2 * crlEntries]);
        }
        finally
        {
            ni.dispose(c);
            ni.disposeCrl(r);
        }
    }

    @Test
    public void nullOutputArrays_refusedTyped() throws Exception
    {
        long c = cert();
        long r = crl();
        try
        {
            Assertions.assertAll(
                    () -> outputNull(() -> ni.fields(c, null, new int[X509NI.SLOT_COUNT],
                            new int[X509NI.INFO_COUNT])),
                    () -> outputNull(() -> ni.fields(c, new byte[ni.fieldsLen(c)], null,
                            new int[X509NI.INFO_COUNT])),
                    () -> outputNull(() -> ni.fields(c, new byte[ni.fieldsLen(c)],
                            new int[X509NI.SLOT_COUNT], null)),
                    () -> outputNull(() -> ni.crlFields(r, null, new int[X509NI.CRL_SLOT_COUNT],
                            new int[X509NI.CRL_INFO_COUNT])),
                    () -> outputNull(() -> ni.crlFields(r, new byte[ni.crlFieldsLen(r)], null,
                            new int[X509NI.CRL_INFO_COUNT])));
        }
        finally
        {
            ni.dispose(c);
            ni.disposeCrl(r);
        }
    }

    // -----------------------------------------------------------------

    private static void wrongKind(Executable call)
    {
        assertTyped(IllegalArgumentException.class, "handle is not of the kind this call expects", call);
    }

    private static void nullHandle(Executable call)
    {
        assertTyped(IllegalArgumentException.class, "handle is null", call);
    }

    private static void tooSmall(Executable call)
    {
        assertTyped(IllegalArgumentException.class, "output too small", call);
    }

    private static void outputNull(Executable call)
    {
        assertTyped(NullPointerException.class, "output is null", call);
    }

    private static void assertTyped(Class<? extends RuntimeException> type, String message,
                                    Executable call)
    {
        Assertions.assertEquals(message, Assertions.assertThrows(type, call).getMessage());
    }
}
