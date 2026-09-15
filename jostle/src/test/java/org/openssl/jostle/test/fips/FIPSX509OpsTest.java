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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.certpath.PkitsCertificates;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * The JSLFIPS X.509 factory drives the FIPS interface library, witnessed by
 * BEHAVIOUR rather than by reading a field.
 *
 * <p>The two interface libraries carry SEPARATE operations-test flag state —
 * each is a distinct shared object with its own statics. That is the whole
 * mechanism here: a fault injected through the FIPS library's own
 * {@code OperationsTestNI} is visible to the FIPS library and to nothing else.
 * So a JSLFIPS factory wired to the BASE library never sees the flag, parses
 * happily, and fails the first cell.
 *
 * <p>Falsification-verified against that exact sabotage ({@code ProvFIPSX509}
 * re-wired to {@code NISelector.X509NI}, confirmed present in the built jar):
 * this class goes RED where {@code FIPSX509LibraryBindingTest} stayed green,
 * which is why both exist. The division of labour:
 *
 * <ul>
 *   <li>{@code FIPSNativeBindingIsolationTest} — the ALWAYS-ON guard. A source
 *       and field-level walk, so it runs on every leg.</li>
 *   <li>this class — the BEHAVIOURAL witness, and only on the injection leg,
 *       since it needs a {@code JOSTLE_OPS_TEST} build of the FIPS library.</li>
 *   <li>{@code FIPSX509LibraryBindingTest} — a capability contract, measured
 *       NOT to discriminate the wiring; its javadoc says so.</li>
 * </ul>
 *
 * <p>The injected site is the {@code d2i_X509} arm of
 * {@code interface/fips/util/x509.c}. It returns {@code JO_CERT_DECODE_FAILED}
 * with NO offset, deliberately — the code is not an OpenSSL error and inventing
 * an offset would make the number mean something it does not — so, exactly as
 * in the base {@code X509OpsTest}, these cells discriminate by the FLAG and not
 * by the code: a VALID certificate must refuse with the flag set and parse with
 * it clear.
 */
public class FIPSX509OpsTest
{
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    private Provider fips;

    @BeforeEach
    public void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    private static byte[] cert() throws Exception
    {
        return PkitsCertificates.der("GoodCACert.crt");
    }

    private CertificateFactory fipsFactory() throws Exception
    {
        return CertificateFactory.getInstance("X.509", fips);
    }

    private static CertificateFactory baseFactory() throws Exception
    {
        return CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);
    }

    private static X509Certificate parse(CertificateFactory cf, byte[] der) throws Exception
    {
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    /**
     * The load-bearing cell. A fault set in the FIPS library must reach the
     * JSLFIPS factory; a factory driving the base library would not see it.
     */
    @Test
    public void fipsFactory_seesAFaultInjectedIntoTheFipsLibrary() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        byte[] der = cert();
        CertificateFactory cf = fipsFactory();

        // Control FIRST, and from a factory that has not yet been driven: a
        // valid certificate parses when nothing is injected, so the refusal
        // below cannot be blamed on the input.
        Assertions.assertNotNull(parse(cf, der), "valid certificate must parse with no flag set");

        try
        {
            // Exercises interface/fips/util/x509.c d2i_X509 arm (no offset)
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            CertificateException ex = Assertions.assertThrows(CertificateException.class,
                    () -> parse(cf, der),
                    "JSLFIPS must see the fault injected into the FIPS library;"
                            + " a factory wired to the base library would not");
            Assertions.assertEquals("input did not decode as an X.509 certificate", ex.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }

        // And it recovers, so the refusal was the flag and not a poisoned SPI.
        Assertions.assertNotNull(parse(cf, der), "must parse again once the flag is cleared");
    }

    /**
     * The flag state is per-library, so the base factory is untouched by it.
     * Without this, a mechanism that set the flag in BOTH libraries would
     * satisfy the cell above while proving nothing about which one JSLFIPS
     * drives.
     */
    @Test
    public void baseFactory_isUnaffectedByAFaultInTheFipsLibrary() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        byte[] der = cert();
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertNotNull(parse(baseFactory(), der),
                    "the base factory must not see a fault injected into the FIPS library");
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // NI-level mirror of X509OpsTest, driven through the FIPS library.
    //
    // The offsets are identical because the trees are twins; what these pin is
    // that the sites FIRE when driven through interface/fips, which the base
    // class cannot show. Annotations name interface/fips/ deliberately —
    // FIPSOpsAnnotationParityTest fails a FIPS test that points at nonfips.
    // -----------------------------------------------------------------

    private final org.openssl.jostle.jcajce.provider.cert.X509NI x509NI =
            org.openssl.jostle.jcajce.provider.fips.FIPSNISelector.X509NI;

    private static byte[] crl() throws Exception
    {
        return org.openssl.jostle.test.certpath.PkitsCertificates.crlDer("TrustAnchorRootCRL.crl");
    }

    @Test
    public void fips_certificateAllocate_x509NewExFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/fips/util/x509.c, offset 7000
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int[] err = new int[1];
            byte[] der = cert();
            x509NI.ni_allocate(der, 0, der.length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1], err);
            Assertions.assertEquals(-7002, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void fips_crlAllocate_x509CrlNewExFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/fips/util/x509.c, offset 7005
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int[] err = new int[1];
            byte[] der = crl();
            x509NI.ni_allocateCrl(der, 0, der.length, org.openssl.jostle.jcajce.provider.cert.X509NI.maxContainerBytes(), new int[1], err);
            Assertions.assertEquals(-7007, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void fips_certificateDecode_injectedD2iFailureIsToldApartByTheFlagNotTheCode() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        byte[] der = cert();
        int[] errClear = new int[1];
        try
        {
            // Control first: the same bytes, no flag, must decode.
            long ref = x509NI.ni_allocate(der, 0, der.length,
                    org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1], errClear);
            Assertions.assertEquals(0, errClear[0], "a valid certificate must decode with no flag set");
            Assertions.assertNotEquals(0L, ref);
            x509NI.ni_dispose(ref);

            // Exercises interface/fips/util/x509.c d2i_X509 arm (no offset)
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int[] err = new int[1];
            x509NI.ni_allocate(der, 0, der.length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1], err);
            Assertions.assertEquals(-175, err[0], "JO_CERT_DECODE_FAILED, injected");
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void fips_certificateFields_forcedTbsReEncodeFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            byte[] der = cert();
            ref = x509NI.allocate(der, 0, der.length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            // Exercises interface/fips/util/x509.c, offset 7003
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            Assertions.assertEquals(-7005, x509NI.ni_fieldsLen(ref));
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_dispose(ref);
            }
        }
    }

    @Test
    public void fips_certificateFields_signatureAlgorithmEncodeFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            byte[] der = cert();
            ref = x509NI.allocate(der, 0, der.length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            // Exercises interface/fips/util/x509.c, offset 7001
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            Assertions.assertEquals(-7003, x509NI.ni_fieldsLen(ref));
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_dispose(ref);
            }
        }
    }

    @Test
    public void fips_certificateAllocate_inputAccessFailure() throws Exception
    {
        // JNI ONLY. These are bridge access faults, and the FFI bridge
        // carries no such points BY CONSTRUCTION — it receives segments the
        // caller already copied, so there is no load to fail. Without this
        // the cell passes on the JNI leg and fails on the FFI one.
        Assumptions.assumeFalse(org.openssl.jostle.Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/fips/jni/x509_ni_jni.c input load arm
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            byte[] der = cert();
            x509NI.ni_allocate(der, 0, der.length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1], err);
            Assertions.assertEquals(-22, err[0], "JO_FAILED_ACCESS_INPUT");
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void fips_certificateFields_signatureEncodeFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocate(cert(), 0, cert().length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            // Exercises interface/fips/util/x509.c, offset 7002
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            Assertions.assertEquals(-7004, x509NI.ni_fieldsLen(ref));
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_dispose(ref);
            }
        }
    }

    @Test
    public void fips_certificateFields_encodingAllocationFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocate(cert(), 0, cert().length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            int need = x509NI.ni_fieldsLen(ref);
            Assertions.assertTrue(need > 0, "control: the length query must succeed first");
            // Exercises interface/fips/util/x509.c, offset 7004
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            Assertions.assertEquals(-7006, x509NI.ni_fields(ref, new byte[need],
                    new int[org.openssl.jostle.jcajce.provider.cert.X509NI.SLOT_COUNT], new int[org.openssl.jostle.jcajce.provider.cert.X509NI.INFO_COUNT]));
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_dispose(ref);
            }
        }
    }

    @Test
    public void fips_certificateFields_encodingLengthOverflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocate(cert(), 0, cert().length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            // Exercises interface/fips/util/x509.c composed-encoding size guard
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            Assertions.assertEquals(-20, x509NI.ni_fieldsLen(ref), "JO_OUTPUT_TOO_LONG_INT32");
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_dispose(ref);
            }
        }
    }

    @Test
    public void fips_crlFields_entryEncodeFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocateCrl(crl(), 0, crl().length, org.openssl.jostle.jcajce.provider.cert.X509NI.maxContainerBytes(), new int[1]);
            // Exercises interface/fips/util/x509.c, offset 7009
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            Assertions.assertEquals(-7011, x509NI.ni_crlEntriesLen(ref));
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_disposeCrl(ref);
            }
        }
    }

    @Test
    public void fips_crlFields_encodingAllocationFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocateCrl(crl(), 0, crl().length, org.openssl.jostle.jcajce.provider.cert.X509NI.maxContainerBytes(), new int[1]);
            int need = x509NI.ni_crlFieldsLen(ref);
            Assertions.assertTrue(need > 0, "control: the length query must succeed first");
            // Exercises interface/fips/util/x509.c, offset 7007
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            Assertions.assertEquals(-7009, x509NI.ni_crlFields(ref, new byte[need],
                    new int[org.openssl.jostle.jcajce.provider.cert.X509NI.CRL_SLOT_COUNT], new int[org.openssl.jostle.jcajce.provider.cert.X509NI.CRL_INFO_COUNT]));
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_disposeCrl(ref);
            }
        }
    }

    @Test
    public void fips_crlFields_encodingLengthOverflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocateCrl(crl(), 0, crl().length, org.openssl.jostle.jcajce.provider.cert.X509NI.maxContainerBytes(), new int[1]);
            // Exercises interface/fips/util/x509.c CRL composed-encoding size guard
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
            Assertions.assertEquals(-20, x509NI.ni_crlFieldsLen(ref), "JO_OUTPUT_TOO_LONG_INT32");
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_disposeCrl(ref);
            }
        }
    }

    @Test
    public void fips_certificateFields_outputArrayAccessFailure() throws Exception
    {
        // JNI ONLY. These are bridge access faults, and the FFI bridge
        // carries no such points BY CONSTRUCTION — it receives segments the
        // caller already copied, so there is no load to fail. Without this
        // the cell passes on the JNI leg and fails on the FFI one.
        Assumptions.assumeFalse(org.openssl.jostle.Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocate(cert(), 0, cert().length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            int need = x509NI.ni_fieldsLen(ref);
            // Exercises interface/fips/jni/x509_ni_jni.c sizes/info load arm
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            Assertions.assertEquals(-23, x509NI.ni_fields(ref, new byte[need],
                    new int[org.openssl.jostle.jcajce.provider.cert.X509NI.SLOT_COUNT], new int[org.openssl.jostle.jcajce.provider.cert.X509NI.INFO_COUNT]),
                    "JO_FAILED_ACCESS_OUTPUT");
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_dispose(ref);
            }
        }
    }

    @Test
    public void fips_certificateExtensions_outputArrayAccessFailure() throws Exception
    {
        // JNI ONLY. These are bridge access faults, and the FFI bridge
        // carries no such points BY CONSTRUCTION — it receives segments the
        // caller already copied, so there is no load to fail. Without this
        // the cell passes on the JNI leg and fails on the FFI one.
        Assumptions.assumeFalse(org.openssl.jostle.Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocate(cert(), 0, cert().length, org.openssl.jostle.jcajce.provider.cert.X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            int count = x509NI.ni_extensionsLen(ref);
            Assertions.assertTrue(count > 0, "control: the fixture must carry extensions");
            // Exercises interface/fips/jni/x509_ni_jni.c extension arrays load arm
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_3);
            Assertions.assertEquals(-23, x509NI.ni_extensions(ref, new byte[4096],
                    new int[count], new int[count], new int[count]),
                    "JO_FAILED_ACCESS_OUTPUT");
        }
        finally
        {
            operationsTestNI.resetFlags();
            if (ref != 0)
            {
                x509NI.ni_dispose(ref);
            }
        }
    }
}
