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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cert.X509NI;
import org.openssl.jostle.test.certpath.PkitsCertificates;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Fault injection over the X.509 native surface.
 *
 * <p>The injected codes are {@code JO_OPENSSL_ERROR + -offset}, so
 * {@code -2 - offset}. The offsets are the 7000 block declared at the top of
 * {@code interface/nonfips/util/x509.c}, and they ARE the test contract:
 * renumbering one in C without changing it here is silent, because the test
 * would then see a different but equally legitimate negative number.
 */
public class X509OpsTest
{
    private final X509NI x509NI = NISelector.X509NI;
    private final OperationsTestNI operationsTestNI =
            org.openssl.jostle.test.crypto.TestNISelector.getOperationsTestNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    private static byte[] cert() throws Exception
    {
        return PkitsCertificates.der("GoodCACert.crt");
    }

    private static byte[] crl() throws Exception
    {
        return PkitsCertificates.crlDer("GoodCACRL.crl");
    }

    @Test
    public void certificateAllocate_x509NewExFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/nonfips/util/x509.c, offset 7000
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int[] err = new int[1];
            byte[] der = cert();
            x509NI.ni_allocate(der, 0, der.length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1], err);
            Assertions.assertEquals(-7002, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void crlAllocate_x509CrlNewExFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/nonfips/util/x509.c, offset 7005
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int[] err = new int[1];
            byte[] der = crl();
            x509NI.ni_allocateCrl(der, 0, der.length, X509NI.maxContainerBytes(), new int[1], err);
            Assertions.assertEquals(-7007, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    /**
     * The d2i arms carry {@code OPS_OPENSSL_ERROR_2} but return
     * {@code JO_CERT_DECODE_FAILED} with NO offset, so an injected failure is
     * indistinguishable BY CODE from a natural one. That is deliberate: the
     * code is not an OpenSSL error and inventing an offset for it would make
     * the number mean something it does not.
     *
     * <p>So this cell discriminates by the FLAG instead — a VALID certificate
     * must decode with the flag clear and refuse with it set. Do not "fix" the
     * missing offset; there is nothing to fix.
     */
    @Test
    public void certificateDecode_injectedD2iFailureIsToldApartByTheFlagNotTheCode() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        byte[] der = cert();
        int[] errClear = new int[1];
        try
        {
            // Control first: the same bytes, no flag, must decode.
            long ref = x509NI.ni_allocate(der, 0, der.length,
                    X509NI.DEFAULT_MAX_CERT_BYTES, new int[1], errClear);
            Assertions.assertEquals(0, errClear[0], "a valid certificate must decode with no flag set");
            Assertions.assertNotEquals(0L, ref);
            x509NI.ni_dispose(ref);

            // Exercises interface/nonfips/util/x509.c d2i_X509 arm (no offset)
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int[] err = new int[1];
            x509NI.ni_allocate(der, 0, der.length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1], err);
            Assertions.assertEquals(-175, err[0], "JO_CERT_DECODE_FAILED, injected");
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void certificateFields_forcedTbsReEncodeFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            byte[] der = cert();
            ref = x509NI.allocate(der, 0, der.length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            // Exercises interface/nonfips/util/x509.c, offset 7003
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
    public void certificateFields_signatureAlgorithmEncodeFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            byte[] der = cert();
            ref = x509NI.allocate(der, 0, der.length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            // Exercises interface/nonfips/util/x509.c, offset 7001
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
    public void certificateAllocate_inputAccessFailure() throws Exception
    {
        // JNI ONLY. These are bridge access faults, and the FFI bridge
        // carries no such points BY CONSTRUCTION — it receives segments the
        // caller already copied, so there is no load to fail. Without this
        // the cell passes on the JNI leg and fails on the FFI one.
        Assumptions.assumeFalse(org.openssl.jostle.Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        try
        {
            // Exercises interface/nonfips/jni/x509_ni_jni.c input load arm
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            int[] err = new int[1];
            byte[] der = cert();
            x509NI.ni_allocate(der, 0, der.length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1], err);
            Assertions.assertEquals(-22, err[0], "JO_FAILED_ACCESS_INPUT");
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    /**
     * The arm {@code parse()} gained so nothing unchecked escapes: an injected
     * OpenSSL failure at allocate must reach a caller of
     * {@code generateCertificate} as the JCA-contract {@link CertificateException},
     * never as the raw runtime exception the NI raises.
     */
    @Test
    public void generateCertificate_injectedFailureSurfacesAsCertificateException() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        CertificateFactory cf = CertificateFactory.getInstance("X.509", jsl);
        byte[] der = cert();
        try
        {
            // Exercises interface/nonfips/util/x509.c, offset 7000, through the SPI
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            CertificateException e = Assertions.assertThrows(CertificateException.class,
                    () -> cf.generateCertificate(new ByteArrayInputStream(der)));
            Assertions.assertTrue(e.getMessage().contains("could not parse certificate"),
                    "expected the SPI's wrapping, got: " + e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // The remaining instrumented sites. OPS_OPENSSL_ERROR_4 and _6 each
    // appear TWICE in x509.c — once on the certificate path, once on the CRL
    // path — so the flag alone does not name the site; the OBJECT being driven
    // does, and the distinct offsets prove which one fired.
    // -----------------------------------------------------------------

    @Test
    public void certificateFields_signatureEncodeFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocate(cert(), 0, cert().length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            // Exercises interface/nonfips/util/x509.c, offset 7002
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
    public void certificateFields_encodingAllocationFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocate(cert(), 0, cert().length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            int need = x509NI.ni_fieldsLen(ref);
            Assertions.assertTrue(need > 0, "control: the length query must succeed first");
            // Exercises interface/nonfips/util/x509.c, offset 7004
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            Assertions.assertEquals(-7006, x509NI.ni_fields(ref, new byte[need],
                    new int[X509NI.SLOT_COUNT], new int[X509NI.INFO_COUNT]));
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
    public void certificateFields_encodingLengthOverflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocate(cert(), 0, cert().length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            // Exercises interface/nonfips/util/x509.c composed-encoding size guard
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
    public void crlFields_entryEncodeFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocateCrl(crl(), 0, crl().length, X509NI.maxContainerBytes(), new int[1]);
            // Exercises interface/nonfips/util/x509.c, offset 7009
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
    public void crlFields_encodingAllocationFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocateCrl(crl(), 0, crl().length, X509NI.maxContainerBytes(), new int[1]);
            int need = x509NI.ni_crlFieldsLen(ref);
            Assertions.assertTrue(need > 0, "control: the length query must succeed first");
            // Exercises interface/nonfips/util/x509.c, offset 7007
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            Assertions.assertEquals(-7009, x509NI.ni_crlFields(ref, new byte[need],
                    new int[X509NI.CRL_SLOT_COUNT], new int[X509NI.CRL_INFO_COUNT]));
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
    public void crlFields_encodingLengthOverflow() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long ref = 0;
        try
        {
            ref = x509NI.allocateCrl(crl(), 0, crl().length, X509NI.maxContainerBytes(), new int[1]);
            // Exercises interface/nonfips/util/x509.c CRL composed-encoding size guard
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
    public void certificateFields_outputArrayAccessFailure() throws Exception
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
            ref = x509NI.allocate(cert(), 0, cert().length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            int need = x509NI.ni_fieldsLen(ref);
            // Exercises interface/nonfips/jni/x509_ni_jni.c sizes/info load arm
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            Assertions.assertEquals(-23, x509NI.ni_fields(ref, new byte[need],
                    new int[X509NI.SLOT_COUNT], new int[X509NI.INFO_COUNT]),
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
    public void certificateExtensions_outputArrayAccessFailure() throws Exception
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
            ref = x509NI.allocate(cert(), 0, cert().length, X509NI.DEFAULT_MAX_CERT_BYTES, new int[1]);
            int count = x509NI.ni_extensionsLen(ref);
            Assertions.assertTrue(count > 0, "control: the fixture must carry extensions");
            // Exercises interface/nonfips/jni/x509_ni_jni.c extension arrays load arm
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
