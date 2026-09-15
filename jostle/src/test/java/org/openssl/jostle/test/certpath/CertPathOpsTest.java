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

package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.certpath.CertPathNI;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

/**
 * Fault injection over the certification-path native surface.
 *
 * <p>Every site driven here is an allocation failure or a mid-sequence OpenSSL
 * failure that NO supported configuration reaches — an {@code X509_STORE_new}
 * returning null, an {@code sk_X509_push} refusing. That is precisely what OPS
 * is for; a real-trigger limit test is impossible because no input provokes
 * them.
 *
 * <p><b>These cells discriminate by FLAG, not by code.</b> Every instrumented
 * site in {@code certpath.c} returns {@code JO_FAIL}, which is not
 * {@code JO_OPENSSL_ERROR}, so no {@code OPS_OFFSET_*} applies and the codes
 * cannot tell two sites apart. Each cell therefore sets exactly ONE flag and
 * asserts the call went from success to {@code JO_FAIL}. The positive control
 * runs first in every cell, so a refusal can never be blamed on the fixture.
 * The same reasoning is written at the top of {@code certpath.c}; do not "fix"
 * the absent offsets.
 *
 * <p>The flags are deliberately disjoint from the X.509 ones — a path call
 * re-parses through the X.509 factory, so a shared flag would fire in two
 * files at once.
 *
 * <p>There is no FIPS twin: {@code certpath.c} is nonfips-only, JSLFIPS
 * registering neither a CertPathValidator nor a CertPathBuilder, and the
 * tree-parity audit sanctions that.
 */
public class CertPathOpsTest
{
    private final CertPathNI ni = NISelector.CertPathNI;
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

    /**
     * A two-entry path: the PKITS trust anchor, then Good CA which it issued.
     * Marshalled by hand in the bridge's own order — anchors first, target
     * last — rather than through the package-private marshaller, which this
     * package cannot see.
     */
    private static final class Path
    {
        final byte[] der;
        final int[] sizes;
        final int count;
        final int anchorCount;
        final byte[] chainOut;
        final int[] outInfo;

        final int crlCount;
        final int revocation;

        /** Anchor then target: the shortest path the bridge accepts. */
        Path() throws Exception
        {
            this(new String[]{ PkitsCertificates.ANCHOR, "GoodCACert.crt" }, new String[0]);
        }

        Path(String[] certs, String[] crls) throws Exception
        {
            byte[][] parts = new byte[certs.length + crls.length][];
            int i = 0;
            for (String c : certs)
            {
                parts[i++] = PkitsCertificates.der(c);
            }
            for (String c : crls)
            {
                parts[i++] = PkitsCertificates.crlDer(c);
            }

            int total = 0;
            for (byte[] b : parts)
            {
                total += b.length;
            }
            der = new byte[total];
            sizes = new int[parts.length];
            int off = 0;
            for (int j = 0; j < parts.length; j++)
            {
                System.arraycopy(parts[j], 0, der, off, parts[j].length);
                off += parts[j].length;
                sizes[j] = parts[j].length;
            }

            count = certs.length;
            crlCount = crls.length;
            anchorCount = 1;
            revocation = crls.length == 0 ? 0 : 1;
            chainOut = new byte[der.length];
            outInfo = new int[CertPathNI.OUT_INFO_HEADER + count];
        }

        int verify()
        {
            return NISelector.CertPathNI.ni_verify(der, sizes, count, crlCount, anchorCount,
                    CertPathNI.TIME_NOW, 0, revocation, chainOut, outInfo);
        }
    }

    /** JO_FAIL; the instrumented sites all report it. */
    private static final int JO_FAIL = -1;

    /**
     * Drive one flag: the same path must verify with it clear and fail with it
     * set. The control comes FIRST, so the fixture is proven good before the
     * flag is blamed for anything.
     */
    private interface Fixture
    {
        Path build() throws Exception;
    }

    private static final Fixture SHORT = new Fixture()
    {
        public Path build() throws Exception
        {
            return new Path();
        }
    };

    /** Three certificates, so the middle one reaches the untrusted stack. */
    private static final Fixture WITH_INTERMEDIATE = new Fixture()
    {
        public Path build() throws Exception
        {
            return new Path(new String[]{ PkitsCertificates.ANCHOR, "GoodCACert.crt",
                    "ValidCertificatePathTest1EE.crt" }, new String[0]);
        }
    };

    /** Same, plus the two CRLs, so the CRL stack is reached. */
    private static final Fixture WITH_CRLS = new Fixture()
    {
        public Path build() throws Exception
        {
            return new Path(new String[]{ PkitsCertificates.ANCHOR, "GoodCACert.crt",
                    "ValidCertificatePathTest1EE.crt" },
                    new String[]{ "TrustAnchorRootCRL.crl", "GoodCACRL.crl" });
        }
    };

    private void assertFlagBreaksVerification(OperationsTestNI.OpsTestFlag flag, String site)
        throws Exception
    {
        assertFlagBreaksVerification(SHORT, flag, site);
    }

    private void assertFlagBreaksVerification(Fixture fixture, OperationsTestNI.OpsTestFlag flag,
                                              String site)
        throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");

        Assertions.assertEquals(0, fixture.build().verify(),
                "control: the path must verify with no flag set, or the cell measures the fixture");

        try
        {
            operationsTestNI.setFlag(flag);
            Assertions.assertEquals(JO_FAIL, fixture.build().verify(),
                    site + " was not reached, or did not report JO_FAIL");
        }
        finally
        {
            operationsTestNI.resetFlags();
        }

        Assertions.assertEquals(0, fixture.build().verify(),
                "and it recovers once the flag is cleared");
    }

    @Test
    public void storeAllocationFailure() throws Exception
    {
        // Exercises interface/nonfips/util/certpath.c X509_STORE_new arm
        assertFlagBreaksVerification(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1,
                "the store/untrusted/crls allocation arm");
    }

    @Test
    public void storeAddCertFailure() throws Exception
    {
        // Exercises interface/nonfips/util/certpath.c X509_STORE_add_cert arm
        assertFlagBreaksVerification(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7,
                "the X509_STORE_add_cert arm");
    }

    @Test
    public void storeCtxAllocationOrInitFailure() throws Exception
    {
        // Exercises interface/nonfips/util/certpath.c X509_STORE_CTX_new_ex/init arm
        assertFlagBreaksVerification(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_2,
                "the store-ctx allocate-and-init arm");
    }

    @Test
    public void chainSizesAllocationFailure() throws Exception
    {
        // Exercises interface/nonfips/util/certpath.c capture_chain chain_sizes arm
        assertFlagBreaksVerification(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10,
                "the capture_chain chain_sizes allocation arm");
    }

    @Test
    public void chainMeasureFailure() throws Exception
    {
        // Exercises interface/nonfips/util/certpath.c capture_chain i2d measure arm
        assertFlagBreaksVerification(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11,
                "the capture_chain i2d measuring arm");
    }

    @Test
    public void chainDerAllocationFailure() throws Exception
    {
        // Exercises interface/nonfips/util/certpath.c capture_chain chain_der arm
        assertFlagBreaksVerification(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_12,
                "the capture_chain chain_der allocation arm");
    }

    /**
     * The bridge's input-access arm, which is a different layer from the six
     * above: it fails before util is entered at all.
     */
    @Test
    public void bridgeInputAccessFailure() throws Exception
    {
        // JNI ONLY. These are bridge access faults, and the FFI bridge
        // carries no such points BY CONSTRUCTION — it receives segments the
        // caller already copied, so there is no load to fail. Without this
        // the cell passes on the JNI leg and fails on the FFI one.
        Assumptions.assumeFalse(org.openssl.jostle.Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assertions.assertEquals(0, new Path().verify(), "control");
        try
        {
            // Exercises interface/nonfips/jni/certpath_ni_jni.c input load arm
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_4);
            Assertions.assertEquals(-22, new Path().verify(), "JO_FAILED_ACCESS_INPUT");
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void bridgeOutputAccessFailure() throws Exception
    {
        // JNI ONLY. These are bridge access faults, and the FFI bridge
        // carries no such points BY CONSTRUCTION — it receives segments the
        // caller already copied, so there is no load to fail. Without this
        // the cell passes on the JNI leg and fails on the FFI one.
        Assumptions.assumeFalse(org.openssl.jostle.Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assertions.assertEquals(0, new Path().verify(), "control");
        try
        {
            // Exercises interface/nonfips/jni/certpath_ni_jni.c chainOut load arm
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_5);
            Assertions.assertEquals(-23, new Path().verify(), "JO_FAILED_ACCESS_OUTPUT");
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void untrustedPushFailure() throws Exception
    {
        // Exercises interface/nonfips/util/certpath.c sk_X509_push arm
        assertFlagBreaksVerification(WITH_INTERMEDIATE,
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8,
                "the sk_X509_push arm, which only a path WITH an intermediate reaches");
    }

    @Test
    public void crlPushFailure() throws Exception
    {
        // Exercises interface/nonfips/util/certpath.c sk_X509_CRL_push arm
        assertFlagBreaksVerification(WITH_CRLS,
                OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_9,
                "the sk_X509_CRL_push arm, which only a call carrying CRLs reaches");
    }

    @Test
    public void bridgeSizesAccessFailure() throws Exception
    {
        // JNI ONLY. These are bridge access faults, and the FFI bridge
        // carries no such points BY CONSTRUCTION — it receives segments the
        // caller already copied, so there is no load to fail. Without this
        // the cell passes on the JNI leg and fails on the FFI one.
        Assumptions.assumeFalse(org.openssl.jostle.Loader.isFFI(), "JNI only");
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "OPS Test support not compiled in");
        Assertions.assertEquals(0, new Path().verify(), "control");
        try
        {
            // Exercises interface/nonfips/jni/certpath_ni_jni.c sizes load arm
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_6);
            Assertions.assertEquals(-22, new Path().verify(), "JO_FAILED_ACCESS_INPUT");
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }
}
