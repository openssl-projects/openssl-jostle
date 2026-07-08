/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.UnexpectedPointerChangeException;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Operations-test fault injection at the FIPS ASN.1 encoder/decoder NI surface.
 * The fault sites live in the shared interface/fips/util/asn1_util.c and the JNI glue
 * interface/fips/jni/asn1_ni_jni.c, re-included into the FIPS library, so they fire
 * identically when driven through {@link FIPSNISelector#Asn1NI}. Mirrors
 * {@code ASN1UtilOpsTest}.
 *
 * <p>FIPS divergence: the base drives the encode/decode paths with ML-DSA (and
 * ML-KEM) keys, which the FIPS 3.1.2 module does not serve. This version
 * substitutes a P-256 EC key (FIPS-approved) for the encode tests and produces
 * the valid DER for the decode/pointer-change tests by encoding that key through
 * the FIPS Asn1 bridge itself. The two ML-DSA/ML-KEM-specific {@code seedOnly}
 * tests are omitted (PQC is absent from the module). The fault sites under test
 * are key-type-independent (overflow/i2d/access-string/pointer-change), so the
 * substitution preserves the coverage.
 *
 * <p>Requires a JOSTLE_OPS_TEST build of the FIPS library: gated on
 * {@code TEST_FIPS_LIB} and per-test on {@code opsTestAvailable()}.
 */
public class FIPSASN1UtilOpsTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final Asn1Ni asn1NI = FIPSNISelector.Asn1NI;
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;
    private final ECServiceNI ec = FIPSNISelector.ECServiceNI;

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    /** A P-256 keypair spec ref (FIPS-approved), for the encode/decode tests. */
    private long genEcKey()
    {
        long keyRef = ec.generateKeyPair("P-256", RND);
        Assertions.assertTrue(keyRef > 0);
        return keyRef;
    }

    /** Encode a key through the FIPS Asn1 bridge into DER (no OPS flag armed). */
    private byte[] encode(long keyRef, boolean priv)
    {
        long a = asn1NI.allocate();
        try
        {
            int len = priv
                    ? asn1NI.encodePrivateKey(a, keyRef, PrivateKeyOptions.DEFAULT.getValue())
                    : asn1NI.encodePublicKey(a, keyRef);
            byte[] der = new byte[len];
            asn1NI.getData(a, der);
            return der;
        }
        finally
        {
            asn1NI.dispose(a);
        }
    }

    // -----------------------------------------------------------------
    // decode overflow (no key needed — bad input triggers the length gate)
    // -----------------------------------------------------------------

    @Test
    public void opsTestDecodePublicKey_Int32Overflow()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            keyRef = asn1NI.fromPublicKeyInfo(new byte[10], 0, 10);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("input too long int32", e.getMessage());
        }
        finally
        {
            if (keyRef > 0)
            {
                specNI.dispose(keyRef);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void opsTestDecodePrivateKey_Int32Overflow()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            keyRef = asn1NI.fromPrivateKeyInfo(new byte[10], 0, 10);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("input too long int32", e.getMessage());
        }
        finally
        {
            if (keyRef > 0)
            {
                specNI.dispose(keyRef);
            }
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // encode overflow / i2d failure (EC key substituted for ML-DSA)
    // -----------------------------------------------------------------

    @Test
    public void opsTestEncodePublicKey_Int32Overflow()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long asn1Ref = 0;
        long keyRef = 0;
        try
        {
            asn1Ref = asn1NI.allocate();
            keyRef = genEcKey();
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            asn1NI.encodePublicKey(asn1Ref, keyRef);
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            asn1NI.dispose(asn1Ref);
            specNI.dispose(keyRef);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void opsTestEncodePrivateKey_Int32Overflow()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long asn1Ref = 0;
        long keyRef = 0;
        try
        {
            asn1Ref = asn1NI.allocate();
            keyRef = genEcKey();
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            asn1NI.encodePrivateKey(asn1Ref, keyRef, PrivateKeyOptions.DEFAULT.getValue());
            Assertions.fail();
        }
        catch (OverflowException e)
        {
            Assertions.assertEquals("output too long int32", e.getMessage());
        }
        finally
        {
            asn1NI.dispose(asn1Ref);
            specNI.dispose(keyRef);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void opsTestEncodePublicKey_i2dFail()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long asn1Ref = 0;
        long keyRef = 0;
        try
        {
            asn1Ref = asn1NI.allocate();
            keyRef = genEcKey();
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            asn1NI.encodePublicKey(asn1Ref, keyRef);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            asn1NI.dispose(asn1Ref);
            specNI.dispose(keyRef);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void opsTestEncodePrivateKey_i2dFail()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long asn1Ref = 0;
        long keyRef = 0;
        try
        {
            asn1Ref = asn1NI.allocate();
            keyRef = genEcKey();
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            asn1NI.encodePrivateKey(asn1Ref, keyRef, PrivateKeyOptions.DEFAULT.getValue());
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            asn1NI.dispose(asn1Ref);
            specNI.dispose(keyRef);
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // JNI access faults (JNI-only)
    // -----------------------------------------------------------------

    @Test
    public void opsTestGetData_accessByteArray()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        long asn1Ref = 0;
        try
        {
            asn1Ref = asn1NI.allocate();
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            asn1NI.getData(asn1Ref, new byte[1024]);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            asn1NI.dispose(asn1Ref);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void opsTestEncodePrivateKey_accessOptionsString()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        long asn1Ref = 0;
        long keyRef = 0;
        try
        {
            asn1Ref = asn1NI.allocate();
            keyRef = genEcKey();
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            asn1NI.encodePrivateKey(asn1Ref, keyRef, PrivateKeyOptions.DEFAULT.getValue());
            Assertions.fail("Should have thrown exception");
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access string with encoding option", e.getMessage());
        }
        finally
        {
            asn1NI.dispose(asn1Ref);
            specNI.dispose(keyRef);
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void opsTestFromPrivateKeyInfo_accessByteArray()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            keyRef = asn1NI.fromPrivateKeyInfo(new byte[100], 0, 100);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            if (keyRef > 0)
            {
                specNI.dispose(keyRef);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void opsTestFromPublicKeyInfo_accessByteArray()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFI());
        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            keyRef = asn1NI.fromPublicKeyInfo(new byte[100], 0, 100);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access input array", e.getMessage());
        }
        finally
        {
            if (keyRef > 0)
            {
                specNI.dispose(keyRef);
            }
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // getData overflow (no key needed)
    // -----------------------------------------------------------------

    @Test
    public void opsTestGetData_Int32Overflow()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long asn1Ref = 0;
        try
        {
            asn1Ref = asn1NI.allocate();
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            asn1NI.getData(asn1Ref, null);
            Assertions.fail();
        }
        catch (OverflowException ex)
        {
            Assertions.assertEquals("output too long int32", ex.getMessage());
        }
        finally
        {
            asn1NI.dispose(asn1Ref);
            operationsTestNI.resetFlags();
        }
    }

    // -----------------------------------------------------------------
    // d2i pointer-change guard on decode (valid EC DER round-tripped in)
    // -----------------------------------------------------------------

    @Test
    public void opsTestFromPrivateKeyInfo_pointerChange()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ecKey = genEcKey();
        byte[] pkcs8;
        try
        {
            pkcs8 = encode(ecKey, true);
        }
        finally
        {
            specNI.dispose(ecKey);
        }

        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_POINTER_CHANGE);
            keyRef = asn1NI.fromPrivateKeyInfo(pkcs8, 0, pkcs8.length);
            Assertions.fail();
        }
        catch (UnexpectedPointerChangeException e)
        {
            Assertions.assertEquals("a returned pointer changed unexpectedly", e.getMessage());
        }
        finally
        {
            if (keyRef > 0)
            {
                specNI.dispose(keyRef);
            }
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void opsTestFromPublicKeyInfo_pointerChange()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long ecKey = genEcKey();
        byte[] x509;
        try
        {
            x509 = encode(ecKey, false);
        }
        finally
        {
            specNI.dispose(ecKey);
        }

        long keyRef = 0;
        try
        {
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_POINTER_CHANGE);
            keyRef = asn1NI.fromPublicKeyInfo(x509, 0, x509.length);
            Assertions.fail();
        }
        catch (UnexpectedPointerChangeException e)
        {
            Assertions.assertEquals("a returned pointer changed unexpectedly", e.getMessage());
        }
        finally
        {
            if (keyRef > 0)
            {
                specNI.dispose(keyRef);
            }
            operationsTestNI.resetFlags();
        }
    }
}
