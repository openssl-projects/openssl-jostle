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

package org.openssl.jostle.test.md;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

public class MDLimitTest
{

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    MDServiceNI mdNI = TestNISelector.getMDNI();



    @Test
    public void allocateDigest_testDigestNameIsNull() throws Exception {
        try
        {
            mdNI.allocateDigest(null, 0);
            Assertions.fail();
        } catch(NullPointerException e) {
            Assertions.assertEquals("name is null", e.getMessage());
        }
    }

    @Test
    public void allocateDigest_testInvalidDigestName() throws Exception
    {
        try
        {
            mdNI.allocateDigest("SHA-255", 0);
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("name not found", e.getMessage());
        }
    }

// updateByte does not
@Test
public void updateBytes_inputNull() throws Exception {
    long ref = mdNI.allocateDigest("SHA256", 0);

    try {
        mdNI.engineUpdate(ref,null,0,0);
        Assertions.fail("Expected NullPointerException");
    } catch (NullPointerException e) {
        Assertions.assertEquals("input is null", e.getMessage());
    } finally {
        if (ref >0) {
            mdNI.dispose(ref);
        }
    }
}

    @Test
    public void updateBytes_inputOffsetNegative() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[0],-1,0);
            Assertions.fail("Expected NullPointerException");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void updateBytes_inputLenNegative() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[0],0,-1);
            Assertions.fail("");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input len is negative", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void updateBytes_range_1() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[10],0,11);
            Assertions.fail("Expected NullPointerException");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void updateBytes_range_2() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[10],1,10);
            Assertions.fail("Expected NullPointerException");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void updateBytes_range_3() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[10],11,21);
            Assertions.fail("Expected NullPointerException");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_outputOffsetNegative() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[0],-1,0);
            Assertions.fail("fail");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_outputLenNegative() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[0],0,-1);
            Assertions.fail("");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output len negative", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_outputTooSmall() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[31],0,31);
            Assertions.fail("");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_range_1() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[31],0,32);
            Assertions.fail("failed");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_range_2() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[32],1,32);
            Assertions.fail("failed");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_range_3() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[32],32,64);
            Assertions.fail("failed");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output offset + length is out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }


    //
    // XOF length / algorithm-kind mismatches are pure input validation in
    //
    @Test
    public void allocateDigest_xofLenForNonXofAlgorithm() throws Exception
    {
        try
        {
            mdNI.allocateDigest("SHA256", 32);
            Assertions.fail("Expected operation to fail but did not");
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("xof length inconsistent with algorithm", e.getMessage());
        }
    }

    @Test
    public void allocateDigest_xofAlgorithmWithoutXofLen() throws Exception
    {
        try
        {
            mdNI.allocateDigest("SHAKE-128", 0);
            Assertions.fail("Expected operation to fail but did not");
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("xof length inconsistent with algorithm", e.getMessage());
        }
    }


    //
    // getDigestOutputLen happy path — pins the NI-level contract for both
    // fixed-size and XOF algorithms.
    //
    @Test
    public void getDigestOutputLen_sha256() throws Exception
    {
        long ref = mdNI.allocateDigest("SHA256", 0);
        try
        {
            Assertions.assertEquals(32, mdNI.getDigestOutputLen(ref));
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void getDigestOutputLen_shake128_xof() throws Exception
    {
        long ref = mdNI.allocateDigest("SHAKE-128", 64);
        try
        {
            Assertions.assertEquals(64, mdNI.getDigestOutputLen(ref));
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void getDigestOutputLen_sha512_224() throws Exception
    {
        // Truncated-output variant: 28 bytes, exercises that the size routing
        // doesn't trip on non-power-of-2 lengths.
        long ref = mdNI.allocateDigest("SHA2-512/224", 0);
        try
        {
            Assertions.assertEquals(28, mdNI.getDigestOutputLen(ref));
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void getDigestOutputLen_sha3_384() throws Exception
    {
        long ref = mdNI.allocateDigest("SHA3-384", 0);
        try
        {
            Assertions.assertEquals(48, mdNI.getDigestOutputLen(ref));
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
        }
    }


    //
    // digest(ref, null, ...) is a length-query path that must agree with
    // getDigestOutputLen — locks the contract added when both paths were
    // unified.
    //
    @Test
    public void digest_lengthQuery_matchesGetDigestOutputLen() throws Exception
    {
        long ref = mdNI.allocateDigest("SHA2-512", 0);
        try
        {
            int viaGetLen = mdNI.getDigestOutputLen(ref);
            int viaDigestNullOut = mdNI.digest(ref, null, 0, 0);
            Assertions.assertEquals(64, viaGetLen);
            Assertions.assertEquals(viaGetLen, viaDigestNullOut);
        }
        finally
        {
            if (ref > 0)
            {
                mdNI.dispose(ref);
            }
        }
    }


    //
    // ni_reset / MD_Reset gracefully no-op on a null ref to tolerate spurious
    // resets emitted by the JCE provider lifecycle. Pin that contract.
    //
    @Test
    public void reset_nullRef_isNoOp() throws Exception
    {
        // No exception should escape; the default reset(long) routes a null
        // ref through ni_reset which returns JO_SUCCESS.
        mdNI.reset(0);
    }



    //
    // NOTE: when JCA-level XOF support is added (e.g. provider exposes a way
    // to set xof_len via algorithm parameters), these tests should move to
    // MDTest and drive through MessageDigest instead of the NI surface.
    //
    @Test
    public void shake128_variableXofLen_matchesBC() throws Exception
    {
        assertShakeMatchesBC(128, "SHAKE-128");
    }

    @Test
    public void shake256_variableXofLen_matchesBC() throws Exception
    {
        assertShakeMatchesBC(256, "SHAKE-256");
    }

    private void assertShakeMatchesBC(int bcBitStrength, String joName) throws Exception
    {
        // Deterministic non-trivial input.
        byte[] input = new byte[256];
        for (int i = 0; i < input.length; i++)
        {
            input[i] = (byte) (i ^ 0x5A);
        }

        for (int len : new int[]{1, 16, 32, 100, 1024})
        {
            // BC reference output of `len` bytes
            SHAKEDigest bc = new SHAKEDigest(bcBitStrength);
            bc.update(input, 0, input.length);
            byte[] bcOut = new byte[len];
            bc.doFinal(bcOut, 0, len);

            // Jostle NI with explicit xof_len
            long ref = mdNI.allocateDigest(joName, len);
            try
            {
                Assertions.assertEquals(len, mdNI.getDigestOutputLen(ref),
                        "configured xof length not honoured (alg " + joName + ", len " + len + ")");

                mdNI.engineUpdate(ref, input, 0, input.length);
                byte[] joOut = new byte[len];
                int written = mdNI.digest(ref, joOut, 0, len);
                Assertions.assertEquals(len, written, "bytes written mismatch (len " + len + ")");

                Assertions.assertArrayEquals(bcOut, joOut,
                        joName + " at xof_len=" + len + " disagrees with BC");
            }
            finally
            {
                if (ref > 0)
                {
                    mdNI.dispose(ref);
                }
            }
        }
    }


}
