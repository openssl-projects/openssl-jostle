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

package org.openssl.jostle.test.rsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.rsa.RSAOAEPCipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

/**
 * NI-layer input-validation tests for the RSA-OAEP cipher. Mirrors the
 * structure of {@link RSALimitTest} but targets the
 * {@link RSAOAEPCipherNI} surface.
 */
public class RSAOAEPCipherLimitTest
{
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};

    RSAServiceNI rsaServiceNI = TestNISelector.getRSANi();
    RSAOAEPCipherNI cipherNI = TestNISelector.getRSAOAEPCipherNi();
    SpecNI specNI = TestNISelector.getSpecNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    @Test
    public void RSAOAEPCipherNI_init_nullKey() throws Exception
    {
        long ref = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            Assertions.assertTrue(ref > 0);
            cipherNI.init(ref, 0, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
        }
    }

    @Test
    public void RSAOAEPCipherNI_init_nullDigest() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    null, null, null, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("name is null", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipherNI_init_invalidOpMode() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, /* invalid */ 99,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalStateException ignored)
        {
            // Op-mode rejection surfaces via the default-method path
            // and the base error handler, which throws an
            // IllegalStateException for unknown errors. Either form is
            // acceptable for this test.
        }
        catch (IllegalArgumentException ignored)
        {
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipherNI_init_nullRand() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipherNI_init_nullRand_decrypt() throws Exception
    {
        // Decrypt also requires a RandSource (RSA blinding consumes entropy).
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_DECRYPT,
                    "SHA-256", null, null, null);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipherNI_doFinal_notInitialized() throws Exception
    {
        long ref = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            cipherNI.doFinal(ref, new byte[1], 0, 1, null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
        }
    }

    @Test
    public void RSAOAEPCipherNI_doFinal_nullInput() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            cipherNI.doFinal(ref, null, 0, 0, null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipherNI_doFinal_offsetNegative() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            cipherNI.doFinal(ref, new byte[16], -1, 16, null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipherNI_doFinal_outputTooSmall() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            // Encrypt outputs 256 bytes for a 2048-bit modulus; supply 100.
            cipherNI.doFinal(ref, new byte[16], 0, 16,
                    new byte[100], 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipherNI_doFinal_outOfRange() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);
            cipherNI.doFinal(ref, new byte[10], 1, 10, null, 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    /**
     * Regression test for an FFI-only bug where {@code ni_doFinal}'s
     * post-call output copy-back was
     * {@code outSeg.asByteBuffer().get(0, output, 0, output.length)},
     * which clobbered caller-provided bytes preceding {@code outOff}
     * with zeros. Confirms the ciphertext lands at {@code outOff} and
     * the leading bytes are untouched.
     */
    @Test
    public void RSAOAEPCipherNI_doFinal_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", null, null, TestUtil.RNDSrc);

            byte[] msg = {1, 2, 3, 4};
            int needed = cipherNI.doFinal(ref, msg, 0, msg.length, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(256, needed);

            int prefix = 5;
            byte[] big = new byte[needed + prefix];
            java.util.Arrays.fill(big, 0, prefix, (byte) 0xAA);

            int written = cipherNI.doFinal(ref, msg, 0, msg.length,
                    big, prefix, TestUtil.RNDSrc);
            Assertions.assertEquals(needed, written);

            for (int i = 0; i < prefix; i++)
            {
                Assertions.assertEquals((byte) 0xAA, big[i],
                        "prefix byte " + i + " was clobbered");
            }
            Assertions.assertNotEquals((byte) 0xAA, big[prefix],
                    "ciphertext should start at offset " + prefix);
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAOAEPCipherNI_roundTrip_withLabel() throws Exception
    {
        // Happy-path sanity check at the NI layer to exercise the
        // label path.
        long encRef = 0;
        long decRef = 0;
        long keyRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            decRef = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            byte[] label = "ni-direct-label".getBytes();
            byte[] msg = new byte[]{1, 2, 3, 4};

            cipherNI.init(encRef, keyRef, RSAOAEPCipherNI.OP_ENCRYPT,
                    "SHA-256", "SHA-256", label, TestUtil.RNDSrc);
            int needed = cipherNI.doFinal(encRef, msg, 0, msg.length, null, 0, TestUtil.RNDSrc);
            byte[] ct = new byte[needed];
            int written = cipherNI.doFinal(encRef, msg, 0, msg.length, ct, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(needed, written);

            cipherNI.init(decRef, keyRef, RSAOAEPCipherNI.OP_DECRYPT,
                    "SHA-256", "SHA-256", label, TestUtil.RNDSrc);
            int ptLen = cipherNI.doFinal(decRef, ct, 0, ct.length, null, 0, TestUtil.RNDSrc);
            byte[] pt = new byte[ptLen];
            int ptWritten = cipherNI.doFinal(decRef, ct, 0, ct.length, pt, 0, TestUtil.RNDSrc);
            byte[] trimmed = new byte[ptWritten];
            System.arraycopy(pt, 0, trimmed, 0, ptWritten);
            Assertions.assertArrayEquals(msg, trimmed);
        }
        finally
        {
            cipherNI.disposeCipher(encRef);
            cipherNI.disposeCipher(decRef);
            specNI.dispose(keyRef);
        }
    }
}
