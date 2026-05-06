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
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

/**
 * NI-layer input-validation tests for the RSA-PKCS#1 v1.5 cipher.
 */
public class RSAPKCS1CipherLimitTest
{
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};

    RSAServiceNI rsaServiceNI = TestNISelector.getRSANi();
    RSAPKCS1CipherNI cipherNI = TestNISelector.getRSAPKCS1CipherNi();
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
    public void RSAPKCS1CipherNI_init_nullKey() throws Exception
    {
        long ref = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            cipherNI.init(ref, 0, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
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
    public void RSAPKCS1CipherNI_init_nullRand() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, null);
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
    public void RSAPKCS1CipherNI_init_nullRand_decrypt() throws Exception
    {
        // Decrypt also requires a RAND source (RSA blinding).
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, null);
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
    public void RSAPKCS1CipherNI_doFinal_notInitialized() throws Exception
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
    public void RSAPKCS1CipherNI_doFinal_nullInput() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
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
    public void RSAPKCS1CipherNI_doFinal_offsetNegative() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
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
    public void RSAPKCS1CipherNI_doFinal_outOfRange() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
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

    @Test
    public void RSAPKCS1CipherNI_doFinal_outputTooSmall() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
            cipherNI.doFinal(ref, new byte[16], 0, 16, new byte[100], 0, TestUtil.RNDSrc);
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

    /**
     * Mirror of the OAEP outOff regression — confirms the FFI doFinal
     * preserves bytes preceding {@code outOff}.
     */
    @Test
    public void RSAPKCS1CipherNI_doFinal_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        long ref = 0;
        long keyRef = 0;
        try
        {
            ref = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(ref, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);

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
            Assertions.assertNotEquals((byte) 0xAA, big[prefix]);
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void RSAPKCS1CipherNI_roundTrip() throws Exception
    {
        long encRef = 0;
        long decRef = 0;
        long keyRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            decRef = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);

            byte[] msg = {1, 2, 3, 4};
            cipherNI.init(encRef, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);
            int needed = cipherNI.doFinal(encRef, msg, 0, msg.length, null, 0, TestUtil.RNDSrc);
            byte[] ct = new byte[needed];
            int written = cipherNI.doFinal(encRef, msg, 0, msg.length, ct, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(needed, written);

            cipherNI.init(decRef, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);
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
