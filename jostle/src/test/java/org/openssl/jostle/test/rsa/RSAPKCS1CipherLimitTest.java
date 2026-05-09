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

import java.security.SecureRandom;
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
        long encRef = 0;
        long decRef = 0;
        long keyRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            decRef = cipherNI.allocateCipher();
            keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, TestUtil.RNDSrc);
            cipherNI.init(encRef, keyRef, RSAPKCS1CipherNI.OP_ENCRYPT, TestUtil.RNDSrc);

            byte[] msg = {1, 2, 3, 4};
            int needed = cipherNI.doFinal(encRef, msg, 0, msg.length, null, 0, TestUtil.RNDSrc);
            Assertions.assertEquals(256, needed);

            // Fill the WHOLE buffer with random bytes; save aside a copy
            // of the prefix so the post-encryption comparison is against
            // an arbitrary value rather than a fixed sentinel.
            int prefix = 5;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            int written = cipherNI.doFinal(encRef, msg, 0, msg.length,
                    big, prefix, TestUtil.RNDSrc);
            Assertions.assertEquals(needed, written);

            // (1) Bridge contract: bytes preceding outOff must be untouched.
            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                    "prefix bytes were modified by the encryption call");

            // (2) Positive functional check: ciphertext at
            //     big[prefix..prefix+needed] decrypts to the original
            //     plaintext.
            byte[] ct = new byte[needed];
            System.arraycopy(big, prefix, ct, 0, needed);

            cipherNI.init(decRef, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);
            int ptLen = cipherNI.doFinal(decRef, ct, 0, ct.length,
                    null, 0, TestUtil.RNDSrc);
            byte[] pt = new byte[ptLen];
            int ptWritten = cipherNI.doFinal(decRef, ct, 0, ct.length,
                    pt, 0, TestUtil.RNDSrc);
            byte[] trimmed = new byte[ptWritten];
            System.arraycopy(pt, 0, trimmed, 0, ptWritten);
            Assertions.assertArrayEquals(msg, trimmed,
                    "ciphertext at offset " + prefix + " did not decrypt to "
                            + "the original plaintext");

            // (3) Negative functional check: a 256-byte window starting
            //     ONE BYTE EARLIER (i.e. one byte INTO the random prefix)
            //     must NOT decrypt to the original plaintext. With
            //     OpenSSL's implicit-rejection enabled, decryption of a
            //     malformed ciphertext returns deterministic synthetic
            //     plaintext rather than throwing — which can never equal
            //     the original 4-byte message except by negligible chance.
            //     If the SPI had written at outOff-1 the shifted window
            //     would actually be the real ciphertext and would decrypt
            //     to msg.
            byte[] shifted = new byte[needed];
            System.arraycopy(big, prefix - 1, shifted, 0, needed);

            boolean shiftedDecryptedToOriginal = false;
            try
            {
                cipherNI.init(decRef, keyRef, RSAPKCS1CipherNI.OP_DECRYPT, TestUtil.RNDSrc);
                int sLen = cipherNI.doFinal(decRef, shifted, 0, shifted.length,
                        null, 0, TestUtil.RNDSrc);
                byte[] sPt = new byte[sLen];
                int sWritten = cipherNI.doFinal(decRef, shifted, 0, shifted.length,
                        sPt, 0, TestUtil.RNDSrc);
                byte[] sTrimmed = new byte[sWritten];
                System.arraycopy(sPt, 0, sTrimmed, 0, sWritten);
                shiftedDecryptedToOriginal = java.util.Arrays.equals(msg, sTrimmed);
            }
            catch (Exception expected)
            {
                // Some shifted windows fail structurally (e.g. ciphertext > n)
                // before the implicit-rejection path runs; that's also a
                // correct outcome.
            }
            Assertions.assertFalse(shiftedDecryptedToOriginal,
                    "ciphertext window shifted by 1 byte INTO the prefix "
                            + "decrypted to the original plaintext — encryption "
                            + "wrote at outOff-1 instead of at outOff=" + prefix);
        }
        finally
        {
            cipherNI.disposeCipher(encRef);
            cipherNI.disposeCipher(decRef);
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
