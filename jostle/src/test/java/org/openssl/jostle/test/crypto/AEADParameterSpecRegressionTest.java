/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.AEADParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * D50/C44 regressions for {@link AEADParameterSpec}: BouncyCastle's own spec
 * type, and any other {@code IvParameterSpec} subclass, are refused typed by
 * every AEAD-capable cipher; this class's own spec is what they accept.
 */
public class AEADParameterSpecRegressionTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Every AEAD-capable transformation this cipher family registers. */
    private static final String[] XFORMS = {
            "AES/GCM/NoPadding", "AES/CCM/NoPadding", "AES/OCB/NoPadding", "ChaCha20-Poly1305"
    };

    private static final String R5_MESSAGE =
            "IvParameterSpec subclasses are not supported in AEAD modes; use "
                    + "org.openssl.jostle.jcajce.spec.AEADParameterSpec";

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static Key aesKey()
    {
        byte[] k = new byte[32];
        RANDOM.nextBytes(k);
        return new SecretKeySpec(k, "AES");
    }

    /** AES for GCM/CCM/OCB; ChaCha20 for ChaCha20-Poly1305. */
    private static Key keyFor(String xform)
    {
        if ("ChaCha20-Poly1305".equals(xform))
        {
            byte[] k = new byte[32];
            RANDOM.nextBytes(k);
            return new SecretKeySpec(k, "ChaCha20");
        }
        return aesKey();
    }

    private static byte[] nonce()
    {
        byte[] n = new byte[12];
        RANDOM.nextBytes(n);
        return n;
    }

    @Test
    public void bcSpecRefusedAtInitBothDirections() throws Exception
    {
        for (String xform : XFORMS)
        {
            org.bouncycastle.jcajce.spec.AEADParameterSpec bcSpec =
                    new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce(), 128);

            Cipher enc = Cipher.getInstance(xform, JSL);
            InvalidAlgorithmParameterException e1 = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> enc.init(Cipher.ENCRYPT_MODE, keyFor(xform), bcSpec, RANDOM),
                    xform + ": ENCRYPT_MODE must refuse a BC AEADParameterSpec");
            Assertions.assertEquals(R5_MESSAGE, e1.getMessage(), xform);

            Cipher dec = Cipher.getInstance(xform, JSL);
            InvalidAlgorithmParameterException e2 = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> dec.init(Cipher.DECRYPT_MODE, keyFor(xform), bcSpec, RANDOM),
                    xform + ": DECRYPT_MODE must refuse a BC AEADParameterSpec");
            Assertions.assertEquals(R5_MESSAGE, e2.getMessage(), xform);
        }
    }

    @Test
    public void anonymousIvParameterSpecSubclassRefused() throws Exception
    {
        for (String xform : XFORMS)
        {
            byte[] iv = nonce();
            IvParameterSpec anon = new IvParameterSpec(iv)
            {
            };
            Cipher c = Cipher.getInstance(xform, JSL);
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, keyFor(xform), anon, RANDOM),
                    xform + ": an IvParameterSpec subclass must be refused");
            Assertions.assertEquals(R5_MESSAGE, e.getMessage(), xform);
        }
    }

    @Test
    public void plainIvParameterSpecStillAcceptedAndRoundTrips() throws Exception
    {
        for (String xform : XFORMS)
        {
            byte[] iv = nonce();
            Key key = keyFor(xform);
            byte[] msg = new byte[1 + RANDOM.nextInt(64)];
            RANDOM.nextBytes(msg);

            Cipher enc = Cipher.getInstance(xform, JSL);
            enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv), RANDOM);
            byte[] ct = enc.doFinal(msg);

            Cipher dec = Cipher.getInstance(xform, JSL);
            dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv), RANDOM);
            Assertions.assertArrayEquals(msg, dec.doFinal(ct), xform + ": plain IvParameterSpec round trip failed");
        }
    }

    @Test
    public void ourSpecWithAadRoundTripsAndTagDiffersFromNoAad() throws Exception
    {
        for (String xform : XFORMS)
        {
            byte[] iv = nonce();
            Key key = keyFor(xform);
            byte[] aad = new byte[1 + RANDOM.nextInt(32)];
            RANDOM.nextBytes(aad);
            byte[] msg = new byte[1 + RANDOM.nextInt(64)];
            RANDOM.nextBytes(msg);

            Cipher encWithAad = Cipher.getInstance(xform, JSL);
            encWithAad.init(Cipher.ENCRYPT_MODE, key, new AEADParameterSpec(iv, 128, aad), RANDOM);
            byte[] ctWithAad = encWithAad.doFinal(msg);

            Cipher decWithAad = Cipher.getInstance(xform, JSL);
            decWithAad.init(Cipher.DECRYPT_MODE, key, new AEADParameterSpec(iv, 128, aad), RANDOM);
            Assertions.assertArrayEquals(msg, decWithAad.doFinal(ctWithAad), xform + ": AAD round trip failed");

            Cipher encNoAad = Cipher.getInstance(xform, JSL);
            encNoAad.init(Cipher.ENCRYPT_MODE, key, new AEADParameterSpec(iv, 128), RANDOM);
            byte[] ctNoAad = encNoAad.doFinal(msg);

            Assertions.assertFalse(Arrays.areEqual(ctWithAad, ctNoAad),
                    xform + ": AAD must change the tag, or it was not honoured");
        }
    }

    @Test
    public void ourSpecOnNonAeadModeRefused() throws Exception
    {
        Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding", JSL);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cbc.init(Cipher.ENCRYPT_MODE, aesKey(), new AEADParameterSpec(new byte[16], 128), RANDOM));
        Assertions.assertTrue(
                e.getMessage().startsWith("AEAD parameter spec cannot be used with non-AEAD mode"),
                "unexpected message: " + e.getMessage());
    }

    @Test
    public void constructorRefusesOutOfRangeOrMisalignedTag()
    {
        byte[] iv = nonce();
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AEADParameterSpec(iv, 24),
                "24 is below the 32-bit floor");
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AEADParameterSpec(iv, 136),
                "136 is above the 128-bit ceiling");
        Assertions.assertThrows(IllegalArgumentException.class, () -> new AEADParameterSpec(iv, 100),
                "100 is not a multiple of 8");
    }
}
