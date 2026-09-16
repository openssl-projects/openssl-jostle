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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
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
 * D50/C44 {@link AEADParameterSpecRegressionTest} FIPS twin: JSLFIPS, GCM and
 * CCM. Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSAEADParameterSpecRegressionTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[] XFORMS = {"AES/GCM/NoPadding", "AES/CCM/NoPadding"};

    private static final String R5_MESSAGE =
            "IvParameterSpec subclasses are not supported in AEAD modes; use "
                    + "org.openssl.jostle.jcajce.spec.AEADParameterSpec";

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
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

            Cipher enc = Cipher.getInstance(xform, FIPS);
            InvalidAlgorithmParameterException e1 = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> enc.init(Cipher.ENCRYPT_MODE, aesKey(), bcSpec, RANDOM),
                    xform + ": ENCRYPT_MODE must refuse a BC AEADParameterSpec");
            Assertions.assertEquals(R5_MESSAGE, e1.getMessage(), xform);

            Cipher dec = Cipher.getInstance(xform, FIPS);
            InvalidAlgorithmParameterException e2 = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> dec.init(Cipher.DECRYPT_MODE, aesKey(), bcSpec, RANDOM),
                    xform + ": DECRYPT_MODE must refuse a BC AEADParameterSpec");
            Assertions.assertEquals(R5_MESSAGE, e2.getMessage(), xform);
        }
    }

    @Test
    public void anonymousIvParameterSpecSubclassRefused() throws Exception
    {
        for (String xform : XFORMS)
        {
            IvParameterSpec anon = new IvParameterSpec(nonce())
            {
            };
            Cipher c = Cipher.getInstance(xform, FIPS);
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, aesKey(), anon, RANDOM),
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
            Key key = aesKey();
            byte[] msg = new byte[1 + RANDOM.nextInt(64)];
            RANDOM.nextBytes(msg);

            Cipher enc = Cipher.getInstance(xform, FIPS);
            enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv), RANDOM);
            byte[] ct = enc.doFinal(msg);

            Cipher dec = Cipher.getInstance(xform, FIPS);
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
            Key key = aesKey();
            byte[] aad = new byte[1 + RANDOM.nextInt(32)];
            RANDOM.nextBytes(aad);
            byte[] msg = new byte[1 + RANDOM.nextInt(64)];
            RANDOM.nextBytes(msg);

            Cipher encWithAad = Cipher.getInstance(xform, FIPS);
            encWithAad.init(Cipher.ENCRYPT_MODE, key, new AEADParameterSpec(iv, 128, aad), RANDOM);
            byte[] ctWithAad = encWithAad.doFinal(msg);

            Cipher decWithAad = Cipher.getInstance(xform, FIPS);
            decWithAad.init(Cipher.DECRYPT_MODE, key, new AEADParameterSpec(iv, 128, aad), RANDOM);
            Assertions.assertArrayEquals(msg, decWithAad.doFinal(ctWithAad), xform + ": AAD round trip failed");

            Cipher encNoAad = Cipher.getInstance(xform, FIPS);
            encNoAad.init(Cipher.ENCRYPT_MODE, key, new AEADParameterSpec(iv, 128), RANDOM);
            byte[] ctNoAad = encNoAad.doFinal(msg);

            Assertions.assertFalse(Arrays.areEqual(ctWithAad, ctNoAad),
                    xform + ": AAD must change the tag, or it was not honoured");
        }
    }

    @Test
    public void ourSpecOnNonAeadModeRefused() throws Exception
    {
        Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding", FIPS);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cbc.init(Cipher.ENCRYPT_MODE, aesKey(), new AEADParameterSpec(new byte[16], 128), RANDOM));
        Assertions.assertTrue(
                e.getMessage().startsWith("AEAD parameter spec cannot be used with non-AEAD mode"),
                "unexpected message: " + e.getMessage());
    }
}
