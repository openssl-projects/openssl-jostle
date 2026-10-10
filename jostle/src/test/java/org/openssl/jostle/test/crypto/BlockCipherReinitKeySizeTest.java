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

package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * One Cipher instance takes any legal key size on each init: the native context is bound to the cipher it was
 * created for, so a key of another size must get a new one.
 */
public class BlockCipherReinitKeySizeTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    /** Drives one instance through the key sizes in order, both directions, each against BouncyCastle. */
    private static void reinitAcross(String alg, int[] keySizes) throws Exception
    {
        String xform = alg + "/CBC/PKCS5Padding";
        Cipher enc = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        Cipher dec = Cipher.getInstance(xform, JostleProvider.PROVIDER_NAME);
        for (int size : keySizes)
        {
            SecretKeySpec key = new SecretKeySpec(random(size), alg);
            IvParameterSpec iv = new IvParameterSpec(random(16));
            byte[] msg = random(RANDOM.nextInt(80));

            enc.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ours = enc.doFinal(msg);
            Cipher bc = Cipher.getInstance(xform, "BC");
            bc.init(Cipher.ENCRYPT_MODE, key, iv);
            Assertions.assertTrue(Arrays.areEqual(bc.doFinal(msg), ours), alg + " " + size + "-byte key ciphertext");

            dec.init(Cipher.DECRYPT_MODE, key, iv);
            Assertions.assertTrue(Arrays.areEqual(msg, dec.doFinal(ours)), alg + " " + size + "-byte key round trip");
        }
    }

    @Test
    public void aesTakesEveryKeySizeOnOneInstance() throws Exception
    {
        reinitAcross("AES", new int[]{16, 32, 24});
        reinitAcross("AES", new int[]{24, 32, 16});
    }

    @Test
    public void ariaTakesEveryKeySizeOnOneInstance() throws Exception
    {
        reinitAcross("ARIA", new int[]{16, 32, 24});
        reinitAcross("ARIA", new int[]{24, 32, 16});
    }

    @Test
    public void camelliaTakesEveryKeySizeOnOneInstance() throws Exception
    {
        reinitAcross("CAMELLIA", new int[]{16, 32, 24});
        reinitAcross("CAMELLIA", new int[]{24, 32, 16});
    }

    /**
     * XTS has no BouncyCastle JCE name; a fresh instance per key is the comparator, and AESXTSTest holds the fresh
     * instance to the IEEE 1619 vectors.
     */
    @Test
    public void xtsTakesBothKeySizesOnOneInstance() throws Exception
    {
        for (int[] order : new int[][]{{32, 64}, {64, 32}})
        {
            Cipher reused = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
            for (int size : order)
            {
                SecretKeySpec key = new SecretKeySpec(random(size), "AES");
                IvParameterSpec tweak = new IvParameterSpec(random(16));
                byte[] unit = random(16 + RANDOM.nextInt(64));

                reused.init(Cipher.ENCRYPT_MODE, key, tweak);
                byte[] ours = reused.doFinal(unit);
                Cipher fresh = Cipher.getInstance("AES/XTS/NoPadding", JostleProvider.PROVIDER_NAME);
                fresh.init(Cipher.ENCRYPT_MODE, key, tweak);
                Assertions.assertTrue(Arrays.areEqual(fresh.doFinal(unit), ours), "XTS " + size + "-byte key");
                Assertions.assertFalse(Arrays.areEqual(unit, ours), "XTS " + size + "-byte key transforms");
            }
        }
    }
}
