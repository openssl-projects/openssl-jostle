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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Regression guard for DESEDE_AUTO_IV_GAP.md: the per-algorithm
 * {@code BlockCipherSpi} subclasses (DESede, ARIA, SM4, Camellia) overrode the
 * {@code AlgorithmParameters}-typed {@code engineInit} and dereferenced
 * {@code params} without a null check — so the JCE auto-IV pattern
 * {@code Cipher.init(ENCRYPT_MODE, key, (AlgorithmParameters) null, random)}
 * (exactly what BC's {@code JceCMSContentEncryptorBuilder} calls) threw
 * {@code NullPointerException} instead of auto-generating an IV.
 */
public class BlockCipherAutoIvParamsTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    // transformation, key algorithm, key bytes, block (IV) bytes
    private static final Object[][] CIPHERS = {
            {"DESede/CBC/PKCS5Padding", "DESede", 24, 8},
            {"ARIA/CBC/PKCS5Padding", "ARIA", 16, 16},
            {"SM4/CBC/PKCS5Padding", "SM4", 16, 16},
            {"Camellia/CBC/PKCS5Padding", "Camellia", 16, 16},
    };

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @Test
    public void nullAlgorithmParametersInit_autoGeneratesIv() throws Exception
    {
        SecureRandom random = seededRandom("nullAlgorithmParametersInit_autoGeneratesIv");

        for (Object[] row : CIPHERS)
        {
            String transformation = (String) row[0];
            String keyAlg = (String) row[1];
            byte[] keyBytes = new byte[(Integer) row[2]];
            int ivLen = (Integer) row[3];
            random.nextBytes(keyBytes);
            SecretKeySpec key = new SecretKeySpec(keyBytes, keyAlg);

            byte[] msg = new byte[1 + random.nextInt(64)];
            random.nextBytes(msg);

            Cipher enc = Cipher.getInstance(transformation, JostleProvider.PROVIDER_NAME);
            // The CMS content-encryptor entry point: AlgorithmParameters-typed
            // init with null params — previously NPE'd in the subclasses.
            enc.init(Cipher.ENCRYPT_MODE, key, (AlgorithmParameters) null, random);

            byte[] iv = enc.getIV();
            Assertions.assertNotNull(iv, transformation + ": must expose an auto-generated IV");
            Assertions.assertEquals(ivLen, iv.length, transformation + ": IV must be one block");

            byte[] ct = enc.doFinal(msg);

            Cipher dec = Cipher.getInstance(transformation, JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            Assertions.assertArrayEquals(msg, dec.doFinal(ct),
                    transformation + ": auto-IV ciphertext did not round-trip");

            // Negative path: a tampered ciphertext must not round-trip
            // (PKCS5 may also reject at doFinal — both prove the transform).
            byte[] tampered = Arrays.clone(ct);
            tampered[0] ^= (byte) 0x01;
            Cipher dec2 = Cipher.getInstance(transformation, JostleProvider.PROVIDER_NAME);
            dec2.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            try
            {
                Assertions.assertFalse(Arrays.areEqual(msg, dec2.doFinal(tampered)),
                        transformation + ": tampered ciphertext must not round-trip");
            }
            catch (javax.crypto.BadPaddingException e)
            {
                // also acceptable — corruption cascaded into the padding
            }
        }
    }
}
