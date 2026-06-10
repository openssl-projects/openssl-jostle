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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Cold-cache regression guard for the CBC auto-IV gap
 * (see {@code docs/CBC_AUTO_IV_COLD_CACHE_GAP.md}).
 * <p>
 * {@code Cipher.init(ENCRYPT_MODE, key, random)} with no {@code IvParameterSpec}
 * must auto-generate an IV sized from the cipher's block size. The block size is
 * an algorithm invariant and must be available <em>before</em> the native
 * {@code EVP_CIPHER_CTX} is initialised — otherwise the first AES-CBC encrypt in
 * a JVM throws {@code IllegalStateException: not initialized} (the symptom that
 * blocked CMS AES-CBC content encryption).
 * <p>
 * This test lives in its own class so the project's {@code forkEvery = 1} runs it
 * in a fresh JVM, making the auto-IV {@code init} the very first cipher operation
 * — the genuinely cold path. The single test method keeps it cold: a second
 * method would warm the JVM and mask a regression. Do not add more methods here.
 */
public class CbcAutoIvColdCacheTest
{
    private static final String CBC = "AES/CBC/NoPadding";

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void cbcAutoIvWorksAsFirstCipherOperation() throws Exception
    {
        long seed = new SecureRandom().nextLong();
        System.out.println("cbcAutoIvWorksAsFirstCipherOperation seed=" + seed);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(seed);

        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        byte[] msg = new byte[48]; // exact block multiple for NoPadding
        random.nextBytes(msg);

        // The very first cipher operation in this (forked) JVM: auto-IV init.
        // On a cold cache this threw IllegalStateException: not initialized.
        Cipher enc = Cipher.getInstance(CBC, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, random); // no IvParameterSpec supplied

        byte[] iv = enc.getIV();
        Assertions.assertNotNull(iv, "CBC must expose an auto-generated IV");
        Assertions.assertEquals(16, iv.length, "CBC IV must be one AES block");

        AlgorithmParameters params = enc.getParameters();
        Assertions.assertNotNull(params, "CBC must expose auto-generated AlgorithmParameters");
        Assertions.assertArrayEquals(iv, params.getParameterSpec(IvParameterSpec.class).getIV(),
                "getIV() and getParameters() must agree");

        byte[] ct = enc.doFinal(msg);

        // Round-trip via BouncyCastle using the IV JSL generated.
        Cipher bcDec = Cipher.getInstance(CBC, BouncyCastleProvider.PROVIDER_NAME);
        bcDec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        Assertions.assertArrayEquals(msg, bcDec.doFinal(ct),
                "auto-IV ciphertext did not round-trip through BouncyCastle");

        // Negative path, kept inside this single method so the cold-path
        // property above is not diluted by a second test warming the JVM:
        // a tampered ciphertext must not decrypt back to the plaintext
        // (NoPadding CBC decrypts without error but diverges).
        byte[] tampered = ct.clone();
        tampered[0] ^= (byte) 0x01;
        Cipher bcDec2 = Cipher.getInstance(CBC, BouncyCastleProvider.PROVIDER_NAME);
        bcDec2.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        Assertions.assertFalse(org.openssl.jostle.util.Arrays.areEqual(msg, bcDec2.doFinal(tampered)),
                "tampered ciphertext must not round-trip");
    }
}
