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

package org.openssl.jostle.test.kdf;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.security.Security;

public class ScryptTest
{
    /**
     * Class-level seeding random — used to derive each test's local
     * SHA1PRNG seed. Per CLAUDE.md: "cache one SecureRandom per test
     * class, not per @Test method."
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Per-test seeded random. The seed is logged on every call so a
     * flaky failure can be reproduced by re-running with the same
     * seed (per CLAUDE.md).
     */
    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

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

    private static byte[] random(int length, SecureRandom sr)
    {
        byte[] bytes = new byte[length];
        sr.nextBytes(bytes);
        return bytes;
    }


    @Test
    public void testBCAgreement() throws Exception
    {
        // "SCRYPT"


        //
        // Parameter values in this test were just chosen without regard to
        // real world viability, please do not cut and paste this into anything important.
        //

        SecureRandom sr = seededRandom("testBCAgreement");
        char[] passphrase = new String(random(8, sr)).toCharArray();
        byte[] salt = random(16, sr);
        SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("SCRYPT", JostleProvider.PROVIDER_NAME);
        SecretKeyFactory kfBc = SecretKeyFactory.getInstance("SCRYPT", BouncyCastleProvider.PROVIDER_NAME);

        SecretKey joKey = kfJostle.generateSecret(new ScryptKeySpec(passphrase, salt, 2, 1, 1, 512));
        SecretKey bcKey = kfBc.generateSecret(new org.bouncycastle.jcajce.spec.ScryptKeySpec(passphrase, salt, 2, 1, 1, 512));

        Assertions.assertArrayEquals(joKey.getEncoded(), bcKey.getEncoded(), "SCRYPT");

    }


    /**
     * Negative path per CLAUDE.md "Tests must exercise the negative
     * path". The BC-agreement test above proves Jostle produces the
     * same output as BC for one input — but doesn't prove the output
     * actually depends on each input. A KDF that ignored its salt (or
     * password) would silently agree with BC if BC had the same bug,
     * or would produce the same output for two distinct salts. This
     * test confirms each input actually influences the derived key.
     */
    @Test
    public void testInputsActuallyInfluenceDerivedKey() throws Exception
    {
        SecureRandom sr = seededRandom("testInputsActuallyInfluenceDerivedKey");
        SecretKeyFactory kf = SecretKeyFactory.getInstance("SCRYPT", JostleProvider.PROVIDER_NAME);

        char[] pwd1 = new String(random(8, sr)).toCharArray();
        char[] pwd2 = new String(random(8, sr)).toCharArray();
        byte[] salt1 = random(16, sr);
        byte[] salt2 = random(16, sr);

        // Cheap scrypt params chosen for test speed, not real-world use.
        int n = 2, r = 1, p = 1, keyLen = 256;

        byte[] base = kf.generateSecret(new ScryptKeySpec(pwd1, salt1, n, r, p, keyLen)).getEncoded();

        byte[] diffPwd = kf.generateSecret(new ScryptKeySpec(pwd2, salt1, n, r, p, keyLen)).getEncoded();
        Assertions.assertFalse(Arrays.areEqual(base, diffPwd),
                "different password must produce a different derived key");

        byte[] diffSalt = kf.generateSecret(new ScryptKeySpec(pwd1, salt2, n, r, p, keyLen)).getEncoded();
        Assertions.assertFalse(Arrays.areEqual(base, diffSalt),
                "different salt must produce a different derived key");

        // Higher cost parameter → different key (scrypt's N parameter
        // changes the iteration count of the inner mixing function).
        byte[] diffN = kf.generateSecret(new ScryptKeySpec(pwd1, salt1, 4, r, p, keyLen)).getEncoded();
        Assertions.assertFalse(Arrays.areEqual(base, diffN),
                "different cost parameter N must produce a different derived key");

        // Same inputs → same key (scrypt is deterministic).
        byte[] repeat = kf.generateSecret(new ScryptKeySpec(pwd1, salt1, n, r, p, keyLen)).getEncoded();
        Assertions.assertArrayEquals(base, repeat,
                "same inputs must produce the same derived key (scrypt is deterministic)");
    }



}
