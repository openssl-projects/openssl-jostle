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
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Strings;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.Security;

public class PBKdf2Test
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
        SecureRandom sr = seededRandom("testBCAgreement");
        // "PBKDF2"
        for (String prf : new String[]{
                "PBKDF2",
                "PBKDF2WITHHMACSHA1",
                "PBKDF2WITHHMACSHA224",
                "PBKDF2WITHHMACSHA256",
                "PBKDF2WITHHMACSHA384",
                "PBKDF2WITHHMACSHA512",
//                "PBKDF2WITHHMACSHA512-224", Put back on next BC release 1.83+
//                "PBKDF2WITHHMACSHA512-256", both tested in testBCAgreementLowLevel
                "PBKDF2WITHHMACSHA3-224",
                "PBKDF2WITHHMACSHA3-256",
                "PBKDF2WITHHMACSHA3-384",
                "PBKDF2WITHHMACSHA3-512",
                "PBKDF2WITHHMACSM3",
        })
        {

            //
            // Parameter values in this test were just chosen without regard to
            // real world viability, please do not cut and paste this into anything important.
            //

            char[] passphrase = new String(random(8, sr)).toCharArray();
            byte[] salt = random(16, sr);
            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance(prf, JostleProvider.PROVIDER_NAME);
            SecretKeyFactory kfBc = SecretKeyFactory.getInstance(prf, BouncyCastleProvider.PROVIDER_NAME);

            SecretKey joKey = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            SecretKey bcKey = kfBc.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));

            Assertions.assertArrayEquals(joKey.getEncoded(), bcKey.getEncoded(), prf);
        }
    }

    @Test
    public void testBCAgreementLowLevel() throws Exception
    {
        //
        // We need to use the low level api to get some of the variations on the BC side
        //
        SecureRandom sr = seededRandom("testBCAgreementLowLevel");
        char[] passphrase = new String(random(8, sr)).toCharArray();
        byte[] salt = random(16, sr);
        byte[] passphraseAsBytes = Strings.toUTF8ByteArray(passphrase);


        { // BLAKE2B-512
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new Blake2bDigest(512));
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACBLAKE2B-512", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }

        { // BLAKE2S-256
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new Blake2sDigest(256));
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACBLAKE2S-256", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }


        { // MD5
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new MD5Digest());
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACMD5", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }


        { // MD5-SHA1
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new MD5SHA1Digest());
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACMD5-SHA1", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));

            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }

        { // SHA512-224
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA512tDigest(224));
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA512-224", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));

            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }

        { // SHA512-256
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA512tDigest(256));
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA512-256", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));

            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }


        { // RIPEMD-160
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new RIPEMD160Digest());
            generator.init(passphraseAsBytes, salt, 100);
            KeyParameter llBC = (KeyParameter) generator.generateDerivedParameters(256);

            SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("PBKDF2WITHHMACRIPEMD160", JostleProvider.PROVIDER_NAME);
            SecretKey sk = kfJostle.generateSecret(new PBEKeySpec(passphrase, salt, 100, 256));
            Assertions.assertArrayEquals(llBC.getKey(), sk.getEncoded());
        }

    }

    /**
     * Negative path per CLAUDE.md "Tests must exercise the negative
     * path". The BC-agreement tests above prove Jostle produces the
     * same output as BC for a given input — but they don't prove that
     * the output actually depends on each input. A stub KDF that
     * returned a fixed buffer would fail BC agreement, but a buggy
     * KDF that, say, ignored the salt would silently produce the same
     * output for distinct salts. This test confirms each input
     * (password, salt, iteration count) actually influences the
     * derived key.
     */
    @Test
    public void testInputsActuallyInfluenceDerivedKey() throws Exception
    {
        SecureRandom sr = seededRandom("testInputsActuallyInfluenceDerivedKey");
        SecretKeyFactory kf = SecretKeyFactory.getInstance(
                "PBKDF2WITHHMACSHA256", JostleProvider.PROVIDER_NAME);

        char[] pwd1 = new String(random(8, sr)).toCharArray();
        char[] pwd2 = new String(random(8, sr)).toCharArray();
        byte[] salt1 = random(16, sr);
        byte[] salt2 = random(16, sr);

        byte[] base = kf.generateSecret(new PBEKeySpec(pwd1, salt1, 1000, 256)).getEncoded();

        // Different password → different key.
        byte[] diffPwd = kf.generateSecret(new PBEKeySpec(pwd2, salt1, 1000, 256)).getEncoded();
        Assertions.assertFalse(Arrays.areEqual(base, diffPwd),
                "different password must produce a different derived key");

        // Different salt → different key.
        byte[] diffSalt = kf.generateSecret(new PBEKeySpec(pwd1, salt2, 1000, 256)).getEncoded();
        Assertions.assertFalse(Arrays.areEqual(base, diffSalt),
                "different salt must produce a different derived key");

        // Different iteration count → different key.
        byte[] diffIter = kf.generateSecret(new PBEKeySpec(pwd1, salt1, 2000, 256)).getEncoded();
        Assertions.assertFalse(Arrays.areEqual(base, diffIter),
                "different iteration count must produce a different derived key");

        // Same inputs → same key (PBKDF2 is deterministic).
        byte[] repeat = kf.generateSecret(new PBEKeySpec(pwd1, salt1, 1000, 256)).getEncoded();
        Assertions.assertArrayEquals(base, repeat,
                "same inputs must produce the same derived key (PBKDF2 is deterministic)");
    }


    private static class MD5SHA1Digest implements ExtendedDigest
    {
        // blast from the past!

        private MD5Digest md5;
        private SHA1Digest sha1;

        public MD5SHA1Digest()
        {
            md5 = new MD5Digest();
            sha1 = new SHA1Digest();
        }


        @Override
        public String getAlgorithmName()
        {
            return "MD5-SHA1";
        }

        @Override
        public int getDigestSize()
        {
            return 20 + 16;
        }

        @Override
        public void update(byte in)
        {
            md5.update(in);
            sha1.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len)
        {
            md5.update(in, inOff, len);
            sha1.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff)
        {
            md5.doFinal(out, outOff);
            sha1.doFinal(out, outOff + md5.getDigestSize());
            return 20 + 16;
        }

        @Override
        public void reset()
        {
            md5.reset();
            sha1.reset();
        }

        @Override
        public int getByteLength()
        {
            return 64;
        }
    }
}
