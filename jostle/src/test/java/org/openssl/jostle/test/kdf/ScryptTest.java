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
import org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Strings;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

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
     * The factory does not read a foreign spec reflectively — BC's
     * {@code org.bouncycastle.jcajce.spec.ScryptKeySpec} is refused typed,
     * naming the Jostle class.
     */
    @Test
    public void scryptFactoryRefusesForeignKeySpec() throws Exception
    {
        SecureRandom sr = seededRandom("scryptFactoryRefusesForeignKeySpec");
        char[] passphrase = new String(random(8, sr)).toCharArray();
        byte[] salt = random(16, sr);
        int n = 4, r = 2, p = 3;

        SecretKeyFactory kfJostle = SecretKeyFactory.getInstance("SCRYPT", JostleProvider.PROVIDER_NAME);
        org.bouncycastle.jcajce.spec.ScryptKeySpec foreign =
                new org.bouncycastle.jcajce.spec.ScryptKeySpec(passphrase, salt, n, r, p, 512);

        java.security.spec.InvalidKeySpecException e = Assertions.assertThrows(
                java.security.spec.InvalidKeySpecException.class, () -> kfJostle.generateSecret(foreign));
        Assertions.assertTrue(e.getMessage().contains("org.openssl.jostle.jcajce.spec.ScryptKeySpec"),
                "message must name the Jostle class: " + e.getMessage());
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




    /** translateKey refuses every key but this factory's own, so no parameter that produced a key is dropped. */
    @Test
    public void translateKey_refusesOtherKeys() throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("SCRYPT", JostleProvider.PROVIDER_NAME);
        SecretKey jostlePbe = BytePasswordKdf.pbeKey("PBKDF2WithHmacSHA256", "password".toCharArray(), new byte[16],
                1000, new byte[32]);
        SecretKey[] others = {jostlePbe, new ForeignPbeKey(), new SecretKeySpec(new byte[16], "AES")};
        for (SecretKey other : others)
        {
            InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                    () -> factory.translateKey(other));
            Assertions.assertEquals("unsupported key type: " + other.getClass(), e.getMessage());
        }
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class, () -> factory.translateKey(null));
        Assertions.assertEquals("key parameter is null", e.getMessage());
    }

    /** A PBEKey from outside Jostle. */
    private static final class ForeignPbeKey implements PBEKey
    {
        public char[] getPassword()
        {
            return "password".toCharArray();
        }

        public byte[] getSalt()
        {
            return new byte[16];
        }

        public int getIterationCount()
        {
            return 1000;
        }

        public String getAlgorithm()
        {
            return "PBKDF2WithHmacSHA256";
        }

        public String getFormat()
        {
            return "RAW";
        }

        public byte[] getEncoded()
        {
            return new byte[32];
        }
    }

    @Test
    public void nullPassword_rejectedTyped()
    {
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> KDFAgreementTest.derive(JostleProvider.PROVIDER_NAME, "SCRYPT",
                        new ScryptKeySpec(null, new byte[16], 16, 1, 1, 256)));
        Assertions.assertEquals("password is null", e.getMessage());
    }

    /**
     * RFC 7914 section 12 vectors 2 and 3 as known answers. Vector 1 has an empty salt, which the bridge refuses;
     * the 1 GiB vector 4 is not run.
     */
    @Test
    public void rfc7914Vectors() throws Exception
    {
        Assertions.assertArrayEquals(Hex.decode("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                        + "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
                KDFAgreementTest.derive(JostleProvider.PROVIDER_NAME, "SCRYPT", new ScryptKeySpec(
                        "password".toCharArray(), Strings.toByteArray("NaCl"), 1024, 8, 16, 512)));
        Assertions.assertArrayEquals(Hex.decode("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
                        + "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"),
                KDFAgreementTest.derive(JostleProvider.PROVIDER_NAME, "SCRYPT", new ScryptKeySpec(
                        "pleaseletmein".toCharArray(), Strings.toByteArray("SodiumChloride"), 16384, 8, 1, 512)));

        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> KDFAgreementTest.derive(JostleProvider.PROVIDER_NAME, "SCRYPT",
                        new ScryptKeySpec(new char[0], new byte[0], 16, 1, 1, 512)));
        Assertions.assertEquals("salt is empty", e.getMessage());
    }
}
