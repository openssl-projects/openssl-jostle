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

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kdf.BytePasswordKdf;

import java.security.SecureRandom;
import java.security.Security;

/**
 * The BCFKS interop pin: the byte-password scheme
 * {@link BytePasswordKdf#pkcs12PasswordToBytes} and
 * {@link BytePasswordKdf#derivationPassword} implement, measured against
 * BouncyCastle r1rv86's own classes, plus a full end-to-end derivation
 * agreement for both KDFs and both PRFs BCFKS's format supports.
 */
public class BytePasswordKdfTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName)
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        try
        {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed(seed);
            return sr;
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // ---- pkcs12PasswordToBytes: the null/empty REGRESSION case ------------

    @Test
    public void pkcs12PasswordToBytes_nullAndEmptyPasswordProduceZeroLengthArrays_regression()
    {
        // Measured against r1rv86 (PBEParametersGenerator.java:150-165) and
        // against the 1.86 jar's bytecode: both branches return new byte[0].
        Assertions.assertEquals(0, BytePasswordKdf.pkcs12PasswordToBytes(null).length);
        Assertions.assertEquals(0, BytePasswordKdf.pkcs12PasswordToBytes(new char[0]).length);

        // Cross-checked against BouncyCastle's own method, live.
        Assertions.assertArrayEquals(
                PBEParametersGenerator.PKCS12PasswordToBytes(null),
                BytePasswordKdf.pkcs12PasswordToBytes(null));
        Assertions.assertArrayEquals(
                PBEParametersGenerator.PKCS12PasswordToBytes(new char[0]),
                BytePasswordKdf.pkcs12PasswordToBytes(new char[0]));
    }

    @Test
    public void pkcs12PasswordToBytes_agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("pkcs12PasswordToBytes_agreesWithBouncyCastle");
        for (int trial = 0; trial < 20; trial++)
        {
            int len = 1 + sr.nextInt(32);
            char[] password = new char[len];
            for (int i = 0; i < len; i++)
            {
                // Full char range, including surrogate halves -- BC's method
                // is a raw per-char UTF-16BE encode with no surrogate-pair
                // awareness, so it is compared exactly, byte for byte.
                password[i] = (char) sr.nextInt(0x10000);
            }
            byte[] expected = PBEParametersGenerator.PKCS12PasswordToBytes(password);
            byte[] actual = BytePasswordKdf.pkcs12PasswordToBytes(password);
            Assertions.assertArrayEquals(expected, actual, "trial " + trial);
        }
    }

    @Test
    public void pkcs12PasswordToBytes_lengthIsTwoBytesPerCharPlusTerminator()
    {
        char[] password = "hello".toCharArray();
        byte[] encoded = BytePasswordKdf.pkcs12PasswordToBytes(password);
        Assertions.assertEquals((password.length + 1) * 2, encoded.length);
        // Trailing two-byte NUL terminator.
        Assertions.assertEquals(0, encoded[encoded.length - 2]);
        Assertions.assertEquals(0, encoded[encoded.length - 1]);
        // First char big-endian.
        Assertions.assertEquals((byte) ('h' >>> 8), encoded[0]);
        Assertions.assertEquals((byte) 'h', encoded[1]);
    }

    // ---- derivationPassword: purpose concatenation -------------------------

    @Test
    public void derivationPassword_isPlainConcatenationOfTheTwoBouncyCastleCalls() throws Exception
    {
        // BcFKSKeyStoreSpi.generateKey (r1rv86, :848-852): encPassword ||
        // differentiator, BC's own Arrays.concatenate -- plain concatenation.
        SecureRandom sr = seededRandom("derivationPassword_isPlainConcatenationOfTheTwoBouncyCastleCalls");
        String[] purposes = {
                BytePasswordKdf.PURPOSE_INTEGRITY_CHECK,
                BytePasswordKdf.PURPOSE_STORE_ENCRYPTION,
                BytePasswordKdf.PURPOSE_PRIVATE_KEY_ENCRYPTION,
                BytePasswordKdf.PURPOSE_SECRET_KEY_ENCRYPTION,
        };
        for (String purpose : purposes)
        {
            char[] password = new char[8 + sr.nextInt(16)];
            for (int i = 0; i < password.length; i++)
            {
                password[i] = (char) (0x20 + sr.nextInt(0x5E));
            }
            byte[] expected = concat(
                    PBEParametersGenerator.PKCS12PasswordToBytes(password),
                    PBEParametersGenerator.PKCS12PasswordToBytes(purpose.toCharArray()));
            byte[] actual = BytePasswordKdf.derivationPassword(password, purpose);
            Assertions.assertArrayEquals(expected, actual, purpose);
        }
    }

    @Test
    public void derivationPassword_nullPasswordIsJustThePurpose()
    {
        byte[] expected = PBEParametersGenerator.PKCS12PasswordToBytes(
                BytePasswordKdf.PURPOSE_INTEGRITY_CHECK.toCharArray());
        byte[] actual = BytePasswordKdf.derivationPassword(null, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK);
        Assertions.assertArrayEquals(expected, actual);
    }

    // ---- Full PBKDF2 derivation agreement, both PRFs BCFKS's format supports --

    @Test
    public void pbkdf2Derivation_agreesWithBouncyCastle_hmacSha512() throws Exception
    {
        SecureRandom sr = seededRandom("pbkdf2Derivation_agreesWithBouncyCastle_hmacSha512");
        for (int trial = 0; trial < 5; trial++)
        {
            char[] password = randomPassword(sr);
            byte[] salt = new byte[64];
            sr.nextBytes(salt);
            int iterationCount = 1000 + sr.nextInt(2000);
            int keyLengthBytes = 32;

            byte[] derivationPassword = BytePasswordKdf.derivationPassword(
                    password, BytePasswordKdf.PURPOSE_STORE_ENCRYPTION);

            PKCS5S2ParametersGenerator bcGen = new PKCS5S2ParametersGenerator(new SHA512Digest());
            bcGen.init(derivationPassword, salt, iterationCount);
            byte[] expected = ((KeyParameter) bcGen.generateDerivedParameters(keyLengthBytes * 8)).getKey();

            byte[] actual = new byte[keyLengthBytes];
            BytePasswordKdf.pbkdf2(NISelector.KdfNI, derivationPassword, salt, iterationCount,
                    "SHA2-512", actual, 0, actual.length);

            Assertions.assertArrayEquals(expected, actual, "trial " + trial);
        }
    }

    @Test
    public void pbkdf2Derivation_agreesWithBouncyCastle_hmacSha3_512() throws Exception
    {
        SecureRandom sr = seededRandom("pbkdf2Derivation_agreesWithBouncyCastle_hmacSha3_512");
        for (int trial = 0; trial < 5; trial++)
        {
            char[] password = randomPassword(sr);
            byte[] salt = new byte[64];
            sr.nextBytes(salt);
            int iterationCount = 1000 + sr.nextInt(2000);
            int keyLengthBytes = 32;

            byte[] derivationPassword = BytePasswordKdf.derivationPassword(
                    password, BytePasswordKdf.PURPOSE_INTEGRITY_CHECK);

            PKCS5S2ParametersGenerator bcGen = new PKCS5S2ParametersGenerator(new SHA3Digest(512));
            bcGen.init(derivationPassword, salt, iterationCount);
            byte[] expected = ((KeyParameter) bcGen.generateDerivedParameters(keyLengthBytes * 8)).getKey();

            byte[] actual = new byte[keyLengthBytes];
            BytePasswordKdf.pbkdf2(NISelector.KdfNI, derivationPassword, salt, iterationCount,
                    "SHA3-512", actual, 0, actual.length);

            Assertions.assertArrayEquals(expected, actual, "trial " + trial);
        }
    }

    @Test
    public void pbkdf2Derivation_agreesWithBouncyCastle_emptyPassword() throws Exception
    {
        // Full-derivation-depth REGRESSION for the null/empty case: with the
        // wrong ("2 zero bytes") reading, an empty password derives a
        // DIFFERENT key than BouncyCastle for the same tuple.
        byte[] salt = new byte[64];
        seededRandom("pbkdf2Derivation_agreesWithBouncyCastle_emptyPassword").nextBytes(salt);
        int iterationCount = 51200;
        int keyLengthBytes = 32;

        byte[] derivationPassword = BytePasswordKdf.derivationPassword(
                new char[0], BytePasswordKdf.PURPOSE_STORE_ENCRYPTION);

        PKCS5S2ParametersGenerator bcGen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        bcGen.init(derivationPassword, salt, iterationCount);
        byte[] expected = ((KeyParameter) bcGen.generateDerivedParameters(keyLengthBytes * 8)).getKey();

        byte[] actual = new byte[keyLengthBytes];
        BytePasswordKdf.pbkdf2(NISelector.KdfNI, derivationPassword, salt, iterationCount,
                "SHA2-512", actual, 0, actual.length);

        Assertions.assertArrayEquals(expected, actual);
    }

    // ---- Full scrypt derivation agreement (BC-default N=16384 r=8 p=1) -----

    @Test
    public void scryptDerivation_agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("scryptDerivation_agreesWithBouncyCastle");
        int n = 16384;
        int r = 8;
        int p = 1;
        int keyLengthBytes = 32;

        for (int trial = 0; trial < 3; trial++)
        {
            char[] password = randomPassword(sr);
            byte[] salt = new byte[64];
            sr.nextBytes(salt);

            byte[] derivationPassword = BytePasswordKdf.derivationPassword(
                    password, BytePasswordKdf.PURPOSE_SECRET_KEY_ENCRYPTION);

            byte[] expected = SCrypt.generate(derivationPassword, salt, n, r, p, keyLengthBytes);

            byte[] actual = new byte[keyLengthBytes];
            BytePasswordKdf.scrypt(NISelector.MemoryHardKdfNI, derivationPassword, salt, n, r, p,
                    actual, 0, actual.length);

            Assertions.assertArrayEquals(expected, actual, "trial " + trial);
        }
    }

    @Test
    public void scryptDerivation_agreesWithBouncyCastle_emptyPassword() throws Exception
    {
        byte[] salt = new byte[64];
        seededRandom("scryptDerivation_agreesWithBouncyCastle_emptyPassword").nextBytes(salt);
        int n = 16384;
        int r = 8;
        int p = 1;
        int keyLengthBytes = 32;

        byte[] derivationPassword = BytePasswordKdf.derivationPassword(
                new char[0], BytePasswordKdf.PURPOSE_SECRET_KEY_ENCRYPTION);

        byte[] expected = SCrypt.generate(derivationPassword, salt, n, r, p, keyLengthBytes);

        byte[] actual = new byte[keyLengthBytes];
        BytePasswordKdf.scrypt(NISelector.MemoryHardKdfNI, derivationPassword, salt, n, r, p,
                actual, 0, actual.length);

        Assertions.assertArrayEquals(expected, actual);
    }

    private static char[] randomPassword(SecureRandom sr)
    {
        char[] password = new char[8 + sr.nextInt(16)];
        for (int i = 0; i < password.length; i++)
        {
            password[i] = (char) (0x20 + sr.nextInt(0x5E));
        }
        return password;
    }
}
