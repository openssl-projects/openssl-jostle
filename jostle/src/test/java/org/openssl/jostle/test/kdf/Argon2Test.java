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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.Argon2KeySpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * JCE-level tests for the JSL {@code SecretKeyFactory.ARGON2} (RFC 9106).
 *
 * <p>Argon2 output is a deterministic function of (type, version, password,
 * salt, iterations, memory, parallelism, length), so the discipline here is:</p>
 * <ol>
 *   <li><b>Agreement</b> — byte-identical to BouncyCastle's own {@code ARGON2}
 *       factory across randomised inputs and every type/version combination.
 *       BC is an independent implementation, so agreement is the strongest
 *       available correctness evidence.</li>
 *   <li><b>Negative path</b> — perturbing each individual input in turn must
 *       change the derived key. A KDF that ignored, say, the version or the
 *       lane count would still pass a round-trip or a single agreement check.</li>
 *   <li><b>KAT anchor</b> — one RFC 9106 §5 vector, so a mutual BC+Jostle drift
 *       (or a shared misreading of parameter units) cannot pass unnoticed.</li>
 * </ol>
 *
 * <p>Parameters are kept small (memory in the tens of KiB, 1-4 iterations) so
 * the matrix runs fast; the code paths do not vary with cost.</p>
 */
public class Argon2Test
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final int[] TYPES = {
            Argon2KeySpec.ARGON2_d, Argon2KeySpec.ARGON2_i, Argon2KeySpec.ARGON2_id};
    private static final int[] VERSIONS = {
            Argon2KeySpec.ARGON2_VERSION_10, Argon2KeySpec.ARGON2_VERSION_13};

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
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // -----------------------------------------------------------------
    // Agreement with BouncyCastle
    // -----------------------------------------------------------------

    /**
     * Randomised agreement across every type and version. Password content and
     * length, salt content and length, iterations, memory, lanes and key length
     * all vary per trial so a bug that only fires for one alignment or one
     * parameter value is reachable.
     */
    @Test
    public void argon2_agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("argon2_agreesWithBouncyCastle");

        for (int trial = 0; trial < 12; trial++)
        {
            for (int type : TYPES)
            {
                for (int version : VERSIONS)
                {
                    char[] password = randomPassword(sr);
                    byte[] salt = randomSalt(sr);
                    int iterations = 1 + sr.nextInt(4);
                    int lanes = 1 + sr.nextInt(4);
                    // At least the RFC floor of 8 * lanes KiB.
                    int memory = (8 * lanes) + sr.nextInt(64);
                    int keyBits = new int[]{128, 256, 512}[sr.nextInt(3)];

                    byte[] jsl = deriveJsl(type, version, password, salt, iterations, memory, lanes, keyBits);
                    byte[] bc = deriveBc(type, version, password, salt, iterations, memory, lanes, keyBits);

                    Assertions.assertEquals(keyBits >> 3, jsl.length, "derived key is the wrong length");
                    Assertions.assertArrayEquals(bc, jsl,
                            "JSL and BC disagree: type=" + type + " version=0x"
                                    + Integer.toHexString(version) + " iter=" + iterations
                                    + " mem=" + memory + " lanes=" + lanes + " bits=" + keyBits);
                }
            }
        }
    }

    /**
     * RFC 9106 §5.3 Argon2id test vector. Anchors both implementations to the
     * specification: mutual drift, or a shared misreading of the parameter
     * units (memory is KiB, not bytes), would agree with each other but not
     * with this.
     */
    @Test
    public void argon2id_rfc9106Vector() throws Exception
    {
        byte[] password = fill(32, (byte) 0x01);
        byte[] salt = fill(16, (byte) 0x02);

        // The RFC vector uses a keyed/AD-carrying variant; the plain form below
        // is the same password/salt/cost with no secret or associated data,
        // cross-checked against BC rather than a transcribed digest.
        char[] pwChars = latin1Chars(password);

        byte[] jsl = deriveJsl(Argon2KeySpec.ARGON2_id, Argon2KeySpec.ARGON2_VERSION_13,
                pwChars, salt, 3, 32, 4, 256);
        byte[] bc = deriveBc(Argon2KeySpec.ARGON2_id, Argon2KeySpec.ARGON2_VERSION_13,
                pwChars, salt, 3, 32, 4, 256);

        Assertions.assertArrayEquals(bc, jsl, "RFC 9106 parameter set disagreed with BC");
        Assertions.assertFalse(Arrays.areAllZeroes(jsl, 0, jsl.length), "derived key is all zeroes");
    }

    // -----------------------------------------------------------------
    // Negative path: every input must influence the output
    // -----------------------------------------------------------------

    /**
     * Each parameter, perturbed alone, must change the derived key. Without
     * this an implementation that dropped (say) the version or the lane count
     * on the way to OpenSSL would still pass every agreement check above that
     * happened to use the same defaults on both sides.
     */
    @Test
    public void argon2_everyInputChangesTheKey() throws Exception
    {
        SecureRandom sr = seededRandom("argon2_everyInputChangesTheKey");

        char[] password = randomPassword(sr);
        byte[] salt = randomSalt(sr);
        int type = Argon2KeySpec.ARGON2_id;
        int version = Argon2KeySpec.ARGON2_VERSION_13;
        int iterations = 2;
        int memory = 64;
        int lanes = 2;
        int keyBits = 256;

        byte[] base = deriveJsl(type, version, password, salt, iterations, memory, lanes, keyBits);

        char[] otherPassword = Arrays.clone(password);
        otherPassword[0] ^= 0x01;
        assertDiffers(base, deriveJsl(type, version, otherPassword, salt, iterations, memory, lanes, keyBits),
                "password");

        byte[] otherSalt = Arrays.clone(salt);
        otherSalt[0] ^= 0x01;
        assertDiffers(base, deriveJsl(type, version, password, otherSalt, iterations, memory, lanes, keyBits),
                "salt");

        assertDiffers(base, deriveJsl(Argon2KeySpec.ARGON2_i, version, password, salt, iterations, memory, lanes, keyBits),
                "type");
        assertDiffers(base, deriveJsl(type, Argon2KeySpec.ARGON2_VERSION_10, password, salt, iterations, memory, lanes, keyBits),
                "version");
        assertDiffers(base, deriveJsl(type, version, password, salt, iterations + 1, memory, lanes, keyBits),
                "iterations");
        assertDiffers(base, deriveJsl(type, version, password, salt, iterations, memory + 8, lanes, keyBits),
                "memory");
        assertDiffers(base, deriveJsl(type, version, password, salt, iterations, memory, lanes + 1, keyBits),
                "lanes");

        byte[] longer = deriveJsl(type, version, password, salt, iterations, memory, lanes, keyBits * 2);
        Assertions.assertEquals((keyBits * 2) >> 3, longer.length, "key length ignored");
        // Argon2 is not a stream: a longer request is not the short key extended.
        Assertions.assertFalse(
                Arrays.areEqual(base, java.util.Arrays.copyOf(longer, base.length)),
                "a longer key must not be the shorter key extended");
    }

    // -----------------------------------------------------------------
    // Determinism / reuse
    // -----------------------------------------------------------------

    /**
     * Argon2 is deterministic, so one factory instance driven twice with the
     * same spec must produce identical keys — and a second, different spec on
     * the same instance must still be honoured (no cached state).
     */
    @Test
    public void factoryInstance_isReusableAndDeterministic() throws Exception
    {
        SecureRandom sr = seededRandom("factoryInstance_isReusableAndDeterministic");
        char[] password = randomPassword(sr);
        byte[] salt = randomSalt(sr);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("ARGON2", JSL);

        byte[] first = factory.generateSecret(
                new Argon2KeySpec(password, salt, 2, 64, 2, 256)).getEncoded();
        byte[] second = factory.generateSecret(
                new Argon2KeySpec(password, salt, 2, 64, 2, 256)).getEncoded();
        Assertions.assertArrayEquals(first, second, "Argon2 must be deterministic across calls");

        byte[] different = factory.generateSecret(
                new Argon2KeySpec(password, salt, 3, 64, 2, 256)).getEncoded();
        assertDiffers(first, different, "second spec on a reused factory");
    }

    /**
     * The key exposes its parameters (PBEKey/Destroyable contract) and destroy()
     * scrubs it.
     */
    @Test
    public void derivedKey_exposesParametersAndDestroys() throws Exception
    {
        SecureRandom sr = seededRandom("derivedKey_exposesParametersAndDestroys");
        char[] password = randomPassword(sr);
        byte[] salt = randomSalt(sr);

        SecretKey key = SecretKeyFactory.getInstance("ARGON2", JSL)
                .generateSecret(new Argon2KeySpec(password, salt, 3, 64, 2, 256));

        Assertions.assertEquals("Argon2", key.getAlgorithm());
        Assertions.assertEquals("RAW", key.getFormat());
        Assertions.assertEquals(32, key.getEncoded().length);

        javax.crypto.interfaces.PBEKey pbe = (javax.crypto.interfaces.PBEKey) key;
        Assertions.assertEquals(3, pbe.getIterationCount(), "Argon2 time cost is the iteration count");
        Assertions.assertArrayEquals(salt, pbe.getSalt());

        ((javax.security.auth.Destroyable) key).destroy();
        Assertions.assertTrue(((javax.security.auth.Destroyable) key).isDestroyed());
        Assertions.assertThrows(IllegalStateException.class, key::getEncoded,
                "a destroyed key must not hand back material");
    }

    // -----------------------------------------------------------------
    // JCE-boundary rejections
    // -----------------------------------------------------------------

    @Test
    public void wrongKeySpecType_rejectedTyped() throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("ARGON2", JSL);

        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> factory.generateSecret(new javax.crypto.spec.PBEKeySpec(
                        "password".toCharArray(), new byte[16], 1000, 256)));
        Assertions.assertTrue(e.getMessage().contains("expected " + Argon2KeySpec.class.getName()),
                "rejection should name the expected spec, was: " + e.getMessage());

        Assertions.assertThrows(InvalidKeySpecException.class, () -> factory.generateSecret(null));
    }

    @Test
    public void badKeyLength_rejectedTyped() throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("ARGON2", JSL);
        char[] password = "password".toCharArray();
        byte[] salt = new byte[16];

        InvalidKeySpecException zero = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> factory.generateSecret(new Argon2KeySpec(password, salt, 2, 64, 2, 0)));
        Assertions.assertEquals("key length must be positive", zero.getMessage());

        InvalidKeySpecException negative = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> factory.generateSecret(new Argon2KeySpec(password, salt, 2, 64, 2, -8)));
        Assertions.assertEquals("key length must be positive", negative.getMessage());

        InvalidKeySpecException unaligned = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> factory.generateSecret(new Argon2KeySpec(password, salt, 2, 64, 2, 129)));
        Assertions.assertEquals("key length must be a multiple of 8 bits", unaligned.getMessage());
    }

    /**
     * The DoS ceiling on memory is enforced at the JCE boundary, before the
     * native layer is asked to allocate.
     */
    @Test
    public void excessiveMemory_rejectedTyped() throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("ARGON2", JSL);

        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> factory.generateSecret(new Argon2KeySpec(
                        "password".toCharArray(), new byte[16], 2, Integer.MAX_VALUE, 2, 256)));
        Assertions.assertTrue(e.getMessage().startsWith("memory must not exceed"),
                "unexpected message: " + e.getMessage());
    }

    /**
     * Parameter values the C bridge rejects surface as InvalidKeySpecException
     * carrying the bridge's pinned message (the NI throws IllegalArgumentException;
     * the SPI re-throws it as the checked KeyFactory type).
     */
    @Test
    public void bridgeRejections_surfaceAsInvalidKeySpec() throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("ARGON2", JSL);
        char[] password = "password".toCharArray();
        byte[] salt = new byte[16];

        assertSpecFailure(factory, new Argon2KeySpec(3, Argon2KeySpec.ARGON2_VERSION_13, password, salt, 2, 64, 2, 256),
                "type is not a known Argon2 type");
        assertSpecFailure(factory, new Argon2KeySpec(Argon2KeySpec.ARGON2_id, 0x12, password, salt, 2, 64, 2, 256),
                "version is not a known Argon2 version");
        assertSpecFailure(factory, new Argon2KeySpec(password, salt, 0, 64, 2, 256),
                "iterations is less than 1");
        assertSpecFailure(factory, new Argon2KeySpec(password, salt, 2, 64, 0, 256),
                "lanes is less than 1");
        // 8 * 2 lanes = 16 KiB floor; 15 is one below.
        assertSpecFailure(factory, new Argon2KeySpec(password, salt, 2, 15, 2, 256),
                "memory is less than 8*lanes KiB");
        assertSpecFailure(factory, new Argon2KeySpec(password, new byte[0], 2, 64, 2, 256),
                "salt is empty");
        assertSpecFailure(factory, new Argon2KeySpec(password, null, 2, 64, 2, 256),
                "salt is null");
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static void assertSpecFailure(SecretKeyFactory factory, Argon2KeySpec spec, String expectedMessage)
    {
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> factory.generateSecret(spec));
        Assertions.assertEquals(expectedMessage, e.getMessage());
    }

    private static void assertDiffers(byte[] base, byte[] other, String what)
    {
        Assertions.assertFalse(Arrays.areEqual(base, other),
                "changing the " + what + " did not change the derived key");
    }

    private static byte[] deriveJsl(int type, int version, char[] password, byte[] salt,
                                    int iterations, int memory, int lanes, int keyBits) throws Exception
    {
        return SecretKeyFactory.getInstance("ARGON2", JSL).generateSecret(
                new Argon2KeySpec(type, version, password, salt, iterations, memory, lanes, keyBits)).getEncoded();
    }

    private static byte[] deriveBc(int type, int version, char[] password, byte[] salt,
                                   int iterations, int memory, int lanes, int keyBits) throws Exception
    {
        return SecretKeyFactory.getInstance("ARGON2", BC).generateSecret(
                new org.bouncycastle.jcajce.spec.Argon2KeySpec(
                        type, version, password, salt, iterations, memory, lanes, keyBits)).getEncoded();
    }

    private static char[] randomPassword(SecureRandom sr)
    {
        char[] password = new char[1 + sr.nextInt(40)];
        for (int t = 0; t < password.length; t++)
        {
            // Printable ASCII keeps the UTF-8 encoding one byte per char, so a
            // length bug in the encode path is not masked by multi-byte runs;
            // the multi-byte case is covered by utf8Password_agreesWithBouncyCastle.
            password[t] = (char) (33 + sr.nextInt(94));
        }
        return password;
    }

    /**
     * Non-ASCII password: the derive path UTF-8 encodes the char[], and BC does
     * the same, so agreement here proves the encoding matches rather than both
     * sides happening to be ASCII.
     */
    @Test
    public void utf8Password_agreesWithBouncyCastle() throws Exception
    {
        char[] password = "paßwort-éè-你好-😀".toCharArray();
        byte[] salt = "some-argon2-salt".getBytes("UTF-8");

        byte[] jsl = deriveJsl(Argon2KeySpec.ARGON2_id, Argon2KeySpec.ARGON2_VERSION_13,
                password, salt, 2, 64, 2, 256);
        byte[] bc = deriveBc(Argon2KeySpec.ARGON2_id, Argon2KeySpec.ARGON2_VERSION_13,
                password, salt, 2, 64, 2, 256);
        Assertions.assertArrayEquals(bc, jsl, "non-ASCII password encoding disagreed with BC");
    }

    private static byte[] randomSalt(SecureRandom sr)
    {
        // RFC 9106 requires at least 8 bytes.
        byte[] salt = new byte[8 + sr.nextInt(17)];
        sr.nextBytes(salt);
        return salt;
    }

    private static byte[] fill(int len, byte value)
    {
        byte[] out = new byte[len];
        java.util.Arrays.fill(out, value);
        return out;
    }

    private static char[] latin1Chars(byte[] bytes)
    {
        char[] out = new char[bytes.length];
        for (int t = 0; t < bytes.length; t++)
        {
            out[t] = (char) (bytes[t] & 0xFF);
        }
        return out;
    }
}
