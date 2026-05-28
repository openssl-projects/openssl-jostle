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

package org.openssl.jostle.test.ec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * JCE-level tests for the ECDH KeyAgreement SPI. Covers:
 * <ol>
 *   <li>round-trip per curve — Alice and Bob derive byte-equal secrets,</li>
 *   <li>secret length matches curve byte size,</li>
 *   <li>BC agreement — Jostle ↔ BC derive byte-equal secrets,</li>
 *   <li>negative — different keys produce different secrets,</li>
 *   <li>negative — mismatched curves rejected at doPhase,</li>
 *   <li>state-machine guards — pre-init / pre-doPhase misuse,</li>
 *   <li>SPI reuse — two derivations on the same instance produce
 *       independent results,</li>
 *   <li>foreign key types rejected,</li>
 *   <li>{@code generateSecret(byte[], int)} offset-write contract,</li>
 *   <li>{@code generateSecret(String)} returns a SecretKey wrapper.</li>
 * </ol>
 */
public class ECDHTest
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

    private static final String[] STANDARD_CURVES = {
            "P-256", "P-384", "P-521", "secp256k1", "sect283k1"
    };


    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    // -----------------------------------------------------------------
    // Round-trip per curve
    // -----------------------------------------------------------------

    @Test
    public void testEcdh_AllCurves_aliceAndBobAgree() throws Exception
    {
        int generated = 0;
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }

            KeyPair alice = generateKeyPair(curve);
            KeyPair bob = generateKeyPair(curve);

            byte[] aliceSecret = derive(alice.getPrivate(), bob.getPublic());
            byte[] bobSecret = derive(bob.getPrivate(), alice.getPublic());

            Assertions.assertArrayEquals(aliceSecret, bobSecret,
                    curve + ": Alice and Bob derived different secrets");

            // Sanity: secret length matches the curve field byte length.
            // Derive from the actual ECParameterSpec rather than a
            // hardcoded switch so the assertion works for any curve we
            // add to STANDARD_CURVES (binary-field K/B curves included).
            int fieldBits = ((java.security.interfaces.ECPublicKey) alice.getPublic())
                    .getParams().getCurve().getField().getFieldSize();
            int expectedBytes = (fieldBits + 7) / 8;
            Assertions.assertEquals(expectedBytes, aliceSecret.length,
                    curve + ": shared secret length mismatch (expected "
                            + expectedBytes + ")");

            generated++;
        }
        Assertions.assertTrue(generated > 0, "no curves were testable");
    }


    // -----------------------------------------------------------------
    // Negative: different keys produce different secrets
    // -----------------------------------------------------------------

    @Test
    public void testEcdh_DifferentPeers_DifferentSecrets() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");
        KeyPair eve = generateKeyPair("P-256");

        byte[] aliceWithBob = derive(alice.getPrivate(), bob.getPublic());
        byte[] aliceWithEve = derive(alice.getPrivate(), eve.getPublic());

        Assertions.assertFalse(Arrays.areEqual(aliceWithBob, aliceWithEve),
                "different peers must produce different shared secrets");
    }


    // -----------------------------------------------------------------
    // Negative: curve mismatch rejected
    // -----------------------------------------------------------------

    @Test
    public void testEcdh_CurveMismatch_rejectsAtDoPhase() throws Exception
    {
        Assumptions.assumeTrue(NISelector.ECServiceNI.curveSupported("P-256"));
        Assumptions.assumeTrue(NISelector.ECServiceNI.curveSupported("P-384"));

        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-384");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        try
        {
            ka.doPhase(bob.getPublic(), true);
            Assertions.fail("expected InvalidKeyException for curve mismatch");
        }
        catch (InvalidKeyException expected)
        {
            // Good — curve mismatch translated to typed exception.
            Assertions.assertEquals(
                    "ECDH doPhase: peer key rejected (curve mismatch?)",
                    expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // BC agreement
    // -----------------------------------------------------------------

    @Test
    public void testEcdh_BCAgreement() throws Exception
    {
        for (String curve : STANDARD_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(curve))
            {
                continue;
            }

            KeyPair joKp = generateKeyPair(curve);
            KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            bcKpg.initialize(new ECGenParameterSpec(curve));
            KeyPair bcKp = bcKpg.generateKeyPair();

            // BC key imported into Jostle for the Jostle-side derive.
            KeyFactory joKf = KeyFactory.getInstance("EC", JostleProvider.PROVIDER_NAME);
            PublicKey bcPubAsJo = joKf.generatePublic(
                    new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));

            // Jostle public key imported into BC.
            KeyFactory bcKf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey joPubAsBc = bcKf.generatePublic(
                    new X509EncodedKeySpec(joKp.getPublic().getEncoded()));

            // Jostle derives with BC's public key.
            KeyAgreement joKa = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
            joKa.init(joKp.getPrivate());
            joKa.doPhase(bcPubAsJo, true);
            byte[] joSecret = joKa.generateSecret();

            // BC derives with Jostle's public key.
            KeyAgreement bcKa = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
            bcKa.init(bcKp.getPrivate());
            bcKa.doPhase(joPubAsBc, true);
            byte[] bcSecret = bcKa.generateSecret();

            Assertions.assertArrayEquals(joSecret, bcSecret,
                    curve + ": Jostle and BC derived different shared secrets");
        }
    }


    // -----------------------------------------------------------------
    // SPI state-machine guards
    // -----------------------------------------------------------------

    @Test
    public void testEcdh_DoPhaseBeforeInit_isIllegalState() throws Exception
    {
        KeyPair kp = generateKeyPair("P-256");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        try
        {
            ka.doPhase(kp.getPublic(), true);
            Assertions.fail("doPhase before init must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("ECDH KeyAgreement not initialised",
                    expected.getMessage());
        }
    }

    @Test
    public void testEcdh_GenerateSecretBeforeDoPhase_isIllegalState() throws Exception
    {
        KeyPair kp = generateKeyPair("P-256");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(kp.getPrivate());
        try
        {
            ka.generateSecret();
            Assertions.fail("generateSecret before doPhase must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("ECDH: must call doPhase before generateSecret",
                    expected.getMessage());
        }
    }

    @Test
    public void testEcdh_LastPhaseFalse_isIllegalState() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        try
        {
            ka.doPhase(bob.getPublic(), false);
            Assertions.fail("ECDH is single-phase; lastPhase=false must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals(
                    "ECDH is a single-phase protocol; lastPhase must be true",
                    expected.getMessage());
        }
    }

    @Test
    public void testEcdh_RejectsForeignPrivateKey() throws Exception
    {
        // RSA private key handed to ECDH must throw InvalidKeyException
        // — required for JCE provider-fallback semantics.
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        PrivateKey rsaPriv = rsaKpg.generateKeyPair().getPrivate();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        try
        {
            ka.init(rsaPriv);
            Assertions.fail("ECDH init with RSA private key must throw InvalidKeyException");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("ECDH init: expected an ECPrivateKey",
                    expected.getMessage());
        }
    }

    @Test
    public void testEcdh_RejectsForeignPublicKey() throws Exception
    {
        KeyPair ec = generateKeyPair("P-256");
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        PublicKey rsaPub = rsaKpg.generateKeyPair().getPublic();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(ec.getPrivate());
        try
        {
            ka.doPhase(rsaPub, true);
            Assertions.fail("ECDH doPhase with RSA public key must throw InvalidKeyException");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("ECDH doPhase: expected an ECPublicKey",
                    expected.getMessage());
        }
    }

    @Test
    public void testEcdh_RejectsAlgorithmParameterSpec() throws Exception
    {
        KeyPair kp = generateKeyPair("P-256");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        try
        {
            ka.init(kp.getPrivate(), new AlgorithmParameterSpec() {}, null);
            Assertions.fail("ECDH does not accept AlgorithmParameterSpec");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            // SPI message names the rejected spec class — varies in
            // suffix because anonymous-subclass class names are
            // compiler-generated, so match on prefix.
            Assertions.assertTrue(
                    expected.getMessage().startsWith("no parameters accepted for ECDH"),
                    "unexpected message: " + expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // SPI reuse
    // -----------------------------------------------------------------

    @Test
    public void testEcdh_ReuseAfterGenerateSecret() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");
        KeyPair charlie = generateKeyPair("P-256");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);

        // First derivation: alice ↔ bob
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);
        byte[] s1 = ka.generateSecret();

        // Re-init with the same private key, different peer.
        ka.init(alice.getPrivate());
        ka.doPhase(charlie.getPublic(), true);
        byte[] s2 = ka.generateSecret();

        Assertions.assertFalse(Arrays.areEqual(s1, s2),
                "different peers on reused SPI must produce different secrets");

        // The reverse derivation by charlie should still match s2.
        byte[] s2Reverse = derive(charlie.getPrivate(), alice.getPublic());
        Assertions.assertArrayEquals(s2, s2Reverse,
                "alice/charlie reverse derivation diverged after SPI reuse");
    }


    // -----------------------------------------------------------------
    // generateSecret(byte[], int) offset-write contract
    // -----------------------------------------------------------------

    @Test
    public void testEcdh_GenerateSecretIntoBuffer_writesAtOffset() throws Exception
    {
        SecureRandom sr = seededRandom("testEcdh_GenerateSecretIntoBuffer_writesAtOffset");
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");

        // First learn the secret length via generateSecret().
        KeyAgreement probe = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        probe.init(alice.getPrivate());
        probe.doPhase(bob.getPublic(), true);
        byte[] reference = probe.generateSecret();

        // Re-derive into a caller-supplied buffer at a non-zero offset.
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);

        int prefix = 5;
        byte[] big = new byte[reference.length + prefix];
        // Fill with random bytes; save aside a copy of the prefix region
        // so we can confirm the bridge didn't write before outOff.
        sr.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        int written = ka.generateSecret(big, prefix);
        Assertions.assertEquals(reference.length, written);

        // Prefix region must be untouched.
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                "ECDH generateSecret(buf, off) modified bytes preceding offset");

        // Secret region must equal the reference.
        byte[] actualSecret = new byte[reference.length];
        System.arraycopy(big, prefix, actualSecret, 0, reference.length);
        Assertions.assertArrayEquals(reference, actualSecret,
                "ECDH generateSecret(buf, off) wrote a different secret");
    }

    @Test
    public void testEcdh_GenerateSecretIntoBuffer_shortBufferThrows() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);

        // P-256 secret is 32 bytes; a 31-byte buffer is too small.
        byte[] tooSmall = new byte[31];
        try
        {
            ka.generateSecret(tooSmall, 0);
            Assertions.fail("expected ShortBufferException");
        }
        catch (ShortBufferException expected)
        {
            Assertions.assertTrue(expected.getMessage().startsWith(
                    "ECDH generateSecret: buffer needs "),
                    "unexpected message: " + expected.getMessage());
        }
    }

    @Test
    public void testEcdh_GenerateSecretIntoBuffer_nullBuffer_isIllegalArgument() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);

        try
        {
            ka.generateSecret(null, 0);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("output buffer is null", expected.getMessage());
        }
    }

    @Test
    public void testEcdh_GenerateSecretIntoBuffer_negativeOffset_isIllegalArgument() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);

        try
        {
            ka.generateSecret(new byte[64], -1);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("offset out of range", expected.getMessage());
        }
    }

    @Test
    public void testEcdh_GenerateSecretIntoBuffer_offsetPastEnd_isIllegalArgument() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);

        try
        {
            // Boundary probe: offset = 65 is the smallest value that
            // exceeds the 64-byte buffer (the SPI accepts
            // offset == length and rejects anything past). Avoids
            // hiding an off-by-N in the SPI's range check.
            ka.generateSecret(new byte[64], 65);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("offset out of range", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // generateSecret(String) — SecretKey form
    // -----------------------------------------------------------------

    @Test
    public void testEcdh_GenerateSecretAsAESKey() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);
        // Note: bare-secret-as-AES-key is for test purposes only — real
        // use must run the bytes through a KDF first. The SPI just
        // wraps the bytes in a SecretKeySpec.
        SecretKey key = ka.generateSecret("AES");
        Assertions.assertNotNull(key);
        Assertions.assertEquals("AES", key.getAlgorithm());
        Assertions.assertEquals(32, key.getEncoded().length,
                "P-256 ECDH secret should be 32 bytes");
    }

    /**
     * {@code engineGenerateSecret(String)} must reject blank algorithm
     * names with {@link java.security.NoSuchAlgorithmException}.
     * {@code SecretKeySpec} only rejects {@code null} / empty strings;
     * a string containing only whitespace would be silently accepted
     * and produce a SecretKey with a non-meaningful algorithm name —
     * almost certainly not what the caller intended.
     */
    @Test
    public void testEcdh_GenerateSecret_rejectsBlankAlgorithmName() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");

        for (String bad : new String[]{null, "", " ", "    ", "\t\n "})
        {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
            ka.init(alice.getPrivate());
            ka.doPhase(bob.getPublic(), true);
            try
            {
                ka.generateSecret(bad);
                Assertions.fail("expected NoSuchAlgorithmException for "
                        + (bad == null ? "null" : "\"" + bad + "\""));
            }
            catch (java.security.NoSuchAlgorithmException expected)
            {
                Assertions.assertEquals(
                        "algorithm name must be non-null and non-blank",
                        expected.getMessage());
            }
        }
    }


    // -----------------------------------------------------------------
    // Provider plumbing: getInstance via OID
    // -----------------------------------------------------------------

    @Test
    public void testEcdh_GetInstanceByOID() throws Exception
    {
        KeyPair alice = generateKeyPair("P-256");
        KeyPair bob = generateKeyPair("P-256");

        // 1.3.132.1.12 = id-ecDH (SECG / RFC 5480)
        KeyAgreement ka = KeyAgreement.getInstance("1.3.132.1.12", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);
        byte[] secret = ka.generateSecret();
        Assertions.assertEquals(32, secret.length);
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static KeyPair generateKeyPair(String curve) throws Exception
    {
        Assumptions.assumeTrue(NISelector.ECServiceNI.curveSupported(curve),
                curve + " not supported by the loaded OpenSSL build");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static byte[] derive(PrivateKey priv, PublicKey peer) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(priv);
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }
}
