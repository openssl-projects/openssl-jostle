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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.ec.KDFParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Tests for {@code ECDHwithSHA<N>KDF} KeyAgreement transformations.
 *
 * <p>These are the JCE transformations CMS / CMP uses for key-agreement
 * recipient infos — the X9.63 KDF applied to a raw ECDH shared secret
 * produces a key-wrapping key, which is then used with AES-Wrap (the
 * AESWrap transformation also added in this branch) to wrap the content
 * encryption key.
 *
 * <p>Coverage:
 * <ol>
 *   <li>self-roundtrip — Alice and Bob derive the same KDF output for
 *       each digest variant,</li>
 *   <li>UKM influence — different shared info produces different output,</li>
 *   <li>output-length control via {@link KDFParameterSpec#getKeySize},</li>
 *   <li>cross-digest disagreement — SHA-256 and SHA-384 over the same
 *       inputs produce different outputs.</li>
 * </ol>
 */
public class ECDHwithKDFTest
{
    @BeforeAll
    static void before()
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


    @Test
    public void ecdhSha256Kdf_selfRoundTrip() throws Exception
    {
        KeyPair alice = generateP256();
        KeyPair bob = generateP256();

        byte[] aliceKey = deriveAES("ECDHwithSHA256KDF", alice.getPrivate(), bob.getPublic(), null);
        byte[] bobKey = deriveAES("ECDHwithSHA256KDF", bob.getPrivate(), alice.getPublic(), null);

        Assertions.assertArrayEquals(aliceKey, bobKey,
                "Alice and Bob should derive the same KEK");
        Assertions.assertEquals(16, aliceKey.length,
                "Default AES key length is 16 bytes (AES-128)");
    }

    @Test
    public void ecdhSha384Kdf_selfRoundTrip() throws Exception
    {
        KeyPair alice = generateP256();
        KeyPair bob = generateP256();

        byte[] aliceKey = deriveAES("ECDHwithSHA384KDF", alice.getPrivate(), bob.getPublic(), null);
        byte[] bobKey = deriveAES("ECDHwithSHA384KDF", bob.getPrivate(), alice.getPublic(), null);

        Assertions.assertArrayEquals(aliceKey, bobKey);
    }

    @Test
    public void ecdhSha512Kdf_selfRoundTrip() throws Exception
    {
        KeyPair alice = generateP256();
        KeyPair bob = generateP256();

        byte[] aliceKey = deriveAES("ECDHwithSHA512KDF", alice.getPrivate(), bob.getPublic(), null);
        byte[] bobKey = deriveAES("ECDHwithSHA512KDF", bob.getPrivate(), alice.getPublic(), null);

        Assertions.assertArrayEquals(aliceKey, bobKey);
    }

    @Test
    public void ecdhSha3_256Kdf_selfRoundTrip() throws Exception
    {
        KeyPair alice = generateP256();
        KeyPair bob = generateP256();

        byte[] aliceKey = deriveAES("ECDHwithSHA3-256KDF", alice.getPrivate(), bob.getPublic(), null);
        byte[] bobKey = deriveAES("ECDHwithSHA3-256KDF", bob.getPrivate(), alice.getPublic(), null);

        Assertions.assertArrayEquals(aliceKey, bobKey);
    }


    @Test
    public void ecdhKdf_differentUKM_differentOutput() throws Exception
    {
        KeyPair alice = generateP256();
        KeyPair bob = generateP256();

        byte[] withUkmA = deriveAES("ECDHwithSHA256KDF", alice.getPrivate(), bob.getPublic(),
                new KDFParameterSpec(new byte[]{1, 2, 3, 4}));
        byte[] withUkmB = deriveAES("ECDHwithSHA256KDF", alice.getPrivate(), bob.getPublic(),
                new KDFParameterSpec(new byte[]{5, 6, 7, 8}));

        Assertions.assertFalse(Arrays.areEqual(withUkmA, withUkmB),
                "Different shared info MUST produce different KDF output");
    }


    @Test
    public void ecdhKdf_explicitKeySize_obeyed() throws Exception
    {
        KeyPair alice = generateP256();
        KeyPair bob = generateP256();

        byte[] key128 = deriveAES("ECDHwithSHA256KDF", alice.getPrivate(), bob.getPublic(),
                new KDFParameterSpec(null, 128));
        byte[] key256 = deriveAES("ECDHwithSHA256KDF", alice.getPrivate(), bob.getPublic(),
                new KDFParameterSpec(null, 256));

        Assertions.assertEquals(16, key128.length);
        Assertions.assertEquals(32, key256.length);
        // The 128-bit output must be a prefix of the 256-bit output —
        // X9.63 KDF is iterated-hash producing a deterministic stream,
        // so longer outputs extend shorter ones starting from the same Z.
        for (int i = 0; i < 16; i++)
        {
            Assertions.assertEquals(key128[i], key256[i],
                    "X9.63 KDF stream should extend: byte " + i + " mismatch");
        }
    }


    @Test
    public void ecdhKdf_differentDigests_differentOutput() throws Exception
    {
        KeyPair alice = generateP256();
        KeyPair bob = generateP256();

        byte[] sha256Key = deriveAES("ECDHwithSHA256KDF", alice.getPrivate(), bob.getPublic(), null);
        byte[] sha384Key = deriveAES("ECDHwithSHA384KDF", alice.getPrivate(), bob.getPublic(), null);

        Assertions.assertFalse(Arrays.areEqual(sha256Key, sha384Key),
                "Different digests should produce different KEKs from the same ECDH inputs");
    }


    // -----------------------------------------------------------------
    // Bare ECDHwithKDF — digest from spec, not pinned
    // -----------------------------------------------------------------

    /**
     * The bare {@code ECDHwithKDF} transformation requires the caller
     * to supply the digest via {@link KDFParameterSpec#getDigestAlgorithm}.
     * The derived key must match what the pinned-digest variant would
     * produce for the same inputs.
     */
    @Test
    public void ecdhKdf_bareForm_matchesPinnedForm() throws Exception
    {
        KeyPair alice = generateP256();
        KeyPair bob = generateP256();
        byte[] sharedInfo = new byte[]{1, 2, 3, 4};

        // Drive the bare transformation with a spec carrying SHA-256.
        KeyAgreement bare = KeyAgreement.getInstance("ECDHwithKDF", JostleProvider.PROVIDER_NAME);
        bare.init(alice.getPrivate(), new KDFParameterSpec(sharedInfo, 128, "SHA-256"));
        bare.doPhase(bob.getPublic(), true);
        byte[] keyBare = bare.generateSecret("AES").getEncoded();

        // Drive the pinned-SHA256 transformation with the same inputs.
        byte[] keyPinned = deriveAES("ECDHwithSHA256KDF", alice.getPrivate(), bob.getPublic(),
                new KDFParameterSpec(sharedInfo, 128));

        Assertions.assertArrayEquals(keyPinned, keyBare,
                "bare ECDHwithKDF + spec-SHA256 should match ECDHwithSHA256KDF");
    }

    /**
     * Bare {@code ECDHwithKDF} called WITHOUT a digest in the spec must
     * reject the init — there's no pinned digest to fall back to.
     */
    @Test
    public void ecdhKdf_bareForm_noDigestInSpec_rejected() throws Exception
    {
        KeyPair alice = generateP256();

        KeyAgreement bare = KeyAgreement.getInstance("ECDHwithKDF", JostleProvider.PROVIDER_NAME);
        try
        {
            bare.init(alice.getPrivate(),
                    new KDFParameterSpec(null, 0)); // null digest in 2-arg form
            Assertions.fail("expected InvalidAlgorithmParameterException");
        }
        catch (java.security.InvalidAlgorithmParameterException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().contains("requires a digest"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    /**
     * Bare {@code ECDHwithKDF} called with NO spec at all (the
     * single-arg {@code init(Key)} form) must reject — bare needs a
     * digest, and the no-spec path can't carry one.
     */
    @Test
    public void ecdhKdf_bareForm_noSpec_rejected() throws Exception
    {
        KeyPair alice = generateP256();

        KeyAgreement bare = KeyAgreement.getInstance("ECDHwithKDF", JostleProvider.PROVIDER_NAME);
        try
        {
            bare.init(alice.getPrivate());
            Assertions.fail("expected InvalidKeyException");
        }
        catch (java.security.InvalidKeyException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().contains("requires a digest"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    /**
     * Pinned-digest transformation rejects a spec carrying a
     * different digest — proves the transformation-name contract is
     * binding (a mismatched spec is a caller error, not a silent
     * override).
     */
    @Test
    public void ecdhKdf_pinnedForm_specDigestConflict_rejected() throws Exception
    {
        KeyPair alice = generateP256();

        KeyAgreement ka = KeyAgreement.getInstance("ECDHwithSHA256KDF",
                JostleProvider.PROVIDER_NAME);
        try
        {
            ka.init(alice.getPrivate(),
                    new KDFParameterSpec(null, 0, "SHA-384"));
            Assertions.fail("expected InvalidAlgorithmParameterException");
        }
        catch (java.security.InvalidAlgorithmParameterException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(
                    expected.getMessage().contains("conflicts with"),
                    "unexpected message: " + expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // SPI reset / reuse (CLAUDE.md "Test that the SPI is correctly
    // usable after reset")
    // -----------------------------------------------------------------

    /**
     * Two derives through one KeyAgreement instance with different
     * peers — both must produce the correct KEK. Catches an SPI that
     * doesn't re-init the underlying ECDH ctx properly between calls,
     * or one that caches the X9.63 KDF state.
     */
    @Test
    public void ecdhKdf_TwoDerivesOnSameInstance() throws Exception
    {
        KeyPair alice = generateP256();
        KeyPair bobA = generateP256();
        KeyPair bobB = generateP256();

        KeyAgreement ka = KeyAgreement.getInstance("ECDHwithSHA256KDF", JostleProvider.PROVIDER_NAME);

        ka.init(alice.getPrivate());
        ka.doPhase(bobA.getPublic(), true);
        byte[] k1 = ka.generateSecret("AES").getEncoded();

        // Re-init on same instance with a different peer.
        ka.init(alice.getPrivate());
        ka.doPhase(bobB.getPublic(), true);
        byte[] k2 = ka.generateSecret("AES").getEncoded();

        // Reference computations.
        byte[] k1Ref = deriveAES("ECDHwithSHA256KDF", alice.getPrivate(), bobA.getPublic(), null);
        byte[] k2Ref = deriveAES("ECDHwithSHA256KDF", alice.getPrivate(), bobB.getPublic(), null);

        Assertions.assertArrayEquals(k1Ref, k1, "first reused derive mismatch");
        Assertions.assertArrayEquals(k2Ref, k2, "second reused derive mismatch");
        Assertions.assertFalse(Arrays.areEqual(k1, k2),
                "two different peers should produce two different KEKs");
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static KeyPair generateP256() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        return kpg.generateKeyPair();
    }

    private static byte[] deriveAES(String xform, java.security.PrivateKey priv,
                                    java.security.PublicKey pub, KDFParameterSpec params) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance(xform, JostleProvider.PROVIDER_NAME);
        if (params == null)
        {
            ka.init(priv);
        }
        else
        {
            ka.init(priv, params);
        }
        ka.doPhase(pub, true);
        SecretKey k = ka.generateSecret("AES");
        return k.getEncoded();
    }
}
