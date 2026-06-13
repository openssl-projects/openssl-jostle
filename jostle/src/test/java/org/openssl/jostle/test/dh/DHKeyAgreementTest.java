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

package org.openssl.jostle.test.dh;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * JCE-level tests for the DH KeyAgreement SPI.
 *
 * <p>Covers Jostle↔Jostle agreement, BouncyCastle agreement in both
 * directions (byte-identical shared secrets — this is what pins the
 * padded-output contract), the padding hard guard, state-machine
 * misuse, wrong-key rejection, group-mismatch rejection, the
 * offset-write contract of {@code generateSecret(byte[], int)}, and
 * post-derive reuse.
 */
public class DHKeyAgreementTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

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

    private static KeyPair generateKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static byte[] agree(String provider, PrivateKey priv, PublicKey pub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("DH", provider);
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }


    // -----------------------------------------------------------------
    // Jostle ↔ Jostle
    // -----------------------------------------------------------------

    @Test
    public void testDh_BothSidesAgree() throws Exception
    {
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();

        byte[] secretA = agree(JostleProvider.PROVIDER_NAME, a.getPrivate(), b.getPublic());
        byte[] secretB = agree(JostleProvider.PROVIDER_NAME, b.getPrivate(), a.getPublic());

        Assertions.assertArrayEquals(secretA, secretB,
                "both sides must derive the same shared secret");
        Assertions.assertEquals(2048 / 8, secretA.length,
                "shared secret must be padded to the prime length");
    }

    @Test
    public void testDh_DifferentPeers_differentSecrets() throws Exception
    {
        // Negative path: the secret must actually depend on the peer.
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();
        KeyPair c = generateKeyPair();

        byte[] secretAB = agree(JostleProvider.PROVIDER_NAME, a.getPrivate(), b.getPublic());
        byte[] secretAC = agree(JostleProvider.PROVIDER_NAME, a.getPrivate(), c.getPublic());

        Assertions.assertFalse(Arrays.areEqual(secretAB, secretAC),
                "agreements with different peers must produce different secrets");
    }


    // -----------------------------------------------------------------
    // BouncyCastle agreement (both directions, multiple trials)
    // -----------------------------------------------------------------

    @Test
    public void testDh_BCAgreement_byteIdenticalSecrets() throws Exception
    {
        // 25 trials: byte-identity across providers is also what pins
        // the padded-output contract — an unpadded Jostle secret would
        // mismatch BC's p-length output on any trial whose secret has
        // a leading zero byte (~9% chance over 25 trials), and the
        // explicit length assertion below catches it deterministically.
        KeyPair seedKp = generateKeyPair();
        DHParameterSpec params = ((DHPublicKey) seedKp.getPublic()).getParams();
        int pLen = (params.getP().bitLength() + 7) / 8;

        KeyFactory bcKf = KeyFactory.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new DHParameterSpec(params.getP(), params.getG()));
        KeyFactory joKf = KeyFactory.getInstance("DH", JostleProvider.PROVIDER_NAME);

        KeyPairGenerator joKpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        joKpg.initialize(new DHParameterSpec(params.getP(), params.getG()));

        for (int trial = 0; trial < 25; trial++)
        {
            KeyPair joKp = joKpg.generateKeyPair();
            KeyPair bcKp = bcKpg.generateKeyPair();

            // Jostle private + BC public (imported into Jostle).
            PublicKey bcPubInJo = joKf.generatePublic(
                    new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));
            byte[] joSecret = agree(JostleProvider.PROVIDER_NAME,
                    joKp.getPrivate(), bcPubInJo);

            // BC private + Jostle public (imported into BC).
            PublicKey joPubInBc = bcKf.generatePublic(
                    new X509EncodedKeySpec(joKp.getPublic().getEncoded()));
            byte[] bcSecret = agree(BouncyCastleProvider.PROVIDER_NAME,
                    bcKp.getPrivate(), joPubInBc);

            Assertions.assertEquals(pLen, joSecret.length,
                    "trial " + trial + ": Jostle secret must be p-length");
            Assertions.assertArrayEquals(joSecret, bcSecret,
                    "trial " + trial + ": Jostle and BC must derive byte-identical secrets");
        }
    }

    /**
     * Hard guard for the padded-output contract (the {@code pad = 1}
     * exchange parameter in {@code dh_kex_init}): hunt for an agreement
     * whose shared secret has a leading zero byte and assert its length
     * is STILL the prime length. With the parameter removed, OpenSSL
     * strips leading zeros and this test fails deterministically on the
     * found case. Capped at 2000 fresh peers (P(miss) ≈ 0.04%); skips
     * via plain pass if no leading-zero secret turns up.
     */
    @Test
    public void testDh_SharedSecretPadding_HardGuard() throws Exception
    {
        KeyPair fixed = generateKeyPair();
        DHParameterSpec params = ((DHPublicKey) fixed.getPublic()).getParams();
        int pLen = (params.getP().bitLength() + 7) / 8;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new DHParameterSpec(params.getP(), params.getG()));

        for (int i = 0; i < 2000; i++)
        {
            KeyPair peer = kpg.generateKeyPair();
            byte[] secret = agree(JostleProvider.PROVIDER_NAME,
                    fixed.getPrivate(), peer.getPublic());
            // Every secret must be exactly p-length, leading zero or not.
            Assertions.assertEquals(pLen, secret.length,
                    "iteration " + i + ": secret not padded to prime length");
            if (secret[0] == 0)
            {
                // Found the case that distinguishes padded from
                // unpadded output — the length assertion above already
                // proved the property on it.
                System.out.println("padding hard guard hit leading-zero secret at iteration " + i);
                return;
            }
        }
        System.out.println("padding hard guard: no leading-zero secret in 2000 trials (pass)");
    }


    // -----------------------------------------------------------------
    // State machine
    // -----------------------------------------------------------------

    @Test
    public void testDh_GenerateSecretBeforeDoPhase_isIllegalState() throws Exception
    {
        KeyPair kp = generateKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        ka.init(kp.getPrivate());
        try
        {
            ka.generateSecret();
            Assertions.fail("generateSecret before doPhase must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("DH: must call doPhase before generateSecret",
                    expected.getMessage());
        }
    }

    @Test
    public void testDh_DoPhaseBeforeInit_isIllegalState() throws Exception
    {
        KeyPair kp = generateKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        try
        {
            ka.doPhase(kp.getPublic(), true);
            Assertions.fail("doPhase before init must throw");
        }
        catch (IllegalStateException expected)
        {
            // The JCE layer itself guards uninitialised doPhase, so the
            // message comes from the JDK; type is the contract here.
            Assertions.assertNotNull(expected.getMessage());
        }
    }

    @Test
    public void testDh_NotLastPhase_isIllegalState() throws Exception
    {
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        ka.init(a.getPrivate());
        try
        {
            ka.doPhase(b.getPublic(), false);
            Assertions.fail("lastPhase=false must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals(
                    "DH is a single-phase protocol here; lastPhase must be true",
                    expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // Wrong keys
    // -----------------------------------------------------------------

    @Test
    public void testDh_RejectsForeignPrivateKey() throws Exception
    {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        try
        {
            ka.init(rsa.getPrivate());
            Assertions.fail("expected InvalidKeyException for RSA private key");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("DH init: expected a DHPrivateKey", expected.getMessage());
        }
    }

    @Test
    public void testDh_RejectsForeignPublicKeyAtDoPhase() throws Exception
    {
        KeyPair dh = generateKeyPair();
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        ka.init(dh.getPrivate());
        try
        {
            ka.doPhase(rsa.getPublic(), true);
            Assertions.fail("expected InvalidKeyException for RSA public key");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("DH doPhase: expected a DHPublicKey", expected.getMessage());
        }
    }

    @Test
    public void testDh_GroupMismatch_rejectedAtDoPhase() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair k2048 = kpg.generateKeyPair();
        kpg.initialize(3072);
        KeyPair k3072 = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        ka.init(k2048.getPrivate());
        try
        {
            ka.doPhase(k3072.getPublic(), true);
            Assertions.fail("expected InvalidKeyException for group mismatch");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().startsWith("DH doPhase: peer key rejected"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    /**
     * A SunJCE DH key must be accepted via the translate-on-init path.
     */
    @Test
    public void testDh_AcceptsForeignDHKey_viaTranslate() throws Exception
    {
        KeyPair joKp = generateKeyPair();
        DHParameterSpec params = ((DHPublicKey) joKp.getPublic()).getParams();

        KeyPairGenerator sunKpg = KeyPairGenerator.getInstance("DH", "SunJCE");
        sunKpg.initialize(new DHParameterSpec(params.getP(), params.getG()));
        KeyPair sunKp = sunKpg.generateKeyPair();

        byte[] secretA = agree(JostleProvider.PROVIDER_NAME,
                sunKp.getPrivate(), joKp.getPublic());
        byte[] secretB = agree(JostleProvider.PROVIDER_NAME,
                joKp.getPrivate(), sunKp.getPublic());

        Assertions.assertArrayEquals(secretA, secretB,
                "agreement with translated SunJCE keys must match");
    }


    // -----------------------------------------------------------------
    // generateSecret(byte[], int) offset contract
    // -----------------------------------------------------------------

    @Test
    public void testDh_GenerateSecretAtOffset_prefixUntouchedAndFunctional() throws Exception
    {
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();

        // Reference secret via the allocating form.
        byte[] expected = agree(JostleProvider.PROVIDER_NAME, a.getPrivate(), b.getPublic());

        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        ka.init(a.getPrivate());
        ka.doPhase(b.getPublic(), true);

        int prefix = 7;
        byte[] big = new byte[prefix + expected.length + 5];
        RANDOM.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        int written = ka.generateSecret(big, prefix);
        Assertions.assertEquals(expected.length, written);

        // (1) Prefix untouched.
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                "generateSecret modified bytes preceding the offset");

        // (2) Functional check: the window at the offset is the secret.
        byte[] window = new byte[written];
        System.arraycopy(big, prefix, window, 0, written);
        Assertions.assertArrayEquals(expected, window,
                "secret at offset must equal the allocating-form secret");

        // (3) A window shifted one byte into the prefix must differ.
        byte[] shifted = new byte[written];
        System.arraycopy(big, prefix - 1, shifted, 0, written);
        Assertions.assertFalse(Arrays.areEqual(expected, shifted),
                "window shifted by 1 matched — wrote at offset-1");
    }

    @Test
    public void testDh_GenerateSecretShortBuffer_throws() throws Exception
    {
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        ka.init(a.getPrivate());
        ka.doPhase(b.getPublic(), true);

        // Boundary probe: secret is 256 bytes (2048-bit p); a buffer
        // one byte short from the offset must be rejected.
        byte[] small = new byte[256];
        try
        {
            ka.generateSecret(small, 1);
            Assertions.fail("expected ShortBufferException");
        }
        catch (ShortBufferException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().startsWith("DH generateSecret: buffer needs"),
                    "unexpected message: " + expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // generateSecret(String) and reuse
    // -----------------------------------------------------------------

    @Test
    public void testDh_GenerateSecretKey_namedAlgorithm() throws Exception
    {
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        ka.init(a.getPrivate());
        ka.doPhase(b.getPublic(), true);
        SecretKey key = ka.generateSecret("TlsPremasterSecret");
        Assertions.assertEquals("TlsPremasterSecret", key.getAlgorithm());
        Assertions.assertEquals(256, key.getEncoded().length);
    }

    @Test
    public void testDh_GenerateSecretKey_blankAlgorithm_rejected() throws Exception
    {
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        ka.init(a.getPrivate());
        ka.doPhase(b.getPublic(), true);
        try
        {
            ka.generateSecret("   ");
            Assertions.fail("expected NoSuchAlgorithmException for blank algorithm name");
        }
        catch (java.security.NoSuchAlgorithmException expected)
        {
            Assertions.assertEquals("algorithm name must be non-null and non-blank",
                    expected.getMessage());
        }
    }

    @Test
    public void testDh_ReuseAfterGenerateSecret() throws Exception
    {
        // JCE contract: generateSecret resets the KA to its post-init
        // state; a fresh doPhase against a different peer must work and
        // must change the derived secret.
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();
        KeyPair c = generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        ka.init(a.getPrivate());

        ka.doPhase(b.getPublic(), true);
        byte[] secretAB = ka.generateSecret();
        Assertions.assertArrayEquals(
                agree(JostleProvider.PROVIDER_NAME, b.getPrivate(), a.getPublic()),
                secretAB);

        ka.doPhase(c.getPublic(), true);
        byte[] secretAC = ka.generateSecret();
        Assertions.assertArrayEquals(
                agree(JostleProvider.PROVIDER_NAME, c.getPrivate(), a.getPublic()),
                secretAC);

        Assertions.assertFalse(Arrays.areEqual(secretAB, secretAC),
                "reused KeyAgreement must track the new peer");
    }
}
