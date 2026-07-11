/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Behaviour-lock for the "OpenSSL is the single source of truth for fixed
 * values" rule (java-spi.md), extended to the FIPS provider ("JSLFIPS") for
 * the length facts that {@code FIPSMDTest.getDigestLengthPerApprovedAlgorithm}
 * and {@code FIPSMacTest.getMacLengthPerApprovedAlgorithm} do NOT already
 * cover: RSA signature length (= modulus size), AES cipher block size and the
 * GCM nonce length reported back through {@code getIV()}, and the ECDH
 * shared-secret length (= EC field size). Each fixed fact is asserted against
 * the value the FIPS module reports for the relevant algorithm/variant, so a
 * transcribed constant that drifts from native truth — or a process-static
 * length cache that served a non-FIPS-probed value to the FIPS consumer — would
 * be caught here. One {@code assertEquals} per approved variant; policy bounds
 * (RSA 2048/16384, the CCM 64-bit BC-parity tag default) are out of scope.
 * Gated on TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSNativeLengthSourcingTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    private static SecretKey randomAesKey(int sizeBytes)
    {
        byte[] keyBytes = new byte[sizeBytes];
        RANDOM.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * An RSA PKCS#1 v1.5 signature is exactly the modulus size in bytes. Sign a
     * random message with FIPS-generated keys of each approved modulus size and
     * assert the emitted signature length equals modulus-bytes — the value the
     * module derives from the key (EVP_PKEY_get_size), not a transcribed
     * constant. Because the keys are FIPS-generated and the signer resolves
     * through JSLFIPS, this also pins that the FIPS consumer sees the FIPS
     * module's reported length (two-lib-ctx isolation).
     */
    @Test
    public void rsaSignatureLengthEqualsModulusSize()
        throws Exception
    {
        ensureProviders();

        int[][] variants = new int[][]{
                {2048, 256},
                {3072, 384},
        };

        for (int[] variant : variants)
        {
            int modulusBits = variant[0];
            int expectedSigBytes = variant[1];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
            kpg.initialize(modulusBits);
            KeyPair kp = kpg.generateKeyPair();

            byte[] message = new byte[1 + RANDOM.nextInt(1024)];
            RANDOM.nextBytes(message);

            Signature signer = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
            signer.initSign(kp.getPrivate());
            signer.update(message);
            byte[] sig = signer.sign();

            Assertions.assertEquals(expectedSigBytes, sig.length,
                    "RSA-" + modulusBits + " signature length must equal modulus size");

            // Differentiator: the length is that of a REAL signature, not a
            // fixed-size stub buffer — it verifies, and a tampered message does
            // not.
            Signature verifier = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
            verifier.initVerify(kp.getPublic());
            verifier.update(message);
            Assertions.assertTrue(verifier.verify(sig),
                    "RSA-" + modulusBits + " signature must verify (length lock must measure a real signature)");
            byte[] tampered = message.clone();
            tampered[RANDOM.nextInt(tampered.length)] ^= (byte) 0x01;
            Signature bad = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
            bad.initVerify(kp.getPublic());
            bad.update(tampered);
            Assertions.assertFalse(bad.verify(sig), "tampered message must not verify");
        }
    }

    /**
     * AES reports a 16-byte block size for every mode it exposes, independent
     * of key/IV/init state. Locks the block-size fact reported at the JCE
     * surface for each approved mode.
     */
    @Test
    public void aesBlockSizeIsSixteenForEveryMode()
        throws Exception
    {
        ensureProviders();

        SecretKey key = randomAesKey(16);

        // Modes taking an explicit IV / auto-IV in ENCRYPT mode.
        String[] ivModes = {"AES/ECB/NoPadding", "AES/CBC/PKCS5Padding", "AES/CTR/NoPadding"};
        for (String transform : ivModes)
        {
            Cipher c = Cipher.getInstance(transform, JostleFIPSProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, key);
            Assertions.assertEquals(16, c.getBlockSize(), "block size for " + transform);
        }

        // AEAD modes require a tag+nonce spec at init.
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        String[] aeadModes = {"AES/GCM/NoPadding", "AES/CCM/NoPadding"};
        for (String transform : aeadModes)
        {
            Cipher c = Cipher.getInstance(transform, JostleFIPSProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, key, spec);
            Assertions.assertEquals(16, c.getBlockSize(), "block size for " + transform);
        }
    }

    /**
     * The GCM nonce handed in at init is reported back verbatim through
     * {@code getIV()}; a 12-byte nonce yields a 12-byte {@code getIV()}. Locks
     * the SPI's IV pass-through length at the FIPS surface.
     */
    @Test
    public void aesGcmIvLengthIsTwelve()
        throws Exception
    {
        ensureProviders();

        SecretKey key = randomAesKey(32);
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));

        byte[] iv = c.getIV();
        Assertions.assertEquals(12, iv.length, "GCM getIV() length");

        // Differentiator: the cipher actually transforms — encrypt/decrypt
        // round-trips, ciphertext differs from plaintext, and a tampered tag is
        // rejected (guards against a copy-input / fixed-output stub).
        byte[] pt = new byte[64];
        RANDOM.nextBytes(pt);
        byte[] ct = c.doFinal(pt);
        Assertions.assertFalse(java.util.Arrays.equals(pt, java.util.Arrays.copyOf(ct, pt.length)),
                "GCM ciphertext must differ from plaintext");
        Cipher d = Cipher.getInstance("AES/GCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        d.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        Assertions.assertArrayEquals(pt, d.doFinal(ct), "GCM must round-trip");
        byte[] bad = ct.clone();
        bad[bad.length - 1] ^= 0x01;
        Cipher d2 = Cipher.getInstance("AES/GCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        d2.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        Assertions.assertThrows(Exception.class, () -> d2.doFinal(bad),
                "a tampered GCM tag must be rejected");
    }

    /**
     * A raw ECDH shared secret is exactly the curve's field size in bytes.
     * Generate two FIPS-provider keypairs per approved curve, run ECDH, and
     * assert the derived secret length equals field-bytes — the module-derived
     * field size, not a transcribed table.
     */
    @Test
    public void ecdhSharedSecretLengthEqualsFieldSize()
        throws Exception
    {
        ensureProviders();

        Object[][] curves = new Object[][]{
                {"secp256r1", 32},
                {"secp384r1", 48},
                {"secp521r1", 66}, // ceil(521/8)
        };

        for (Object[] row : curves)
        {
            String curve = (String) row[0];
            int expectedSecretBytes = (Integer) row[1];

            KeyPair alice = generateEc(curve);
            KeyPair bob = generateEc(curve);

            byte[] secret = agree(alice.getPrivate(), bob.getPublic());
            Assertions.assertEquals(expectedSecretBytes, secret.length,
                    "ECDH shared-secret length for " + curve);
        }
    }

    private static KeyPair generateEc(String curve)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static byte[] agree(java.security.PrivateKey priv, java.security.PublicKey peerPub)
        throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleFIPSProvider.PROVIDER_NAME);
        ka.init(priv);
        ka.doPhase(peerPub, true);
        return ka.generateSecret();
    }
}
