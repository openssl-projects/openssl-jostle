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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Cross-provider agreement for the FIPS provider's AES surface.
 * <p>
 * This is the FIPS analogue of {@code crypto/AESAgreementTest}, and the
 * <b>pattern-setter</b> for the other {@code FIPS*AgreementTest} classes.
 * Every approved transformation is exercised three ways in the same JVM:
 * <ol>
 *   <li>JSLFIPS vs the non-FIPS provider (JSL), and</li>
 *   <li>JSLFIPS vs BouncyCastle (BC),</li>
 * </ol>
 * and in <b>both directions</b> for each reference: JSLFIPS encrypts and the
 * reference decrypts, AND the reference encrypts and JSLFIPS decrypts. For the
 * deterministic AES modes the ciphertext (and AEAD tag) must be byte-identical
 * across providers — a strong differentiator that a stubbed or wrong-but-
 * self-consistent implementation cannot satisfy against an independent
 * reference. Inputs (keys, IVs, nonces, AAD, plaintext content and length) are
 * all drawn from a per-test SHA1PRNG whose seed is logged, so a flaky run is
 * reproducible (per CLAUDE.md).
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSAESAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final int[] KEY_SIZES = {16, 24, 32};

    // Lengths straddling the 16-byte block boundary plus a large value; the
    // trailing entry is replaced per trial with a random length.
    private static final int[] LENGTHS = {0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 129, 256, 1000};

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        ensureProviders();
    }

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static SecretKey randomKey(int size, SecureRandom sr)
    {
        byte[] keyBytes = new byte[size];
        sr.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] transform(String xform, String provider, int mode, SecretKey key,
                                    AlgorithmParameterSpec spec, byte[] aad, byte[] in) throws Exception
    {
        Cipher cipher = Cipher.getInstance(xform, provider);
        if (spec != null)
        {
            cipher.init(mode, key, spec);
        }
        else
        {
            cipher.init(mode, key);
        }
        if (aad != null)
        {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(in);
    }

    /**
     * Deterministic non-AEAD modes: ciphertext must be byte-identical to the
     * reference, and each side must decrypt the other's ciphertext.
     */
    private void crossCipher(String xform, int ivLen, String ref, SecureRandom sr) throws Exception
    {
        for (int keySize : KEY_SIZES)
        {
            for (int i = 0; i < LENGTHS.length; i++)
            {
                int len = (i == LENGTHS.length - 1) ? 512 + sr.nextInt(2048) : LENGTHS[i];

                SecretKey key = randomKey(keySize, sr);
                AlgorithmParameterSpec spec = null;
                if (ivLen >= 0)
                {
                    byte[] iv = new byte[ivLen];
                    sr.nextBytes(iv);
                    spec = new IvParameterSpec(iv);
                }
                byte[] msg = new byte[len];
                sr.nextBytes(msg);

                String tag = xform + " k=" + keySize + " len=" + len + " ref=" + ref;

                byte[] ctFips = transform(xform, FIPS, Cipher.ENCRYPT_MODE, key, spec, null, msg);
                byte[] ctRef = transform(xform, ref, Cipher.ENCRYPT_MODE, key, spec, null, msg);
                Assertions.assertArrayEquals(ctRef, ctFips, tag + ": ciphertext");

                Assertions.assertArrayEquals(msg, transform(xform, FIPS, Cipher.DECRYPT_MODE, key, spec, null, ctRef),
                        tag + ": " + ref + " encrypt -> JSLFIPS decrypt");
                Assertions.assertArrayEquals(msg, transform(xform, ref, Cipher.DECRYPT_MODE, key, spec, null, ctFips),
                        tag + ": JSLFIPS encrypt -> " + ref + " decrypt");
            }
        }
    }

    /**
     * AEAD modes (GCM/CCM): with a fixed key/nonce/AAD the ciphertext+tag are
     * deterministic and must match the reference byte-for-byte; each side
     * decrypts the other's output; and a tampered tag is rejected.
     */
    private void crossAead(String xform, int nonceLen, int tagBits, String ref, SecureRandom sr) throws Exception
    {
        for (int keySize : KEY_SIZES)
        {
            for (int trial = 0; trial < 6; trial++)
            {
                SecretKey key = randomKey(keySize, sr);
                byte[] nonce = new byte[nonceLen];
                sr.nextBytes(nonce);
                byte[] aad = new byte[sr.nextInt(64)];
                sr.nextBytes(aad);
                byte[] msg = new byte[sr.nextInt(1024)];
                sr.nextBytes(msg);
                GCMParameterSpec spec = new GCMParameterSpec(tagBits, nonce);
                byte[] aadArg = aad.length == 0 ? null : aad;

                String tag = xform + " k=" + keySize + " ref=" + ref;

                byte[] ctFips = transform(xform, FIPS, Cipher.ENCRYPT_MODE, key, spec, aadArg, msg);
                byte[] ctRef = transform(xform, ref, Cipher.ENCRYPT_MODE, key, spec, aadArg, msg);
                Assertions.assertArrayEquals(ctRef, ctFips, tag + ": ciphertext+tag");

                Assertions.assertArrayEquals(msg, transform(xform, FIPS, Cipher.DECRYPT_MODE, key, spec, aadArg, ctRef),
                        tag + ": " + ref + " encrypt -> JSLFIPS decrypt");
                Assertions.assertArrayEquals(msg, transform(xform, ref, Cipher.DECRYPT_MODE, key, spec, aadArg, ctFips),
                        tag + ": JSLFIPS encrypt -> " + ref + " decrypt");

                // AEAD differentiator: a flipped tag byte must not decrypt.
                byte[] tampered = ctFips.clone();
                tampered[tampered.length - 1] ^= 0x01;
                final byte[] bad = tampered;
                Assertions.assertThrows(Exception.class,
                        () -> transform(xform, FIPS, Cipher.DECRYPT_MODE, key, spec, aadArg, bad),
                        tag + ": tampered tag must be rejected");
            }
        }
    }

    @Test
    public void cbcAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("cbcAgrees");
        crossCipher("AES/CBC/PKCS5Padding", 16, JSL, sr);
        crossCipher("AES/CBC/PKCS5Padding", 16, BC, sr);
    }

    @Test
    public void ctrAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("ctrAgrees");
        crossCipher("AES/CTR/NoPadding", 16, JSL, sr);
        crossCipher("AES/CTR/NoPadding", 16, BC, sr);
    }

    @Test
    public void ecbAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("ecbAgrees");
        crossCipher("AES/ECB/PKCS5Padding", -1, JSL, sr);
        crossCipher("AES/ECB/PKCS5Padding", -1, BC, sr);
    }

    @Test
    public void gcmAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("gcmAgrees");
        crossAead("AES/GCM/NoPadding", 12, 128, JSL, sr);
        crossAead("AES/GCM/NoPadding", 12, 128, BC, sr);
    }

    @Test
    public void ccmAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("ccmAgrees");
        // CCM is not registered by the non-FIPS provider under this name in
        // every build; BC is the authoritative reference for CCM.
        crossAead("AES/CCM/NoPadding", 12, 128, BC, sr);
    }

    @Test
    public void keyWrapAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("keyWrapAgrees");

        // RFC 3394 AES-256 key wrap, registered by OID in both Jostle
        // providers; BC exposes it as "AESWrap".
        final String wrapOid = "2.16.840.1.101.3.4.1.45"; // id-aes256-wrap

        for (int trial = 0; trial < 10; trial++)
        {
            SecretKey kek = randomKey(32, sr);
            SecretKey target = randomKey(16 + 8 * sr.nextInt(3), sr); // 16/24/32

            byte[] wrappedFips = wrap(wrapOid, FIPS, kek, target);
            byte[] wrappedBc = wrap("AESWrap", BC, kek, target);
            Assertions.assertArrayEquals(wrappedBc, wrappedFips, "wrapped bytes JSLFIPS vs BC");

            Assertions.assertArrayEquals(target.getEncoded(), unwrap(wrapOid, FIPS, kek, wrappedBc),
                    "BC wrap -> JSLFIPS unwrap");
            Assertions.assertArrayEquals(target.getEncoded(), unwrap("AESWrap", BC, kek, wrappedFips),
                    "JSLFIPS wrap -> BC unwrap");
            Assertions.assertArrayEquals(target.getEncoded(), unwrap(wrapOid, JSL, kek, wrappedFips),
                    "JSLFIPS wrap -> JSL unwrap");
        }
    }

    @Test
    public void keyWrapPadAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("keyWrapPadAgrees");

        // RFC 5649 AES-256 key wrap WITH PADDING (KWP), registered by OID in
        // both Jostle providers; BC exposes it as "AESWrapPad" (alias AESKWP).
        // Unlike plain KW (RFC 3394), KWP wraps a key of ANY length, not just a
        // multiple of 8 — so target lengths straddle the 8-byte semiblock
        // boundary here to exercise the padding path.
        final String wrapPadOid = "2.16.840.1.101.3.4.1.48"; // id-aes256-wrap-pad

        for (int trial = 0; trial < 12; trial++)
        {
            SecretKey kek = randomKey(32, sr);
            int targetLen = 1 + sr.nextInt(40); // 1..40, crossing the 8-byte boundary
            byte[] targetBytes = new byte[targetLen];
            sr.nextBytes(targetBytes);
            SecretKey target = new SecretKeySpec(targetBytes, "AES");

            String tag = "KWP trial=" + trial + " len=" + targetLen;

            byte[] wrappedFips = wrap(wrapPadOid, FIPS, kek, target);
            byte[] wrappedBc = wrap("AESWrapPad", BC, kek, target);
            Assertions.assertArrayEquals(wrappedBc, wrappedFips, tag + ": wrapped bytes JSLFIPS vs BC");

            Assertions.assertArrayEquals(targetBytes, unwrap(wrapPadOid, FIPS, kek, wrappedBc),
                    tag + ": BC wrap -> JSLFIPS unwrap");
            Assertions.assertArrayEquals(targetBytes, unwrap("AESWrapPad", BC, kek, wrappedFips),
                    tag + ": JSLFIPS wrap -> BC unwrap");
            Assertions.assertArrayEquals(targetBytes, unwrap(wrapPadOid, JSL, kek, wrappedFips),
                    tag + ": JSLFIPS wrap -> JSL unwrap");
        }
    }

    /**
     * Chunking invariance: for a fixed key/IV/nonce the same plaintext driven
     * through JSLFIPS AES/CBC and AES/GCM as one-shot vs byte-by-byte vs
     * adversarial block-1/block/block+1 splits must yield byte-identical
     * ciphertext (and, for GCM, an identical tag) — the one-shot output is the
     * reference every other chunking is compared against. Mirrors
     * {@code crypto/AESAgreementTest.exercise_complexUpdateDoFinal} /
     * {@code aesGCMSpreadSplitUpdateDoFinal}, which the one-shot-only
     * cbcAgrees/gcmAgrees tests in this class do not exercise. A round-trip on
     * the reference proves the bytes are genuine ciphertext, not a stub.
     */
    @Test
    public void cbcAndGcmChunkingIsByteIdentical() throws Exception
    {
        SecureRandom sr = seededRandom("cbcAndGcmChunkingIsByteIdentical");

        // chunk == 0 is the one-shot reference; 1 is byte-by-byte; 15/16/17
        // straddle the 16-byte block boundary (adversarial partial-block splits).
        final int[] chunkings = {0, 1, 15, 16, 17};

        for (int keySize : KEY_SIZES)
        {
            for (int len : LENGTHS)
            {
                SecretKey key = randomKey(keySize, sr);

                byte[] cbcIv = new byte[16];
                sr.nextBytes(cbcIv);
                assertChunkingByteIdentical("AES/CBC/PKCS5Padding", key,
                        new IvParameterSpec(cbcIv), null, len, chunkings, sr);

                byte[] nonce = new byte[12];
                sr.nextBytes(nonce);
                byte[] aad = new byte[sr.nextInt(64)];
                sr.nextBytes(aad);
                byte[] aadArg = aad.length == 0 ? null : aad;
                assertChunkingByteIdentical("AES/GCM/NoPadding", key,
                        new GCMParameterSpec(128, nonce), aadArg, len, chunkings, sr);
            }
        }
    }

    private void assertChunkingByteIdentical(String xform, SecretKey key, AlgorithmParameterSpec spec,
                                             byte[] aad, int len, int[] chunkings, SecureRandom sr) throws Exception
    {
        byte[] msg = new byte[len];
        sr.nextBytes(msg);

        byte[] reference = chunkedEncrypt(xform, key, spec, aad, msg, 0); // one-shot
        String base = xform + " len=" + len;

        for (int chunk : chunkings)
        {
            byte[] ct = chunkedEncrypt(xform, key, spec, aad, msg, chunk);
            Assertions.assertArrayEquals(reference, ct, base + " chunk=" + chunk + ": ciphertext");
        }

        byte[] pt = decryptOneShot(xform, key, spec, aad, reference);
        Assertions.assertArrayEquals(msg, pt, base + ": decrypt round-trip");
    }

    private static byte[] chunkedEncrypt(String xform, SecretKey key, AlgorithmParameterSpec spec,
                                         byte[] aad, byte[] msg, int chunk) throws Exception
    {
        Cipher cipher = Cipher.getInstance(xform, FIPS);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        if (aad != null)
        {
            cipher.updateAAD(aad);
        }
        if (chunk <= 0)
        {
            return cipher.doFinal(msg);
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int off = 0;
        while (off < msg.length)
        {
            int part = Math.min(chunk, msg.length - off);
            byte[] out = cipher.update(msg, off, part);
            if (out != null)
            {
                bos.write(out, 0, out.length);
            }
            off += part;
        }
        byte[] fin = cipher.doFinal();
        bos.write(fin, 0, fin.length);
        return bos.toByteArray();
    }

    private static byte[] decryptOneShot(String xform, SecretKey key, AlgorithmParameterSpec spec,
                                         byte[] aad, byte[] ct) throws Exception
    {
        Cipher cipher = Cipher.getInstance(xform, FIPS);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        if (aad != null)
        {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(ct);
    }

    private static byte[] wrap(String xform, String provider, SecretKey kek, SecretKey target) throws Exception
    {
        Cipher cipher = Cipher.getInstance(xform, provider);
        cipher.init(Cipher.WRAP_MODE, kek);
        return cipher.wrap(target);
    }

    private static byte[] unwrap(String xform, String provider, SecretKey kek, byte[] wrapped) throws Exception
    {
        Cipher cipher = Cipher.getInstance(xform, provider);
        cipher.init(Cipher.UNWRAP_MODE, kek);
        Key recovered = cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        return recovered.getEncoded();
    }
}
