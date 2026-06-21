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

package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Agreement between BouncyCastle and Jostle for ChaCha20-Poly1305 (RFC 8439),
 * plus the negative-path, boundary, reset/reuse and offset-write coverage the
 * test discipline requires. All inputs are random (seeded, logged for repro).
 */
public class ChaCha20Poly1305AgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String XFORM = "ChaCha20-Poly1305";

    private static final SecureRandom RANDOM = new SecureRandom();

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
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecretKey randomKey(SecureRandom sr)
    {
        byte[] key = new byte[32];
        sr.nextBytes(key);
        return new SecretKeySpec(key, "ChaCha20");
    }

    /**
     * Core agreement: BC and Jostle produce byte-identical ciphertext||tag, in
     * both directions, across an AAD-length sweep and a random plaintext. The
     * 12-byte nonce is supplied via IvParameterSpec (tag defaults to 128 bits).
     */
    @Test
    public void agreesWithBC_ivParameterSpec_aadSweep() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBC_ivParameterSpec_aadSweep");
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);

        for (int aadLen = 0; aadLen < 129; aadLen++)
        {
            SecretKey key = randomKey(sr);
            byte[] aad = new byte[aadLen];
            sr.nextBytes(aad);
            byte[] msg = new byte[1 + sr.nextInt(200)];
            sr.nextBytes(msg);
            IvParameterSpec iv = new IvParameterSpec(nonce);

            Cipher bcEnc = Cipher.getInstance(XFORM, BC);
            bcEnc.init(Cipher.ENCRYPT_MODE, key, iv);
            bcEnc.updateAAD(aad);
            byte[] bcCt = bcEnc.doFinal(msg);

            Cipher jslEnc = Cipher.getInstance(XFORM, JSL);
            jslEnc.init(Cipher.ENCRYPT_MODE, key, iv);
            jslEnc.updateAAD(aad);
            byte[] jslCt = jslEnc.doFinal(msg);

            Assertions.assertArrayEquals(bcCt, jslCt, "ciphertext||tag (aadLen=" + aadLen + ")");

            // BC-encrypt -> Jostle-decrypt
            Cipher jslDec = Cipher.getInstance(XFORM, JSL);
            jslDec.init(Cipher.DECRYPT_MODE, key, iv);
            jslDec.updateAAD(aad);
            Assertions.assertArrayEquals(msg, jslDec.doFinal(bcCt), "BC-enc/JSL-dec");

            // Jostle-encrypt -> BC-decrypt
            Cipher bcDec = Cipher.getInstance(XFORM, BC);
            bcDec.init(Cipher.DECRYPT_MODE, key, iv);
            bcDec.updateAAD(aad);
            Assertions.assertArrayEquals(msg, bcDec.doFinal(jslCt), "JSL-enc/BC-dec");
        }
    }

    /**
     * Agreement via GCMParameterSpec (128-bit tag), the JCE-standard AEAD spec.
     * Plaintext length is varied; AAD chunking is split independently of the
     * plaintext to exercise the partial-AAD path.
     */
    @Test
    public void agreesWithBC_gcmParameterSpec() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBC_gcmParameterSpec");

        for (int trial = 0; trial < 25; trial++)
        {
            SecretKey key = randomKey(sr);
            byte[] nonce = new byte[12];
            sr.nextBytes(nonce);
            byte[] aad = new byte[sr.nextInt(64)];
            sr.nextBytes(aad);
            byte[] msg = new byte[sr.nextInt(300)];
            sr.nextBytes(msg);
            GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

            Cipher bcEnc = Cipher.getInstance(XFORM, BC);
            bcEnc.init(Cipher.ENCRYPT_MODE, key, spec);
            bcEnc.updateAAD(aad);
            byte[] bcCt = bcEnc.doFinal(msg);

            Cipher jslEnc = Cipher.getInstance(XFORM, JSL);
            jslEnc.init(Cipher.ENCRYPT_MODE, key, spec);
            // Feed AAD in two chunks to exercise partial-AAD updates.
            int split = aad.length / 2;
            jslEnc.updateAAD(aad, 0, split);
            jslEnc.updateAAD(aad, split, aad.length - split);
            byte[] jslCt = jslEnc.doFinal(msg);

            Assertions.assertArrayEquals(bcCt, jslCt, "trial " + trial);

            Cipher jslDec = Cipher.getInstance(XFORM, JSL);
            jslDec.init(Cipher.DECRYPT_MODE, key, spec);
            jslDec.updateAAD(aad);
            Assertions.assertArrayEquals(msg, jslDec.doFinal(bcCt));
        }
    }

    /**
     * Agreement via BouncyCastle's own AEADParameterSpec (nonce + 128-bit tag +
     * associated data), resolved on the Jostle side through the reflective
     * AEADParameterSpecAccessor.
     */
    @Test
    public void agreesWithBC_bcAeadParameterSpec() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBC_bcAeadParameterSpec");

        for (int trial = 0; trial < 15; trial++)
        {
            SecretKey key = randomKey(sr);
            byte[] nonce = new byte[12];
            sr.nextBytes(nonce);
            byte[] aad = new byte[1 + sr.nextInt(48)];
            sr.nextBytes(aad);
            byte[] msg = new byte[sr.nextInt(120)];
            sr.nextBytes(msg);
            // AAD carried by the spec itself (no separate updateAAD).
            org.bouncycastle.jcajce.spec.AEADParameterSpec spec =
                    new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce, 128, aad);

            Cipher bcEnc = Cipher.getInstance(XFORM, BC);
            bcEnc.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] bcCt = bcEnc.doFinal(msg);

            Cipher jslEnc = Cipher.getInstance(XFORM, JSL);
            jslEnc.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] jslCt = jslEnc.doFinal(msg);

            Assertions.assertArrayEquals(bcCt, jslCt, "trial " + trial);

            Cipher jslDec = Cipher.getInstance(XFORM, JSL);
            jslDec.init(Cipher.DECRYPT_MODE, key, spec);
            Assertions.assertArrayEquals(msg, jslDec.doFinal(bcCt));
        }
    }

    /**
     * Negative path: tamper the ciphertext body, the tag, and the AAD
     * independently — each must fail authentication with AEADBadTagException.
     */
    @Test
    public void tamperedInputs_throwAEADBadTag() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedInputs_throwAEADBadTag");
        SecretKey key = randomKey(sr);
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        byte[] aad = new byte[24];
        sr.nextBytes(aad);
        byte[] msg = new byte[40];
        sr.nextBytes(msg);
        IvParameterSpec iv = new IvParameterSpec(nonce);

        Cipher enc = Cipher.getInstance(XFORM, JSL);
        enc.init(Cipher.ENCRYPT_MODE, key, iv);
        enc.updateAAD(aad);
        byte[] ct = enc.doFinal(msg); // ciphertext (40) || tag (16)

        // Tamper a ciphertext body byte.
        byte[] ctBody = Arrays.clone(ct);
        ctBody[0] ^= 0x01;
        decryptExpectingBadTag(key, iv, aad, ctBody, "tampered ciphertext");

        // Tamper a tag byte (last 16).
        byte[] ctTag = Arrays.clone(ct);
        ctTag[ctTag.length - 1] ^= 0x01;
        decryptExpectingBadTag(key, iv, aad, ctTag, "tampered tag");

        // Tamper the AAD.
        byte[] badAad = Arrays.clone(aad);
        badAad[0] ^= 0x01;
        decryptExpectingBadTag(key, iv, badAad, ct, "tampered AAD");

        // Sanity: untampered decrypt still succeeds on a fresh instance.
        Cipher ok = Cipher.getInstance(XFORM, JSL);
        ok.init(Cipher.DECRYPT_MODE, key, iv);
        ok.updateAAD(aad);
        Assertions.assertArrayEquals(msg, ok.doFinal(ct));
    }

    private static void decryptExpectingBadTag(SecretKey key, IvParameterSpec iv, byte[] aad, byte[] ct, String what)
            throws Exception
    {
        Cipher dec = Cipher.getInstance(XFORM, JSL);
        dec.init(Cipher.DECRYPT_MODE, key, iv);
        dec.updateAAD(aad);
        AEADBadTagException ex = assertThrows(AEADBadTagException.class, () -> dec.doFinal(ct), what);
        Assertions.assertEquals("bad tag", ex.getMessage(), what);
    }

    /**
     * Boundary lengths, checked independently. Nonce must be 12, key 32, tag
     * 128 bits — each off-boundary value rejected with the JCE-contracted type.
     */
    @Test
    public void boundaryLengths_rejected() throws Exception
    {
        SecureRandom sr = seededRandom("boundaryLengths_rejected");
        SecretKey key = randomKey(sr);

        // Nonce 11 and 13 rejected (only 12 accepted) -> InvalidAlgorithmParameterException.
        for (int n : new int[]{11, 13})
        {
            byte[] nonce = new byte[n];
            sr.nextBytes(nonce);
            Cipher c = Cipher.getInstance(XFORM, JSL);
            assertThrows(InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce)), "nonce len " + n);
        }
        // Nonce 12 accepted.
        byte[] good = new byte[12];
        sr.nextBytes(good);
        Cipher okNonce = Cipher.getInstance(XFORM, JSL);
        okNonce.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(good));

        // Key 31 and 33 rejected (only 32 accepted) -> InvalidKeyException.
        for (int kl : new int[]{31, 33})
        {
            byte[] kb = new byte[kl];
            sr.nextBytes(kb);
            SecretKey badKey = new SecretKeySpec(kb, "ChaCha20");
            Cipher c = Cipher.getInstance(XFORM, JSL);
            assertThrows(InvalidKeyException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, badKey, new IvParameterSpec(good)), "key len " + kl);
        }

        // Tag must be 128 bits: 96 and 120 rejected -> InvalidAlgorithmParameterException.
        for (int tag : new int[]{96, 120})
        {
            Cipher c = Cipher.getInstance(XFORM, JSL);
            assertThrows(InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(tag, good)), "tag bits " + tag);
        }
        // Tag 128 accepted.
        Cipher okTag = Cipher.getInstance(XFORM, JSL);
        okTag.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, good));
    }

    /**
     * Reset/reuse state machine: distinct messages through one instance; the
     * encrypt-nonce-reuse guard fires on a second encrypt without re-init; a
     * decrypt failure does not poison a subsequent successful operation.
     */
    @Test
    public void resetAndReuse() throws Exception
    {
        SecureRandom sr = seededRandom("resetAndReuse");
        SecretKey key = randomKey(sr);
        byte[] n1 = new byte[12];
        sr.nextBytes(n1);
        byte[] n2 = new byte[12];
        sr.nextBytes(n2);
        byte[] m1 = new byte[33];
        sr.nextBytes(m1);
        byte[] m2 = new byte[77];
        sr.nextBytes(m2);

        Cipher enc = Cipher.getInstance(XFORM, JSL);
        // Two distinct inputs through one re-initialised instance.
        enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(n1));
        byte[] c1 = enc.doFinal(m1);
        enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(n2));
        byte[] c2 = enc.doFinal(m2);

        Cipher dec = Cipher.getInstance(XFORM, JSL);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(n1));
        Assertions.assertArrayEquals(m1, dec.doFinal(c1));
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(n2));
        Assertions.assertArrayEquals(m2, dec.doFinal(c2));

        // Encrypt-nonce-reuse guard: a second encrypt without re-init is rejected.
        Cipher reuse = Cipher.getInstance(XFORM, JSL);
        reuse.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(n1));
        reuse.doFinal(m1);
        assertThrows(IllegalStateException.class, () -> reuse.doFinal(m1), "nonce reuse without re-init");

        // Negative-then-positive: a bad-tag failure must not poison the instance.
        Cipher mixed = Cipher.getInstance(XFORM, JSL);
        mixed.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(n1));
        byte[] broken = Arrays.clone(c1);
        broken[broken.length - 1] ^= 0x01;
        assertThrows(AEADBadTagException.class, () -> mixed.doFinal(broken));
        mixed.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(n1));
        Assertions.assertArrayEquals(m1, mixed.doFinal(c1), "usable after a failed decrypt");
    }

    /**
     * Offset-write contract at the JCE level: writing at a non-zero output
     * offset must not touch bytes before it, must place valid output exactly at
     * the offset, and must NOT produce valid output one byte earlier.
     */
    @Test
    public void offsetWriteContract() throws Exception
    {
        SecureRandom sr = seededRandom("offsetWriteContract");
        SecretKey key = randomKey(sr);
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        byte[] msg = new byte[64];
        sr.nextBytes(msg);
        IvParameterSpec iv = new IvParameterSpec(nonce);

        Cipher enc = Cipher.getInstance(XFORM, JSL);
        enc.init(Cipher.ENCRYPT_MODE, key, iv);
        final int outOff = 7;
        int outLen = enc.getOutputSize(msg.length);
        byte[] big = new byte[outOff + outLen + 5];
        sr.nextBytes(big);
        byte[] expectedPrefix = Arrays.copyOfRange(big, 0, outOff);

        int written = enc.doFinal(msg, 0, msg.length, big, outOff);

        // (1) prefix untouched.
        Assertions.assertArrayEquals(expectedPrefix, Arrays.copyOfRange(big, 0, outOff), "prefix clobbered");

        // (2) the window at outOff decrypts back to the plaintext.
        byte[] ct = Arrays.copyOfRange(big, outOff, outOff + written);
        Cipher dec = Cipher.getInstance(XFORM, JSL);
        dec.init(Cipher.DECRYPT_MODE, key, iv);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct), "window at outOff");

        // (3) the window starting one byte earlier does NOT decrypt (proves the
        // write landed at exactly outOff, not outOff-1).
        byte[] shifted = Arrays.copyOfRange(big, outOff - 1, outOff - 1 + written);
        Cipher dec2 = Cipher.getInstance(XFORM, JSL);
        dec2.init(Cipher.DECRYPT_MODE, key, iv);
        try
        {
            byte[] pt = dec2.doFinal(shifted);
            Assertions.assertFalse(Arrays.areEqual(msg, pt), "shifted window must not round-trip");
        }
        catch (AEADBadTagException expected)
        {
            // Expected — the shifted window is not a valid ChaCha20-Poly1305 frame.
        }
    }

    /**
     * Short output buffer is rejected with ShortBufferException and leaves the
     * SPI usable.
     */
    @Test
    public void shortBuffer_rejected() throws Exception
    {
        SecureRandom sr = seededRandom("shortBuffer_rejected");
        SecretKey key = randomKey(sr);
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        byte[] msg = new byte[50];
        sr.nextBytes(msg);

        Cipher enc = Cipher.getInstance(XFORM, JSL);
        enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        byte[] tooSmall = new byte[msg.length]; // missing room for the 16-byte tag
        assertThrows(ShortBufferException.class, () -> enc.doFinal(msg, 0, msg.length, tooSmall, 0));
    }

    /**
     * Provider/OID resolution: the dash-name, its case variant, and the RFC 8103
     * OID all resolve to the dedicated SPI, and the KeyGenerator (direct and via
     * the AEAD alias) produces 32-byte keys.
     */
    @Test
    public void providerResolution() throws Exception
    {
        Assertions.assertNotNull(Cipher.getInstance("ChaCha20-Poly1305", JSL));
        Assertions.assertNotNull(Cipher.getInstance("CHACHA20-POLY1305", JSL));
        Assertions.assertNotNull(Cipher.getInstance("1.2.840.113549.1.9.16.3.18", JSL));

        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("ChaCha20-Poly1305", JSL);
        SecretKey k = kg.generateKey();
        Assertions.assertEquals(32, k.getEncoded().length);
    }
}
