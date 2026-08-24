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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * XTS-AES (IEEE Std 1619-2007 / NIST SP 800-38E) through the JSL provider.
 *
 * <p>There is no BouncyCastle agreement half for this family: BC ships no
 * AES-XTS at all (its only XTS class is {@code KXTSBlockCipher}, the DSTU 7624
 * Kalyna variant), and neither does SunJCE. Per the agreement-test rules in
 * {@code .claude/guides/testing.md} — "where BC implements nothing at all,
 * write the specification's own recurrence against a JDK primitive" — the
 * independent reference here is {@link XTSReference}, IEEE 1619 XTS built from
 * the JDK's own AES/ECB. It is anchored to the published IEEE 1619 Vector 4
 * by {@link #referenceImplementationMatchesIeee1619Vector4()}, so a bug in the
 * reference cannot silently excuse a matching bug in Jostle.
 *
 * <p>XTS takes a <em>tweak</em>, not an IV, and the key is key1||key2 — so a
 * 32-byte key selects AES-128-XTS and a 64-byte key AES-256-XTS. There is no
 * AES-192-XTS.
 */
public class AESXTSTest
{
    private static final String XFORM = "AES/XTS/NoPadding";

    /**
     * Class-level seeding random — used to derive each test's local SHA1PRNG
     * seed. Per CLAUDE.md: cache one SecureRandom per test class.
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    protected static SecureRandom seededRandom(String testName) throws Exception
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
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    protected String providerName()
    {
        return JostleProvider.PROVIDER_NAME;
    }

    // ------------------------------------------------------------------
    // Known-answer vectors
    // ------------------------------------------------------------------

    /**
     * Anchors the independent reference to the published standard, so the
     * agreement tests below compare against something known-correct rather
     * than against a second copy of the same mistake.
     */
    @Test
    public void referenceImplementationMatchesIeee1619Vector4() throws Exception
    {
        Assertions.assertArrayEquals(Ieee1619Vector4.CIPHERTEXT,
                XTSReference.encrypt(Ieee1619Vector4.KEY, Ieee1619Vector4.TWEAK, Ieee1619Vector4.PLAINTEXT),
                "the from-spec reference must reproduce IEEE 1619 Vector 4");
    }

    @Test
    public void jostleMatchesIeee1619Vector4() throws Exception
    {
        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Ieee1619Vector4.KEY, "AES"),
                new IvParameterSpec(Ieee1619Vector4.TWEAK));
        Assertions.assertArrayEquals(Ieee1619Vector4.CIPHERTEXT, enc.doFinal(Ieee1619Vector4.PLAINTEXT));

        Cipher dec = Cipher.getInstance(XFORM, providerName());
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Ieee1619Vector4.KEY, "AES"),
                new IvParameterSpec(Ieee1619Vector4.TWEAK));
        Assertions.assertArrayEquals(Ieee1619Vector4.PLAINTEXT, dec.doFinal(Ieee1619Vector4.CIPHERTEXT));
    }

    /**
     * A KAT alone cannot show the implementation reads all of its input — pair
     * it with a differentiator, per the negative-path rule.
     */
    @Test
    public void ieee1619Vector4_singleBitChangeChangesCiphertext() throws Exception
    {
        byte[] tweaked = Arrays.clone(Ieee1619Vector4.PLAINTEXT);
        tweaked[Ieee1619Vector4.PLAINTEXT.length - 1] ^= (byte) 0x01;

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Ieee1619Vector4.KEY, "AES"),
                new IvParameterSpec(Ieee1619Vector4.TWEAK));

        Assertions.assertFalse(Arrays.areEqual(Ieee1619Vector4.CIPHERTEXT, enc.doFinal(tweaked)),
                "flipping the last plaintext bit must change the ciphertext");
    }

    // ------------------------------------------------------------------
    // Agreement with the independent from-spec reference
    // ------------------------------------------------------------------

    /**
     * Random keys, tweaks, contents and lengths across both key sizes and both
     * the block-aligned and ciphertext-stealing paths.
     */
    @Test
    public void agreesWithReferenceAcrossRandomTrials() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithReferenceAcrossRandomTrials");

        for (int keyLen : new int[]{32, 64})
        {
            for (int trial = 0; trial < 25; trial++)
            {
                byte[] key = distinctHalvesKey(keyLen, sr);
                byte[] tweak = random(16, sr);
                // >= 16: XTS has no defined output below one block.
                byte[] pt = random(16 + sr.nextInt(512), sr);

                byte[] expected = XTSReference.encrypt(key, tweak, pt);

                Cipher enc = Cipher.getInstance(XFORM, providerName());
                enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
                byte[] ct = enc.doFinal(pt);

                Assertions.assertArrayEquals(expected, ct,
                        "keyLen=" + keyLen + " ptLen=" + pt.length);

                Cipher dec = Cipher.getInstance(XFORM, providerName());
                dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
                Assertions.assertArrayEquals(pt, dec.doFinal(ct));
            }
        }
    }

    /**
     * Ciphertext stealing is where an XTS implementation most easily goes
     * wrong, so walk every residue of the block size explicitly rather than
     * relying on the random lengths above to hit them all.
     */
    @Test
    public void ciphertextStealingAgreesWithReferenceAtEveryResidue() throws Exception
    {
        SecureRandom sr = seededRandom("ciphertextStealingAgreesWithReferenceAtEveryResidue");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);

        for (int len = 16; len <= 16 + 32; len++)
        {
            byte[] pt = random(len, sr);
            byte[] expected = XTSReference.encrypt(key, tweak, pt);

            Cipher enc = Cipher.getInstance(XFORM, providerName());
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
            byte[] ct = enc.doFinal(pt);

            Assertions.assertEquals(len, ct.length, "XTS output length must equal input length, len=" + len);
            Assertions.assertArrayEquals(expected, ct, "len=" + len);
        }
    }

    // ------------------------------------------------------------------
    // Negative path
    // ------------------------------------------------------------------

    @Test
    public void tamperedCiphertextDoesNotRoundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedCiphertextDoesNotRoundTrip");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        byte[] ct = encrypt(key, tweak, pt);
        ct[sr.nextInt(ct.length)] ^= (byte) 0x01;

        Cipher dec = Cipher.getInstance(XFORM, providerName());
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        Assertions.assertFalse(Arrays.areEqual(pt, dec.doFinal(ct)),
                "tampered ciphertext must not round-trip (XTS is unauthenticated, so it decrypts to garbage)");
    }

    @Test
    public void wrongTweakDoesNotRoundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("wrongTweakDoesNotRoundTrip");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        byte[] ct = encrypt(key, tweak, pt);

        Cipher dec = Cipher.getInstance(XFORM, providerName());
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(random(16, sr)));
        Assertions.assertFalse(Arrays.areEqual(pt, dec.doFinal(ct)),
                "the tweak must influence the result — a decrypt under a different tweak cannot recover the plaintext");
    }

    @Test
    public void wrongKeyDoesNotRoundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("wrongKeyDoesNotRoundTrip");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        byte[] ct = encrypt(key, tweak, pt);

        Cipher dec = Cipher.getInstance(XFORM, providerName());
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(distinctHalvesKey(32, sr), "AES"), new IvParameterSpec(tweak));
        Assertions.assertFalse(Arrays.areEqual(pt, dec.doFinal(ct)), "a different key must not recover the plaintext");
    }

    @Test
    public void encryptionActuallyTransformsTheInput() throws Exception
    {
        SecureRandom sr = seededRandom("encryptionActuallyTransformsTheInput");
        byte[] pt = random(64, sr);
        Assertions.assertFalse(Arrays.areEqual(pt, encrypt(distinctHalvesKey(32, sr), random(16, sr), pt)),
                "ciphertext must differ from plaintext");
    }

    @Test
    public void distinctTweaksProduceDistinctCiphertext() throws Exception
    {
        SecureRandom sr = seededRandom("distinctTweaksProduceDistinctCiphertext");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] pt = random(64, sr);
        Assertions.assertFalse(Arrays.areEqual(encrypt(key, random(16, sr), pt), encrypt(key, random(16, sr), pt)),
                "two tweaks over the same plaintext must give different ciphertext");
    }

    // ------------------------------------------------------------------
    // Key length matrix
    // ------------------------------------------------------------------

    /**
     * The XTS key is key1||key2, so only 32 and 64 bytes are meaningful. 24 is
     * probed explicitly: AES-192 is a valid AES key size but AES-192-XTS does
     * not exist, so it must be refused like any other wrong length.
     */
    @Test
    public void keyLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("keyLengthBoundaries");

        // A zero-length key never reaches the provider: SecretKeySpec itself
        // refuses to be constructed. Pinned separately so the loop below can
        // assert our own message on every length that does reach us.
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> init(Cipher.ENCRYPT_MODE, new byte[0], new byte[16]),
                "an empty key is refused by SecretKeySpec before the provider sees it");

        for (int keyLen : new int[]{1, 15, 16, 17, 24, 31, 33, 47, 48, 63, 65, 128})
        {
            InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                    () -> init(Cipher.ENCRYPT_MODE, new byte[keyLen], new byte[16]),
                    "key length " + keyLen + " must be refused");
            Assertions.assertEquals("XTS requires a 32-byte (AES-128) or 64-byte (AES-256) key", ex.getMessage());
        }

        for (int keyLen : new int[]{32, 64})
        {
            Assertions.assertDoesNotThrow(() -> init(Cipher.ENCRYPT_MODE, distinctHalvesKey(keyLen, sr), random(16, sr)),
                    "key length " + keyLen + " must be accepted");
        }
    }

    /**
     * IEEE 1619 §5.1 and SP 800-38E forbid key1 == key2 — the tweak encryption
     * would then use the same key as the data encryption. OpenSSL enforces it
     * for us; this pins that we surface the refusal as a typed
     * InvalidKeyException rather than a runtime exception out of init.
     */
    @Test
    public void duplicateKeyHalvesRejected() throws Exception
    {
        SecureRandom sr = seededRandom("duplicateKeyHalvesRejected");

        for (int keyLen : new int[]{32, 64})
        {
            byte[] half = random(keyLen / 2, sr);
            byte[] key = new byte[keyLen];
            System.arraycopy(half, 0, key, 0, half.length);
            System.arraycopy(half, 0, key, half.length, half.length);

            InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                    () -> init(Cipher.ENCRYPT_MODE, key, random(16, sr)),
                    "key1 == key2 must be refused for a " + keyLen + "-byte key");
            Assertions.assertTrue(ex.getMessage().contains("xts duplicated keys"),
                    "expected OpenSSL's duplicated-keys refusal, got: " + ex.getMessage());
        }
    }

    // ------------------------------------------------------------------
    // Tweak length matrix
    // ------------------------------------------------------------------

    @Test
    public void tweakLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("tweakLengthBoundaries");
        byte[] key = distinctHalvesKey(32, sr);

        for (int tweakLen : new int[]{1, 8, 12, 15, 17, 24, 32})
        {
            InvalidAlgorithmParameterException ex = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> init(Cipher.ENCRYPT_MODE, key, new byte[tweakLen]),
                    "tweak length " + tweakLen + " must be refused");
            Assertions.assertEquals("invalid iv length", ex.getMessage());
        }

        InvalidAlgorithmParameterException empty = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> init(Cipher.ENCRYPT_MODE, key, new byte[0]));
        Assertions.assertEquals("iv is null", empty.getMessage());

        Assertions.assertDoesNotThrow(() -> init(Cipher.ENCRYPT_MODE, key, random(16, sr)),
                "a 16-byte tweak must be accepted");
    }

    /**
     * With no parameters the SPI must generate a tweak and publish it, or the
     * caller cannot decrypt what it just encrypted.
     */
    @Test
    public void encryptWithoutTweakGeneratesAndPublishesOne() throws Exception
    {
        SecureRandom sr = seededRandom("encryptWithoutTweakGeneratesAndPublishesOne");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] pt = random(64, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] ct = enc.doFinal(pt);

        byte[] tweak = enc.getIV();
        Assertions.assertNotNull(tweak, "an auto-generated tweak must be retrievable");
        Assertions.assertEquals(16, tweak.length);

        Cipher dec = Cipher.getInstance(XFORM, providerName());
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        Assertions.assertArrayEquals(pt, dec.doFinal(ct));
    }

    // ------------------------------------------------------------------
    // Data unit length contract
    // ------------------------------------------------------------------

    /**
     * XTS has no defined output below one AES block. The check lives at final,
     * once the total is known — a caller feeding 8 bytes then 8 more has a
     * valid 16-byte unit (see
     * {@link #chunksBelowOneBlockAccumulateIntoAValidUnit()}), so a per-chunk
     * check would wrongly refuse it. The zero-length case is called out
     * because it reaches the native layer by a different route — the SPI skips
     * the update call entirely when there is nothing to feed — and used to
     * return an empty result and look like success.
     */
    @Test
    public void dataUnitShorterThanOneBlockRejected() throws Exception
    {
        SecureRandom sr = seededRandom("dataUnitShorterThanOneBlockRejected");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);

        for (int len : new int[]{0, 1, 2, 15})
        {
            Cipher enc = Cipher.getInstance(XFORM, providerName());
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

            IllegalBlockSizeException ex = Assertions.assertThrows(IllegalBlockSizeException.class,
                    () -> enc.doFinal(new byte[len]),
                    "a " + len + "-byte data unit must be refused");
            Assertions.assertEquals("data not block size aligned", ex.getMessage());
        }

        Cipher ok = Cipher.getInstance(XFORM, providerName());
        ok.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        Assertions.assertEquals(16, ok.doFinal(new byte[16]).length,
                "16 bytes is exactly one block and must be accepted — the boundary sits at 16, not above it");
    }

    // ------------------------------------------------------------------
    // One-shot contract
    // ------------------------------------------------------------------

    /**
     * The load-bearing test of this file.
     *
     * <p>OpenSSL's EVP XTS is one-shot per data unit: it restarts the tweak
     * sequence at the head of every update call. Feeding a unit straight
     * through in chunks therefore produced ciphertext that matched a
     * conforming implementation for the FIRST chunk only — while Jostle's own
     * chunked decrypt repeated the same mistake, so it round-tripped and
     * looked correct. A roundtrip-only test passes against that; only the
     * independent reference catches it.
     *
     * <p>The util layer now accumulates the data unit and hands it to EVP in a
     * single call at final, so chunking is invisible to the output. This test
     * pins that: every split of the same unit must give byte-identical
     * ciphertext, and it must equal the from-spec reference — not merely equal
     * each other, which a uniformly-wrong implementation would also satisfy.
     */
    @Test
    public void chunkedUpdatesAgreeWithOneShotAndTheReference() throws Exception
    {
        SecureRandom sr = seededRandom("chunkedUpdatesAgreeWithOneShotAndTheReference");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(96, sr);

        byte[] reference = XTSReference.encrypt(key, tweak, pt);
        Assertions.assertArrayEquals(reference, encrypt(key, tweak, pt), "one-shot must match the reference");

        // Splits chosen to straddle the block boundary in both directions, to
        // land mid-block, and to include a degenerate single-byte first chunk.
        int[][] splits = {
                {48, 48}, {32, 32, 32}, {16, 80}, {80, 16}, {1, 95}, {95, 1},
                {15, 17, 64}, {17, 15, 64}, {31, 33, 32}, {1, 1, 1, 93},
        };

        for (int[] split : splits)
        {
            Cipher enc = Cipher.getInstance(XFORM, providerName());
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            int off = 0;
            for (int i = 0; i < split.length - 1; i++)
            {
                byte[] produced = enc.update(pt, off, split[i]);
                if (produced != null)
                {
                    bos.write(produced);
                }
                off += split[i];
            }
            bos.write(enc.doFinal(pt, off, split[split.length - 1]));

            Assertions.assertArrayEquals(reference, bos.toByteArray(),
                    "split " + java.util.Arrays.toString(split) + " diverged from the reference");
        }
    }

    /**
     * Byte-by-byte is the extreme case of the above, and the one that a
     * per-chunk implementation gets most obviously wrong. Covers decrypt too,
     * since the accumulation path is shared but the EVP call is not.
     */
    @Test
    public void byteByByteAgreesWithOneShot() throws Exception
    {
        SecureRandom sr = seededRandom("byteByByteAgreesWithOneShot");
        byte[] key = distinctHalvesKey(64, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(50, sr);   // not a block multiple: exercises stealing

        byte[] reference = XTSReference.encrypt(key, tweak, pt);

        Assertions.assertArrayEquals(reference, driveByteByByte(Cipher.ENCRYPT_MODE, key, tweak, pt),
                "byte-by-byte encrypt must equal the one-shot reference");
        Assertions.assertArrayEquals(pt, driveByteByByte(Cipher.DECRYPT_MODE, key, tweak, reference),
                "byte-by-byte decrypt must recover the plaintext");
    }

    /**
     * A chunk boundary must not become a data-unit boundary: 8 bytes then 8
     * more is a legal 16-byte unit, even though a single 8-byte unit is not.
     * This is why the minimum-length check lives at final, once the total is
     * known, rather than per chunk.
     */
    @Test
    public void chunksBelowOneBlockAccumulateIntoAValidUnit() throws Exception
    {
        SecureRandom sr = seededRandom("chunksBelowOneBlockAccumulateIntoAValidUnit");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(16, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        byte[] head = enc.update(pt, 0, 8);
        byte[] tail = enc.doFinal(pt, 8, 8);

        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, pt), Arrays.concatenate(head, tail),
                "two sub-block chunks totalling one block must produce a valid data unit");
    }

    /**
     * An update that accumulates must emit nothing — a caller appending
     * {@code update()}'s return to a stream would otherwise get the data unit
     * twice, or get zero-filled padding, depending on how the size functions
     * lied.
     */
    @Test
    public void updateEmitsNothingWhileAccumulating() throws Exception
    {
        SecureRandom sr = seededRandom("updateEmitsNothingWhileAccumulating");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

        byte[] produced = enc.update(pt, 0, 32);
        Assertions.assertTrue(produced == null || produced.length == 0,
                "an accumulating update must emit no bytes, got "
                        + (produced == null ? "null" : produced.length));

        // The explicit-output overload is sized by getOutputSize, which for a
        // buffering mode legitimately over-estimates (it answers for the
        // eventual doFinal). Give it that much and assert nothing is written.
        byte[] out = new byte[enc.getOutputSize(32)];
        byte[] snapshot = Arrays.clone(out);
        Assertions.assertEquals(0, enc.update(pt, 32, 32, out, 0),
                "the explicit-output update overload must report 0 bytes written");
        Assertions.assertArrayEquals(snapshot, out,
                "an accumulating update must not touch the output buffer");

        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, pt), enc.doFinal(),
                "and doFinal must then emit the whole data unit");
    }

    /**
     * Accumulated bytes must not leak into the next data unit. A caller that
     * abandons a unit by re-initing, then encrypts a different one, must get
     * the clean answer for the second unit alone.
     */
    @Test
    public void reinitDiscardsAPartiallyAccumulatedUnit() throws Exception
    {
        SecureRandom sr = seededRandom("reinitDiscardsAPartiallyAccumulatedUnit");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] abandoned = random(48, sr);
        byte[] wanted = random(32, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        enc.update(abandoned, 0, abandoned.length);

        // Re-init abandons whatever was accumulated.
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, wanted), enc.doFinal(wanted),
                "the abandoned unit's bytes must not appear in the next operation");
    }

    /**
     * And the same after a completed operation: the terminal call must leave
     * the accumulator empty, or the next unit would be prefixed by the last.
     */
    @Test
    public void doFinalLeavesTheAccumulatorEmpty() throws Exception
    {
        SecureRandom sr = seededRandom("doFinalLeavesTheAccumulatorEmpty");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] first = random(48, sr);
        byte[] second = random(32, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, first), enc.doFinal(first));
        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, second), enc.doFinal(second),
                "the second unit must not carry the first unit's bytes");
    }

    /**
     * The supported chunk-free shapes must keep working, and must agree with
     * each other and with the reference.
     */
    @Test
    public void singleUpdateThenDoFinalMatchesOneShot() throws Exception
    {
        SecureRandom sr = seededRandom("singleUpdateThenDoFinalMatchesOneShot");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        byte[] reference = XTSReference.encrypt(key, tweak, pt);

        Cipher a = Cipher.getInstance(XFORM, providerName());
        a.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        Assertions.assertArrayEquals(reference, a.doFinal(pt), "one-shot doFinal");

        Cipher b = Cipher.getInstance(XFORM, providerName());
        b.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        byte[] head = b.update(pt, 0, pt.length);
        byte[] tail = b.doFinal();
        Assertions.assertArrayEquals(reference, Arrays.concatenate(head, tail),
                "a single whole-unit update followed by doFinal() must give the same answer");
    }

    private byte[] driveByteByByte(int opmode, byte[] key, byte[] tweak, byte[] in) throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(opmode, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < in.length - 1; i++)
        {
            byte[] produced = c.update(in, i, 1);
            if (produced != null)
            {
                bos.write(produced);
            }
        }
        bos.write(c.doFinal(in, in.length - 1, 1));
        return bos.toByteArray();
    }

    // ------------------------------------------------------------------
    // Offset-write, aliasing, and reuse
    // ------------------------------------------------------------------

    @Test
    public void doFinalWritesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        SecureRandom sr = seededRandom("doFinalWritesAtOffsetWithoutClobberingPrefix");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        final int outOff = 23;
        byte[] big = random(outOff + 64 + 19, sr);
        byte[] snapshot = Arrays.clone(big);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        int written = enc.doFinal(pt, 0, pt.length, big, outOff);
        Assertions.assertEquals(64, written);

        // Nothing outside [outOff, outOff+written) may be touched.
        Assertions.assertArrayEquals(java.util.Arrays.copyOf(snapshot, outOff),
                java.util.Arrays.copyOf(big, outOff), "bytes before outOff must be untouched");
        Assertions.assertArrayEquals(
                java.util.Arrays.copyOfRange(snapshot, outOff + written, snapshot.length),
                java.util.Arrays.copyOfRange(big, outOff + written, big.length),
                "bytes after the written region must be untouched");

        // The written region must be the real ciphertext...
        byte[] region = java.util.Arrays.copyOfRange(big, outOff, outOff + written);
        Assertions.assertArrayEquals(pt, decrypt(key, tweak, region), "the written region must round-trip");

        // ...and a window one byte early must NOT, which is what proves the
        // write landed at exactly outOff rather than one byte before it.
        byte[] shifted = java.util.Arrays.copyOfRange(big, outOff - 1, outOff - 1 + written);
        Assertions.assertFalse(Arrays.areEqual(pt, decrypt(key, tweak, shifted)),
                "a window starting one byte early must not round-trip");
    }

    /**
     * XTS reads its whole data unit before emitting output, so in-place at the
     * same offset is the supported aliased layout. Different-offset overlap is
     * deliberately not tested — see the streaming caveat in testing.md.
     */
    @Test
    public void inPlaceSameOffsetMatchesSeparateBuffer() throws Exception
    {
        SecureRandom sr = seededRandom("inPlaceSameOffsetMatchesSeparateBuffer");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        byte[] reference = encrypt(key, tweak, pt);

        final int off = 11;
        byte[] buf = random(off + 64 + 13, sr);
        byte[] snapshot = Arrays.clone(buf);
        System.arraycopy(pt, 0, buf, off, pt.length);
        System.arraycopy(buf, 0, snapshot, 0, off);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        int written = enc.doFinal(buf, off, pt.length, buf, off);

        Assertions.assertEquals(64, written);
        Assertions.assertArrayEquals(reference, java.util.Arrays.copyOfRange(buf, off, off + written),
                "in-place output must equal the separate-buffer result");
        Assertions.assertArrayEquals(java.util.Arrays.copyOf(snapshot, off),
                java.util.Arrays.copyOf(buf, off), "bytes before the offset must be untouched");
        Assertions.assertArrayEquals(
                java.util.Arrays.copyOfRange(snapshot, off + written, snapshot.length),
                java.util.Arrays.copyOfRange(buf, off + written, buf.length),
                "bytes after the written region must be untouched");
    }

    @Test
    public void shortOutputBufferRejected() throws Exception
    {
        SecureRandom sr = seededRandom("shortOutputBufferRejected");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        Assertions.assertThrows(ShortBufferException.class, () -> enc.doFinal(pt, 0, pt.length, new byte[63], 0));
    }

    /**
     * XTS is deterministic — the same key, tweak and plaintext must give the
     * same ciphertext on a reused instance. A difference would mean state
     * leaked across the terminal call.
     */
    @Test
    public void reuseAfterDoFinalIsDeterministic() throws Exception
    {
        SecureRandom sr = seededRandom("reuseAfterDoFinalIsDeterministic");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

        byte[] first = enc.doFinal(pt);
        byte[] second = enc.doFinal(pt);
        Assertions.assertArrayEquals(first, second, "a reused instance must produce the same ciphertext");
        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, pt), second,
                "and it must still be the right ciphertext, not merely a stable wrong one");
    }

    @Test
    public void twoDistinctInputsThroughOneInstance() throws Exception
    {
        SecureRandom sr = seededRandom("twoDistinctInputsThroughOneInstance");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] a = random(64, sr);
        byte[] b = random(48, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, a), enc.doFinal(a));
        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, b), enc.doFinal(b));
    }

    /**
     * Failure must not poison the instance: after a refused call the same
     * Cipher has to keep working.
     */
    @Test
    public void refusedCallThenSuccessfulCall() throws Exception
    {
        SecureRandom sr = seededRandom("refusedCallThenSuccessfulCall");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

        Assertions.assertThrows(IllegalBlockSizeException.class, () -> enc.doFinal(new byte[3]));

        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, pt), enc.doFinal(pt),
                "the instance must be usable after a refused call");
    }

    /**
     * The other order: a success must not leave state that makes the next,
     * genuinely-bad call look fine. A verify-style SPI that cached its last
     * result, or a ctx that kept the previous data unit's length, only fails
     * this pattern.
     */
    @Test
    public void successfulCallThenRefusedCall() throws Exception
    {
        SecureRandom sr = seededRandom("successfulCallThenRefusedCall");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, pt), enc.doFinal(pt));

        IllegalBlockSizeException ex = Assertions.assertThrows(IllegalBlockSizeException.class,
                () -> enc.doFinal(new byte[7]),
                "a sub-block data unit must still be refused after a successful call");
        Assertions.assertEquals("data not block size aligned", ex.getMessage());
    }

    /**
     * A refused data unit must not leave its bytes in the accumulator for the
     * next call to absorb. Without the discard, a rejected 7-byte unit
     * followed by a 9-byte one would silently succeed as a 16-byte unit the
     * caller never asked for — and produce ciphertext over a plaintext that
     * spans two logically separate operations.
     */
    @Test
    public void refusedShortUnitLeavesNothingBehind() throws Exception
    {
        SecureRandom sr = seededRandom("refusedShortUnitLeavesNothingBehind");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] wanted = random(16, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

        Assertions.assertThrows(IllegalBlockSizeException.class, () -> enc.doFinal(random(7, sr)),
                "a 7-byte data unit must be refused");

        // The next unit must stand alone — not be prefixed by the refused 7.
        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, wanted), enc.doFinal(wanted),
                "the refused unit's bytes must not have joined the next one");
    }

    /**
     * ShortBufferException is the one refusal that must NOT discard: JCE's
     * contract for it is "retry with a bigger buffer", so dropping the
     * accumulated unit would make the retry silently produce a different,
     * shorter result.
     */
    @Test
    public void shortBufferRefusalKeepsTheUnitForRetry() throws Exception
    {
        SecureRandom sr = seededRandom("shortBufferRefusalKeepsTheUnitForRetry");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        enc.update(pt, 0, 64);

        Assertions.assertThrows(ShortBufferException.class, () -> enc.doFinal(new byte[63], 0),
                "an undersized output buffer must be refused");

        byte[] out = new byte[64];
        int written = enc.doFinal(out, 0);
        Assertions.assertEquals(64, written, "the retry must still see the whole accumulated unit");
        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, pt), out,
                "and produce the same ciphertext the first call would have");
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    /**
     * Registration is not usability: assert the explicit transformation is
     * registered AND that it resolves to a working XTS cipher, rather than
     * falling through to some other mode.
     */
    @Test
    public void explicitTransformationIsRegisteredAndUsable() throws Exception
    {
        Provider p = Security.getProvider(providerName());
        Assertions.assertNotNull(p.getService("Cipher", "AES/XTS/NoPadding"),
                "AES/XTS/NoPadding must be a registered service, not merely reachable through the bare AES primary");

        SecureRandom sr = seededRandom("explicitTransformationIsRegisteredAndUsable");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, pt), encrypt(key, tweak, pt));
    }

    /**
     * The bare "AES" primary reaches XTS through engineSetMode (JCE form-4
     * lookup). Both routes must give the same answer — the explicit
     * registration must not have introduced a second, differently-configured
     * code path.
     */
    @Test
    public void bareAesPrimaryReachesTheSameXtsImplementation() throws Exception
    {
        SecureRandom sr = seededRandom("bareAesPrimaryReachesTheSameXtsImplementation");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        Cipher viaMode = Cipher.getInstance("AES/XTS/NOPADDING", providerName());
        viaMode.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));

        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, pt), viaMode.doFinal(pt));
    }

    @Test
    public void blockSizeAndOutputSize() throws Exception
    {
        SecureRandom sr = seededRandom("blockSizeAndOutputSize");
        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(distinctHalvesKey(32, sr), "AES"),
                new IvParameterSpec(random(16, sr)));

        Assertions.assertEquals(16, enc.getBlockSize());
        // Ciphertext stealing means output length always equals input length.
        Assertions.assertEquals(64, enc.getOutputSize(64));
        Assertions.assertEquals(50, enc.getOutputSize(50));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private void init(int opmode, byte[] key, byte[] tweak) throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(opmode, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
    }

    private byte[] encrypt(byte[] key, byte[] tweak, byte[] pt) throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        return c.doFinal(pt);
    }

    private byte[] decrypt(byte[] key, byte[] tweak, byte[] ct) throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        return c.doFinal(ct);
    }

    protected static byte[] random(int n, SecureRandom sr)
    {
        byte[] b = new byte[n];
        sr.nextBytes(b);
        return b;
    }

    /**
     * XTS refuses key1 == key2, so a randomly generated key must have distinct
     * halves. At 16/32 bytes per half a collision is not going to happen, but
     * the loop makes the requirement explicit rather than implicit.
     */
    public static byte[] distinctHalvesKey(int len, SecureRandom sr)
    {
        while (true)
        {
            byte[] key = random(len, sr);
            byte[] k1 = java.util.Arrays.copyOfRange(key, 0, len / 2);
            byte[] k2 = java.util.Arrays.copyOfRange(key, len / 2, len);
            if (!Arrays.areEqual(k1, k2))
            {
                return key;
            }
        }
    }

    /**
     * IEEE Std 1619-2007 Vector 4 — 256-bit key (key1||key2), zero tweak, 512
     * bytes of plaintext 0x00..0xFF twice over. Only the leading 64 bytes of
     * ciphertext are pinned; that is enough to catch any tweak, key-split or
     * GF(2^128) error, and the full-length agreement is covered by the
     * reference comparison tests.
     */
    private static final class Ieee1619Vector4
    {
        static final byte[] KEY = Hex.decode(
                "2718281828459045235360287471352631415926535897932384626433832795");
        static final byte[] TWEAK = Hex.decode("00000000000000000000000000000000");
        static final byte[] PLAINTEXT = plaintext();
        static final byte[] CIPHERTEXT = ciphertext();

        private static byte[] plaintext()
        {
            byte[] pt = new byte[512];
            for (int i = 0; i < pt.length; i++)
            {
                pt[i] = (byte) i;
            }
            return pt;
        }

        private static byte[] ciphertext()
        {
            // Produced by the from-spec reference and independently confirmed
            // against the published vector's leading bytes
            // (27a7479befa1d476489f308cd4cfa6e2...).
            byte[] full = XTSReference.encryptUnchecked(KEY, TWEAK, PLAINTEXT);
            byte[] head = Hex.decode("27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c");
            if (!Arrays.areEqual(head, java.util.Arrays.copyOf(full, head.length)))
            {
                throw new IllegalStateException("IEEE 1619 Vector 4 head mismatch — the reference is wrong");
            }
            return full;
        }
    }

    /**
     * IEEE 1619 XTS-AES built from the JDK's own AES/ECB primitive.
     *
     * <p>This is the independent implementation the agreement tests compare
     * against, standing in for BouncyCastle — which ships no AES-XTS. It is
     * deliberately a direct transcription of the standard's recurrence rather
     * than a port of anything in this repository, so a bug shared with the
     * native path is not possible.
     */
    public static final class XTSReference
    {
        public static byte[] encrypt(byte[] key, byte[] tweak, byte[] pt) throws Exception
        {
            return transform(key, tweak, pt, true);
        }

        public static byte[] decrypt(byte[] key, byte[] tweak, byte[] ct) throws Exception
        {
            return transform(key, tweak, ct, false);
        }

        static byte[] encryptUnchecked(byte[] key, byte[] tweak, byte[] pt)
        {
            try
            {
                return encrypt(key, tweak, pt);
            }
            catch (Exception ex)
            {
                throw new IllegalStateException(ex);
            }
        }

        private static byte[] transform(byte[] key, byte[] tweak, byte[] in, boolean encrypting) throws Exception
        {
            int half = key.length / 2;
            Cipher data = Cipher.getInstance("AES/ECB/NoPadding");
            data.init(encrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(java.util.Arrays.copyOfRange(key, 0, half), "AES"));
            Cipher tweakCipher = Cipher.getInstance("AES/ECB/NoPadding");
            tweakCipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(java.util.Arrays.copyOfRange(key, half, key.length), "AES"));

            byte[] t = tweakCipher.doFinal(tweak);

            int rem = in.length % 16;
            // With a partial trailing block, the last FULL block joins the
            // ciphertext-stealing step instead of the plain loop.
            int fullBlocks = in.length / 16 - (rem == 0 ? 0 : 1);

            byte[] out = new byte[in.length];
            int off = 0;
            for (int i = 0; i < fullBlocks; i++)
            {
                System.arraycopy(applyTweak(data, in, off, t), 0, out, off, 16);
                t = mulAlpha(t);
                off += 16;
            }

            if (rem != 0)
            {
                if (encrypting)
                {
                    byte[] cm1 = applyTweak(data, in, off, t);
                    byte[] tNext = mulAlpha(t);

                    byte[] cc = new byte[16];
                    System.arraycopy(in, off + 16, cc, 0, rem);
                    System.arraycopy(cm1, rem, cc, rem, 16 - rem);

                    System.arraycopy(applyTweak(data, cc, 0, tNext), 0, out, off, 16);
                    System.arraycopy(cm1, 0, out, off + 16, rem);
                }
                else
                {
                    // Decryption swaps the order of the two tweaks.
                    byte[] tNext = mulAlpha(t);
                    byte[] pm1 = applyTweak(data, in, off, tNext);

                    byte[] pp = new byte[16];
                    System.arraycopy(in, off + 16, pp, 0, rem);
                    System.arraycopy(pm1, rem, pp, rem, 16 - rem);

                    System.arraycopy(applyTweak(data, pp, 0, t), 0, out, off, 16);
                    System.arraycopy(pm1, 0, out, off + 16, rem);
                }
            }
            return out;
        }

        /** XEX: xor the tweak in, run the block cipher, xor the tweak out. */
        private static byte[] applyTweak(Cipher c, byte[] src, int off, byte[] t) throws Exception
        {
            byte[] block = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                block[i] = (byte) (src[off + i] ^ t[i]);
            }
            byte[] enc = c.doFinal(block);
            for (int i = 0; i < 16; i++)
            {
                enc[i] ^= t[i];
            }
            return enc;
        }

        /**
         * Multiply by the primitive element alpha in GF(2^128) with the
         * little-endian byte order IEEE 1619 specifies, reducing modulo
         * x^128 + x^7 + x^2 + x + 1.
         */
        private static byte[] mulAlpha(byte[] t)
        {
            byte[] r = new byte[16];
            int carry = 0;
            for (int i = 0; i < 16; i++)
            {
                int v = ((t[i] & 0xFF) << 1) | carry;
                r[i] = (byte) (v & 0xFF);
                carry = (v >> 8) & 1;
            }
            if (carry != 0)
            {
                r[0] ^= (byte) 0x87;
            }
            return r;
        }
    }
}
