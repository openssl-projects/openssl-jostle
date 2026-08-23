/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/**
 * AES-GMAC (NIST SP 800-38D) agreement between the Jostle base provider and
 * BouncyCastle, plus the surface behaviour the two must share.
 * <p>
 * GMAC is GCM run with no plaintext, so every input byte is absorbed as AAD
 * and the tag is a deterministic function of (key, IV, message). That makes
 * byte-equality against an independent implementation the strongest available
 * check, and it is the one used throughout: a stubbed, truncated or
 * IV-ignoring implementation cannot match BC's tag.
 * <p>
 * Both providers spell the algorithm the same way. BC's
 * {@code SymmetricAlgorithmProvider.addGMacAlgorithm} registers
 * {@code Mac.AES-GMAC} with an {@code AESGMAC} alias, and {@code ProvMac}
 * mirrors that pair, so every test below runs against both spellings.
 * <p>
 * Facts pinned here that were MEASURED rather than assumed
 * ({@code fips-c-review/probes/gmac_probe.c}, 2026-08-23, against mainline
 * 3.6.2 and both supported FIPS modules):
 * <ul>
 *   <li>GMAC inherits GCM's <b>variable-length</b> nonce. 1, 8, 11, 12, 13, 16
 *       and 32 bytes are all accepted; only a zero-length IV is refused, by
 *       OpenSSL itself. A "12 bytes only" assumption would have been wrong.</li>
 *   <li>The tag length is <b>fixed</b> at the GCM block size and cannot be
 *       configured: {@code size} does not appear in
 *       {@code EVP_MAC_CTX_settable_params}, so setting
 *       {@code OSSL_MAC_PARAM_SIZE} is silently ignored. A
 *       {@code GCMParameterSpec} asking for a shorter tag is therefore refused
 *       rather than quietly served a full-length one — and BC, which CAN
 *       truncate, is the reference proving 128 is the value we must match.</li>
 * </ul>
 * Inputs (keys, IVs, message content and length) come from a per-test SHA1PRNG
 * whose seed is logged, so a flaky run is reproducible.
 */
public class GMACAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** The two spellings both providers register. */
    private static final String[] NAMES = {"AESGMAC", "AES-GMAC"};

    /** The three AES key sizes; the C arm picks aes-128/192/256-gcm from these. */
    private static final int[] KEY_SIZES = {16, 24, 32};

    /**
     * IV lengths measured as accepted by GMAC on mainline and both FIPS
     * modules. 12 is the SP 800-38D recommendation; the rest are here because
     * GCM permits them and a length-restricting bug would otherwise pass.
     */
    private static final int[] IV_LENGTHS = {1, 8, 11, 12, 13, 16, 32};

    /** Message lengths straddling the 16-byte GCM block boundary. */
    private static final int[] LENGTHS = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1000};

    private static final SecureRandom RANDOM = new SecureRandom();

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

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static SecretKey randomKey(SecureRandom sr)
    {
        byte[] keyBytes = new byte[KEY_SIZES[sr.nextInt(KEY_SIZES.length)]];
        sr.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] randomIv(SecureRandom sr)
    {
        byte[] iv = new byte[IV_LENGTHS[sr.nextInt(IV_LENGTHS.length)]];
        sr.nextBytes(iv);
        return iv;
    }

    private static byte[] oneShot(String name, String provider, SecretKey key,
                                  AlgorithmParameterSpec spec, byte[] msg) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, spec);
        return mac.doFinal(msg);
    }

    private static byte[] byteWise(String name, String provider, SecretKey key,
                                   AlgorithmParameterSpec spec, byte[] msg) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, spec);
        for (byte b : msg)
        {
            mac.update(b);
        }
        return mac.doFinal();
    }

    private static byte[] fixedChunks(String name, String provider, SecretKey key,
                                      AlgorithmParameterSpec spec, byte[] msg, int chunk) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, spec);
        int offset = 0;
        while (offset < msg.length)
        {
            int take = Math.min(chunk, msg.length - offset);
            mac.update(msg, offset, take);
            offset += take;
        }
        return mac.doFinal();
    }

    private static byte[] randomSplit(String name, String provider, SecretKey key,
                                      AlgorithmParameterSpec spec, byte[] msg, SecureRandom sr) throws Exception
    {
        Mac mac = Mac.getInstance(name, provider);
        mac.init(key, spec);
        int offset = 0;
        while (offset < msg.length)
        {
            int take = Math.min(1 + sr.nextInt(97), msg.length - offset);
            mac.update(msg, offset, take);
            offset += take;
        }
        return mac.doFinal();
    }

    /**
     * The core agreement: over the length matrix, with random keys and random
     * (legal) IV lengths, the Jostle tag must equal BouncyCastle's byte for
     * byte — under both registered spellings and through both parameter specs.
     * <p>
     * Both directions of the streaming split are covered: Jostle streaming
     * against BC one-shot, and BC streaming against Jostle one-shot. A
     * buffering bug on either side shows up as a mismatch with the other
     * side's single call.
     */
    @Test
    public void gmacAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("gmacAgreesWithBouncyCastle");

        for (String name : NAMES)
        {
            for (int i = 0; i < LENGTHS.length; i++)
            {
                int len = (i == LENGTHS.length - 1) ? 512 + sr.nextInt(2048) : LENGTHS[i];

                SecretKey key = randomKey(sr);
                byte[] iv = randomIv(sr);
                byte[] msg = new byte[len];
                sr.nextBytes(msg);

                String tag = name + " keyLen=" + key.getEncoded().length
                        + " ivLen=" + iv.length + " msgLen=" + len;

                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                byte[] jostle = oneShot(name, JSL, key, ivSpec, msg);

                Assertions.assertEquals(16, jostle.length, tag + ": tag length");

                // Jostle one-shot == BC one-shot.
                Assertions.assertArrayEquals(jostle, oneShot(name, BC, key, ivSpec, msg),
                        tag + ": one-shot JSL vs BC");

                // Jostle streaming == BC one-shot (Jostle's buffering).
                Assertions.assertArrayEquals(jostle, byteWise(name, JSL, key, ivSpec, msg),
                        tag + ": JSL byte-wise vs BC one-shot");
                Assertions.assertArrayEquals(jostle, randomSplit(name, JSL, key, ivSpec, msg, sr),
                        tag + ": JSL random-split");

                // BC streaming == Jostle one-shot (the other direction).
                Assertions.assertArrayEquals(jostle, randomSplit(name, BC, key, ivSpec, msg, sr),
                        tag + ": BC random-split vs JSL one-shot");

                // GCMParameterSpec at the full tag length must be the same
                // operation as the IvParameterSpec form, on both providers.
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                Assertions.assertArrayEquals(jostle, oneShot(name, JSL, key, gcmSpec, msg),
                        tag + ": JSL GCMParameterSpec");
                Assertions.assertArrayEquals(jostle, oneShot(name, BC, key, gcmSpec, msg),
                        tag + ": BC GCMParameterSpec");
            }
        }
    }

    /**
     * Chunking matrix at the block boundaries. Partial-block buffering is where
     * a streaming MAC most often diverges from its one-shot path, and GMAC's
     * 16-byte GCM block is the alignment that matters.
     */
    @Test
    public void chunkingMatrixAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("chunkingMatrixAgrees");

        for (int trial = 0; trial < 10; trial++)
        {
            SecretKey key = randomKey(sr);
            byte[] iv = randomIv(sr);
            byte[] msg = new byte[128 + sr.nextInt(512)];
            sr.nextBytes(msg);
            IvParameterSpec spec = new IvParameterSpec(iv);

            byte[] expected = oneShot("AESGMAC", BC, key, spec, msg);
            String tag = "trial=" + trial + " msgLen=" + msg.length;

            Assertions.assertArrayEquals(expected, oneShot("AESGMAC", JSL, key, spec, msg),
                    tag + ": one-shot");
            Assertions.assertArrayEquals(expected, byteWise("AESGMAC", JSL, key, spec, msg),
                    tag + ": byte-by-byte");
            for (int chunk : new int[]{15, 16, 17, 31, 32, 33})
            {
                Assertions.assertArrayEquals(expected, fixedChunks("AESGMAC", JSL, key, spec, msg, chunk),
                        tag + ": chunk=" + chunk);
            }
            Assertions.assertArrayEquals(expected, randomSplit("AESGMAC", JSL, key, spec, msg, sr),
                    tag + ": random split");
        }
    }

    /**
     * Every accepted IV length produces a tag that agrees with BC — and each
     * distinct IV produces a DISTINCT tag.
     * <p>
     * The second half is the load-bearing part. Without it an implementation
     * that dropped the IV entirely would still agree with BC on nothing at all
     * (BC uses it), but a subtler one that truncated or padded the IV to 12
     * bytes would agree for the 12-byte case and be silently wrong elsewhere;
     * comparing lengths against each other catches that.
     */
    @Test
    public void everyAcceptedIvLengthAgreesAndChangesTheTag() throws Exception
    {
        SecureRandom sr = seededRandom("everyAcceptedIvLengthAgreesAndChangesTheTag");

        SecretKey key = randomKey(sr);
        byte[] msg = new byte[1 + sr.nextInt(500)];
        sr.nextBytes(msg);

        byte[][] tags = new byte[IV_LENGTHS.length][];

        for (int i = 0; i < IV_LENGTHS.length; i++)
        {
            byte[] iv = new byte[IV_LENGTHS[i]];
            sr.nextBytes(iv);
            IvParameterSpec spec = new IvParameterSpec(iv);

            tags[i] = oneShot("AESGMAC", JSL, key, spec, msg);
            Assertions.assertArrayEquals(tags[i], oneShot("AESGMAC", BC, key, spec, msg),
                    "ivLen=" + IV_LENGTHS[i] + ": JSL vs BC");
        }

        for (int i = 0; i < tags.length; i++)
        {
            for (int j = i + 1; j < tags.length; j++)
            {
                Assertions.assertFalse(Arrays.areEqual(tags[i], tags[j]),
                        "ivLen " + IV_LENGTHS[i] + " and " + IV_LENGTHS[j]
                                + " produced the same tag - the IV is not fully honoured");
            }
        }

        // Same length, one bit different: the tag must still change.
        byte[] ivA = new byte[12];
        sr.nextBytes(ivA);
        byte[] ivB = Arrays.clone(ivA);
        ivB[sr.nextInt(ivB.length)] ^= (byte) 0x01;
        Assertions.assertFalse(Arrays.areEqual(
                        oneShot("AESGMAC", JSL, key, new IvParameterSpec(ivA), msg),
                        oneShot("AESGMAC", JSL, key, new IvParameterSpec(ivB), msg)),
                "a one-bit IV change produced the same tag");
    }

    /**
     * Negative path: the tag must depend on the message and on the key.
     */
    @Test
    public void tamperedMessageAndWrongKeyChangeTheTag() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedMessageAndWrongKeyChangeTheTag");

        for (int trial = 0; trial < 10; trial++)
        {
            SecretKey key = randomKey(sr);
            byte[] iv = randomIv(sr);
            IvParameterSpec spec = new IvParameterSpec(iv);
            byte[] msg = new byte[1 + sr.nextInt(1024)];
            sr.nextBytes(msg);

            byte[] base = oneShot("AESGMAC", JSL, key, spec, msg);

            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(Arrays.areEqual(base, oneShot("AESGMAC", JSL, key, spec, tampered)),
                    "tampered message produced an identical tag");

            byte[] otherKeyBytes = new byte[key.getEncoded().length];
            sr.nextBytes(otherKeyBytes);
            Assertions.assertFalse(Arrays.areEqual(base,
                            oneShot("AESGMAC", JSL, new SecretKeySpec(otherKeyBytes, "AES"), spec, msg)),
                    "a different key produced an identical tag");
        }
    }

    /**
     * Key-length boundaries. AES accepts exactly 16, 24 and 32 bytes; the value
     * either side of each must be refused, and so must 0 and a large value.
     * A compact key-length check that accepted 17 alongside 16 is invisible to
     * every test that only ever passes a valid length.
     */
    @Test
    public void keyLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("keyLengthBoundaries");
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        IvParameterSpec spec = new IvParameterSpec(iv);

        byte[] msg = new byte[7];
        sr.nextBytes(msg);

        for (int valid : KEY_SIZES)
        {
            byte[] k = new byte[valid];
            sr.nextBytes(k);
            SecretKey key = new SecretKeySpec(k, "AES");

            // Compared against BC rather than just length-checked: each key
            // size selects a different AES variant in the C arm, and only an
            // independent implementation can show the RIGHT one was chosen.
            // A length assertion alone passes for all three even if every one
            // of them silently ran AES-128.
            Mac mac = Mac.getInstance("AESGMAC", JSL);
            mac.init(key, spec);
            Assertions.assertArrayEquals(oneShot("AESGMAC", BC, key, spec, msg), mac.doFinal(msg),
                    "keyLen=" + valid + ": wrong AES variant selected for this key size");
        }

        for (int invalid : new int[]{1, 15, 17, 23, 25, 31, 33, 64})
        {
            byte[] k = new byte[invalid];
            sr.nextBytes(k);
            Mac mac = Mac.getInstance("AESGMAC", JSL);
            InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                    () -> mac.init(new SecretKeySpec(k, "AES"), spec),
                    "keyLen=" + invalid + " should be rejected");
            Assertions.assertEquals("invalid key length for mac type", ex.getMessage(),
                    "keyLen=" + invalid);
        }
    }

    /**
     * The tag length is fixed at what OpenSSL reports, so a
     * {@code GCMParameterSpec} asking for anything shorter must be REFUSED.
     * <p>
     * This is the assertion that would fail if someone "supported" truncation
     * by passing {@code OSSL_MAC_PARAM_SIZE} through: that parameter is not in
     * GMAC's settable set, so it is silently ignored and the caller would get a
     * full 16-byte tag while believing it asked for 12. BC, which genuinely can
     * truncate, is the proof that 12 is a thing a caller might reasonably ask
     * for — which is exactly why refusing has to be explicit.
     */
    @Test
    public void shortGcmTagLengthIsRefusedNotSilentlyWidened() throws Exception
    {
        SecureRandom sr = seededRandom("shortGcmTagLengthIsRefusedNotSilentlyWidened");
        SecretKey key = randomKey(sr);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);

        for (int tLen : new int[]{32, 64, 96, 104, 112, 120, 127, 129, 256})
        {
            Mac mac = Mac.getInstance("AESGMAC", JSL);
            InvalidAlgorithmParameterException ex =
                    Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                            () -> mac.init(key, new GCMParameterSpec(tLen, iv)),
                            "tLen=" + tLen + " should be refused");
            Assertions.assertEquals(
                    "GMAC tag length is fixed at 128 bits, got " + tLen, ex.getMessage());
        }

        // The full length is accepted, and BC agrees with the result — proving
        // the refusals above are a tag-length check and not a broken spec path.
        Mac mac = Mac.getInstance("AESGMAC", JSL);
        mac.init(key, new GCMParameterSpec(128, iv));
        byte[] msg = new byte[64];
        sr.nextBytes(msg);
        Assertions.assertArrayEquals(oneShot("AESGMAC", BC, key, new GCMParameterSpec(128, iv), msg),
                mac.doFinal(msg));
    }

    /**
     * Parameter-spec contract at the JCE surface.
     */
    @Test
    public void parameterSpecRejections() throws Exception
    {
        SecureRandom sr = seededRandom("parameterSpecRejections");
        SecretKey key = randomKey(sr);
        byte[] iv = new byte[12];
        sr.nextBytes(iv);

        // GMAC cannot run without a nonce, so a null spec is refused rather
        // than defaulted. Note the JDK's Mac.init(Key) wraps an
        // InvalidAlgorithmParameterException as InvalidKeyException, so the
        // two entry points report the refusal differently; both are pinned.
        Mac viaSpec = Mac.getInstance("AESGMAC", JSL);
        InvalidAlgorithmParameterException iape =
                Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                        () -> viaSpec.init(key, null));
        Assertions.assertEquals(
                "GMAC requires an IvParameterSpec or GCMParameterSpec carrying the nonce",
                iape.getMessage());

        Mac viaKeyOnly = Mac.getInstance("AESGMAC", JSL);
        Assertions.assertThrows(InvalidKeyException.class, () -> viaKeyOnly.init(key));

        // A spec of an unrelated type names what was expected and what arrived.
        Mac wrongSpec = Mac.getInstance("AESGMAC", JSL);
        InvalidAlgorithmParameterException wrong =
                Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                        () -> wrongSpec.init(key, new javax.crypto.spec.PBEParameterSpec(new byte[8], 1)));
        Assertions.assertEquals(
                "expected IvParameterSpec or GCMParameterSpec, got javax.crypto.spec.PBEParameterSpec",
                wrong.getMessage());

        // A zero-length IV is refused by OpenSSL itself ("invalid iv length"),
        // not pre-checked here — the guides' classify-don't-pre-check rule.
        Mac emptyIv = Mac.getInstance("AESGMAC", JSL);
        Exception empty = Assertions.assertThrows(Exception.class,
                () -> emptyIv.init(key, new IvParameterSpec(new byte[0])));
        Assertions.assertTrue(empty.getMessage() != null
                        && empty.getMessage().startsWith("OpenSSL Error:"),
                "zero-length IV should surface the OpenSSL refusal, got: " + empty.getMessage());

        // CONTROL: the MACs that take no nonce must still refuse a spec, or the
        // change above has widened every registration rather than just GMAC's.
        for (String other : new String[]{"HMACSHA256", "AESCMAC"})
        {
            Mac mac = Mac.getInstance(other, JSL);
            byte[] k = new byte[32];
            sr.nextBytes(k);
            InvalidAlgorithmParameterException ex =
                    Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                            () -> mac.init(new SecretKeySpec(k, "AES"), new IvParameterSpec(iv)),
                            other + " should not accept an IV");
            Assertions.assertEquals("params not supported", ex.getMessage());
        }
    }

    /**
     * Reset and reuse. GMAC is deterministic, so the same instance driven twice
     * over the same input must give byte-identical tags, and over different
     * inputs must give the right tag each time — the auto-reset that
     * {@code Mac.doFinal} performs has to restore the IV as well as the key,
     * which a reset that re-inited from the key alone would not.
     */
    @Test
    public void resetAndReuse() throws Exception
    {
        SecureRandom sr = seededRandom("resetAndReuse");
        SecretKey key = randomKey(sr);
        byte[] iv = randomIv(sr);
        IvParameterSpec spec = new IvParameterSpec(iv);

        byte[] msgA = new byte[100];
        byte[] msgB = new byte[37];
        sr.nextBytes(msgA);
        sr.nextBytes(msgB);

        byte[] refA = oneShot("AESGMAC", BC, key, spec, msgA);
        byte[] refB = oneShot("AESGMAC", BC, key, spec, msgB);

        Mac mac = Mac.getInstance("AESGMAC", JSL);
        mac.init(key, spec);

        // Two different inputs through one instance.
        Assertions.assertArrayEquals(refA, mac.doFinal(msgA), "first message");
        Assertions.assertArrayEquals(refB, mac.doFinal(msgB), "second message after auto-reset");

        // Deterministic: the same input twice must repeat exactly.
        Assertions.assertArrayEquals(refA, mac.doFinal(msgA), "repeat of the first message");
        Assertions.assertArrayEquals(refA, mac.doFinal(msgA), "second repeat");

        // An explicit reset mid-message must discard the partial absorption.
        mac.update(msgB);
        mac.reset();
        Assertions.assertArrayEquals(refA, mac.doFinal(msgA), "after an explicit mid-message reset");

        // Re-init with a different IV on the same instance must take effect.
        byte[] iv2 = Arrays.clone(iv);
        iv2[0] ^= (byte) 0xff;
        mac.init(key, new IvParameterSpec(iv2));
        Assertions.assertArrayEquals(
                oneShot("AESGMAC", BC, key, new IvParameterSpec(iv2), msgA),
                mac.doFinal(msgA), "after re-init with a different IV");
    }

    /**
     * {@code Mac.clone()} must CONTINUE the absorbed state, IV included.
     * <p>
     * Divergence is not continuation: two hollow clones fed different
     * remainders also diverge, so an {@code assertFalse(equal(a, b))} would
     * pass for a clone that carried nothing. The assertion here is against an
     * independent BouncyCastle MAC over the WHOLE message — only a clone that
     * really carried the first half's state can match it.
     * <p>
     * Falsified by substituting {@code EVP_MAC_CTX_new} for
     * {@code EVP_MAC_CTX_dup} in {@code mac_copy}: this test fails and
     * {@code cloneIsIndependentOfItsSource} fails, while the non-clone tests in
     * this class stay green as the control.
     */
    @Test
    public void cloneContinuesTheSameState() throws Exception
    {
        SecureRandom sr = seededRandom("cloneContinuesTheSameState");

        for (int trial = 0; trial < 5; trial++)
        {
            SecretKey key = randomKey(sr);
            byte[] iv = randomIv(sr);
            IvParameterSpec spec = new IvParameterSpec(iv);
            byte[] msg = new byte[64 + sr.nextInt(256)];
            sr.nextBytes(msg);
            int split = 1 + sr.nextInt(msg.length - 1);

            byte[] whole = oneShot("AESGMAC", BC, key, spec, msg);

            Mac source = Mac.getInstance("AESGMAC", JSL);
            source.init(key, spec);
            source.update(msg, 0, split);

            Mac copy = (Mac) source.clone();
            copy.update(msg, split, msg.length - split);

            Assertions.assertArrayEquals(whole, copy.doFinal(),
                    "trial=" + trial + " split=" + split
                            + ": the clone did not continue the absorbed state");

            // The source must be unaffected and able to finish independently.
            source.update(msg, split, msg.length - split);
            Assertions.assertArrayEquals(whole, source.doFinal(),
                    "trial=" + trial + ": the source was disturbed by cloning");
        }
    }

    /**
     * Clones must be independent in both directions: feeding one must not
     * change what the other produces.
     */
    @Test
    public void cloneIsIndependentOfItsSource() throws Exception
    {
        SecureRandom sr = seededRandom("cloneIsIndependentOfItsSource");

        SecretKey key = randomKey(sr);
        byte[] iv = randomIv(sr);
        IvParameterSpec spec = new IvParameterSpec(iv);
        byte[] prefix = new byte[48];
        byte[] tailA = new byte[33];
        byte[] tailB = new byte[71];
        sr.nextBytes(prefix);
        sr.nextBytes(tailA);
        sr.nextBytes(tailB);

        Mac source = Mac.getInstance("AESGMAC", JSL);
        source.init(key, spec);
        source.update(prefix);

        Mac copy = (Mac) source.clone();

        source.update(tailA);
        copy.update(tailB);

        Assertions.assertArrayEquals(
                oneShot("AESGMAC", BC, key, spec, Arrays.concatenate(prefix, tailA)),
                source.doFinal(), "source after independent feeding");
        Assertions.assertArrayEquals(
                oneShot("AESGMAC", BC, key, spec, Arrays.concatenate(prefix, tailB)),
                copy.doFinal(), "clone after independent feeding");
    }

    /**
     * A clone taken before any update, and one taken at an exact block
     * boundary, must both continue correctly — the two states most likely to be
     * mishandled by a buffering copy.
     */
    @Test
    public void cloneAtStateBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("cloneAtStateBoundaries");
        SecretKey key = randomKey(sr);
        byte[] iv = randomIv(sr);
        IvParameterSpec spec = new IvParameterSpec(iv);
        byte[] msg = new byte[96];
        sr.nextBytes(msg);

        byte[] whole = oneShot("AESGMAC", BC, key, spec, msg);

        for (int split : new int[]{0, 15, 16, 17, 32, 96})
        {
            Mac source = Mac.getInstance("AESGMAC", JSL);
            source.init(key, spec);
            if (split > 0)
            {
                source.update(msg, 0, split);
            }
            Mac copy = (Mac) source.clone();
            if (split < msg.length)
            {
                copy.update(msg, split, msg.length - split);
            }
            Assertions.assertArrayEquals(whole, copy.doFinal(), "split=" + split);
        }
    }

    /**
     * The two registered spellings must be the same service, not two that
     * happen to agree: {@code getMacLength} and the produced tag both match,
     * and the alias resolves through the JCE the same way BC's does.
     */
    @Test
    public void bothSpellingsResolveToTheSameService() throws Exception
    {
        SecureRandom sr = seededRandom("bothSpellingsResolveToTheSameService");
        SecretKey key = randomKey(sr);
        byte[] iv = randomIv(sr);
        IvParameterSpec spec = new IvParameterSpec(iv);
        byte[] msg = new byte[128];
        sr.nextBytes(msg);

        Mac a = Mac.getInstance("AESGMAC", JSL);
        Mac b = Mac.getInstance("AES-GMAC", JSL);

        Assertions.assertEquals(a.getMacLength(), b.getMacLength());
        Assertions.assertEquals(16, a.getMacLength(),
                "GMAC's tag length is the GCM block size, queried from OpenSSL");

        a.init(key, spec);
        b.init(key, spec);

        // Judged against BC, not against each other: two of our own instances
        // sharing a wrong implementation agree perfectly, so a self-comparison
        // would prove only that the alias resolves somewhere, not that it
        // resolves to a working GMAC.
        byte[] reference = oneShot("AESGMAC", BC, key, spec, msg);
        Assertions.assertArrayEquals(reference, a.doFinal(msg), "AESGMAC");
        Assertions.assertArrayEquals(reference, b.doFinal(msg), "AES-GMAC alias");

        // And BC answers the same length for both of its spellings.
        Assertions.assertEquals(16, Mac.getInstance("AESGMAC", BC).getMacLength());
        Assertions.assertEquals(16, Mac.getInstance("AES-GMAC", BC).getMacLength());
    }
}
