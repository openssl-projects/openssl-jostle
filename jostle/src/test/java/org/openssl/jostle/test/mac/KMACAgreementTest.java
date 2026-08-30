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
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KMACParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KMAC128 / KMAC256 (NIST SP 800-185) agreement between the Jostle base
 * provider and BouncyCastle, plus the surface behaviour the two must share.
 * <p>
 * KMAC is the only variable-length MAC either provider registers, and the two
 * knobs that make it so — the output length {@code L} and the customisation
 * string {@code S} — are exactly where a wrong-but-self-consistent
 * implementation hides. Every test here therefore compares against BC byte for
 * byte rather than checking Jostle against itself: an implementation that
 * ignored {@code S}, silently substituted the default length, or treated KMAC
 * as a plain XOF would round-trip perfectly with itself and still fail here.
 * <p>
 * Facts pinned below that were MEASURED rather than assumed
 * ({@code fips-c-review/probes/kmac_probe.c}, 2026-08-24, across mainline
 * 3.6.2, mainline 3.5.7, FIPS 3.1.2 and FIPS 3.5.8-pedantic):
 * <ul>
 *   <li>{@code L} is bound into the KMAC input, so two output lengths share
 *       <b>no prefix</b>. Asking for 32 bytes is not the same as truncating a
 *       64-byte tag — {@link #differentOutputLengthsDoNotSharePrefix} is the
 *       property assertion, and it is what separates KMAC from a XOF.</li>
 *   <li>An <b>absent</b> customisation string is identical to an <b>empty</b>
 *       one, on every build. That is why omitting the spec entirely and
 *       passing {@code new KMACParameterSpec(bits)} agree.</li>
 *   <li>The default output length is 32 bytes for KMAC128 and 64 for KMAC256,
 *       and Jostle <b>queries</b> it from OpenSSL rather than transcribing it;
 *       {@link #defaultLengthMatchesBouncyCastle} pins that the queried value
 *       is the one BC independently arrives at.</li>
 * </ul>
 * Inputs (keys, customisation strings, message content and length, output
 * length) come from a per-test SHA1PRNG whose seed is logged, so a flaky run is
 * reproducible.
 */
public class KMACAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** The JCE service names both providers register. */
    private static final String[] NAMES = {"KMAC128", "KMAC256"};

    /**
     * The alias spellings ProvMac registers alongside each primary: the OpenSSL
     * EVP_MAC name, and the two NIST OIDs BouncyCastle also carries
     * (id-KmacWithSHAKEnnn from RFC 8702, and id-KMACnnn).
     */
    private static final String[][] ALIASES = {
            {"KMAC-128", "2.16.840.1.101.3.4.2.19", "2.16.840.1.101.3.4.2.21"},
            {"KMAC-256", "2.16.840.1.101.3.4.2.20", "2.16.840.1.101.3.4.2.22"},
    };

    /** SP 800-185's defaults: 2 * the security strength, in bytes. */
    private static final int[] DEFAULT_LENGTHS = {32, 64};

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

    /**
     * A random key of a length every supported build accepts. The floor moves
     * with the module's fipsinstall config — 4 bytes by default, 14 under
     * {@code kmac-key-check} — so the base provider's tests stay at or above 14
     * and the config-dependent boundary is pinned in the FIPS contract tests
     * instead.
     */
    private static SecretKey randomKey(SecureRandom sr, String name)
    {
        byte[] keyBytes = new byte[14 + sr.nextInt(51)];
        sr.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, name);
    }

    private static byte[] randomCustom(SecureRandom sr)
    {
        // 0 exercises the empty-S path, which must equal the absent-S path.
        byte[] s = new byte[sr.nextInt(40)];
        sr.nextBytes(s);
        return s;
    }

    /**
     * BC's KMACParameterSpec, built from the same values as ours. The two
     * classes are deliberate mirrors (see Jostle's KMACParameterSpec Javadoc);
     * constructing both from one pair of values is what makes the comparison an
     * agreement test rather than a self-check.
     */
    private static AlgorithmParameterSpec bcSpec(int macSizeInBits, byte[] custom)
    {
        return new org.bouncycastle.jcajce.spec.KMACParameterSpec(macSizeInBits, custom);
    }

    private static AlgorithmParameterSpec joSpec(int macSizeInBits, byte[] custom)
    {
        return new KMACParameterSpec(macSizeInBits, custom);
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
     * The core agreement: random keys, random customisation strings, random
     * output lengths, random message content and length — Jostle's tag must
     * equal BouncyCastle's byte for byte, in both streaming directions.
     */
    @Test
    public void kmacAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("kmacAgreesWithBouncyCastle");

        for (int nameIdx = 0; nameIdx < NAMES.length; nameIdx++)
        {
            String name = NAMES[nameIdx];
            for (int trial = 0; trial < 20; trial++)
            {
                SecretKey key = randomKey(sr, name);
                byte[] custom = randomCustom(sr);
                // A byte multiple, as SP 800-185 and both specs require.
                int bits = (1 + sr.nextInt(96)) * 8;
                byte[] msg = new byte[sr.nextInt(400)];
                sr.nextBytes(msg);

                byte[] jo = oneShot(name, JSL, key, joSpec(bits, custom), msg);
                byte[] bc = oneShot(name, BC, key, bcSpec(bits, custom), msg);

                Assertions.assertEquals(bits / 8, jo.length,
                        name + " must produce the requested length");
                Assertions.assertTrue(Arrays.areEqual(bc, jo),
                        name + " one-shot must agree with BC (trial " + trial + ")");

                // Jostle streaming vs BC one-shot, and the reverse: a buffering
                // bug on either side shows up against the other's single call.
                Assertions.assertTrue(
                        Arrays.areEqual(bc, byteWise(name, JSL, key, joSpec(bits, custom), msg)),
                        name + " byte-wise Jostle must agree with BC one-shot");
                Assertions.assertTrue(
                        Arrays.areEqual(jo, byteWise(name, BC, key, bcSpec(bits, custom), msg)),
                        name + " byte-wise BC must agree with Jostle one-shot");
            }
        }
    }

    /**
     * The same logical input chunked several ways must give one answer, and
     * that answer must be BC's. Covers the partial-block buffering that a
     * one-shot-only test never reaches.
     */
    @Test
    public void chunkingMatrixAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("chunkingMatrixAgrees");

        for (String name : NAMES)
        {
            for (int trial = 0; trial < 5; trial++)
            {
                SecretKey key = randomKey(sr, name);
                byte[] custom = randomCustom(sr);
                int bits = (1 + sr.nextInt(64)) * 8;
                byte[] msg = new byte[200 + sr.nextInt(200)];
                sr.nextBytes(msg);

                byte[] reference = oneShot(name, BC, key, bcSpec(bits, custom), msg);

                Assertions.assertTrue(
                        Arrays.areEqual(reference, oneShot(name, JSL, key, joSpec(bits, custom), msg)),
                        name + " one-shot");
                Assertions.assertTrue(
                        Arrays.areEqual(reference, byteWise(name, JSL, key, joSpec(bits, custom), msg)),
                        name + " byte-by-byte");
                Assertions.assertTrue(
                        Arrays.areEqual(reference, randomSplit(name, JSL, key, joSpec(bits, custom), msg, sr)),
                        name + " random splits");

                // KMAC's rate is 168 bytes (KMAC128) / 136 (KMAC256); straddle
                // both, and 1 either side, so partial-block boundaries land in
                // different places.
                for (int chunk : new int[]{1, 135, 136, 137, 167, 168, 169})
                {
                    Assertions.assertTrue(
                            Arrays.areEqual(reference,
                                    fixedChunks(name, JSL, key, joSpec(bits, custom), msg, chunk)),
                            name + " chunk=" + chunk);
                }
            }
        }
    }

    /**
     * The customisation string matrix, and the negative that goes with it.
     * <p>
     * Two different values of {@code S} must give different tags — an
     * implementation that dropped {@code S} on the floor would produce the same
     * tag for both and still agree with itself. An absent {@code S} must equal
     * an empty one, which is the measured OpenSSL behaviour and the reason the
     * NI can represent "no S" as a null array.
     */
    @Test
    public void customisationStringIsMixedInAndMatchesBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("customisationStringIsMixedInAndMatchesBouncyCastle");

        for (String name : NAMES)
        {
            SecretKey key = randomKey(sr, name);
            byte[] msg = new byte[64 + sr.nextInt(64)];
            sr.nextBytes(msg);
            int bits = 256;

            // Two DIFFERENT random customisation strings, of different random
            // lengths, rather than fixed literals: S is length-prefixed in the
            // KMAC encoding, so varying its length exercises encoding paths a
            // pair of fixed short strings never reaches.
            byte[] alpha = new byte[1 + sr.nextInt(40)];
            byte[] beta = new byte[1 + sr.nextInt(40)];
            sr.nextBytes(alpha);
            do
            {
                sr.nextBytes(beta);
            }
            while (Arrays.areEqual(alpha, beta));

            byte[] withAlpha = oneShot(name, JSL, key, joSpec(bits, alpha), msg);
            byte[] withBeta = oneShot(name, JSL, key, joSpec(bits, beta), msg);
            byte[] withEmpty = oneShot(name, JSL, key, joSpec(bits, new byte[0]), msg);

            // Every one of these must also be BC's answer, so "different" can
            // never be satisfied by both sides being differently wrong.
            Assertions.assertTrue(Arrays.areEqual(oneShot(name, BC, key, bcSpec(bits, alpha), msg), withAlpha),
                    name + " S=alpha must agree with BC");
            Assertions.assertTrue(Arrays.areEqual(oneShot(name, BC, key, bcSpec(bits, beta), msg), withBeta),
                    name + " S=beta must agree with BC");
            Assertions.assertTrue(Arrays.areEqual(oneShot(name, BC, key, bcSpec(bits, new byte[0]), msg), withEmpty),
                    name + " S=empty must agree with BC");

            Assertions.assertFalse(Arrays.areEqual(withAlpha, withBeta),
                    name + " a different customisation string must change the tag");
            Assertions.assertFalse(Arrays.areEqual(withAlpha, withEmpty),
                    name + " a customisation string must change the tag versus an empty one");

            // Absent == empty. Note the spec cannot express "absent", so this
            // compares no-spec-at-all against an explicitly empty S.
            Mac noSpec = Mac.getInstance(name, JSL);
            noSpec.init(key);
            byte[] absent = noSpec.doFinal(msg);
            byte[] emptyAtDefaultLength =
                    oneShot(name, JSL, key, joSpec(DEFAULT_LENGTHS[name.equals("KMAC128") ? 0 : 1] * 8,
                            new byte[0]), msg);
            Assertions.assertTrue(Arrays.areEqual(absent, emptyAtDefaultLength),
                    name + " an absent customisation string must equal an empty one");

            // A null customisation string is documented as equivalent to empty.
            Assertions.assertTrue(
                    Arrays.areEqual(withEmpty, oneShot(name, JSL, key, joSpec(bits, null), msg)),
                    name + " a null customisation string must equal an empty one");
        }
    }

    /**
     * The property that distinguishes KMAC from a plain XOF, and the reason
     * "ask for 32" is not "ask for 64 and truncate".
     * <p>
     * SP 800-185 right-encodes {@code L} into the KMAC input, so changing the
     * requested length changes the whole output. A prefix relationship here
     * would mean the length was being applied as a truncation after the fact —
     * which is what a naive implementation over cSHAKE would do, and which
     * every roundtrip test in this file would still pass.
     */
    @Test
    public void differentOutputLengthsDoNotSharePrefix() throws Exception
    {
        SecureRandom sr = seededRandom("differentOutputLengthsDoNotSharePrefix");

        for (String name : NAMES)
        {
            SecretKey key = randomKey(sr, name);
            byte[] custom = randomCustom(sr);
            byte[] msg = new byte[128];
            sr.nextBytes(msg);

            byte[] shortTag = oneShot(name, JSL, key, joSpec(32 * 8, custom), msg);
            byte[] longTag = oneShot(name, JSL, key, joSpec(64 * 8, custom), msg);

            Assertions.assertEquals(32, shortTag.length);
            Assertions.assertEquals(64, longTag.length);

            byte[] prefixOfLong = new byte[32];
            System.arraycopy(longTag, 0, prefixOfLong, 0, 32);
            Assertions.assertFalse(Arrays.areEqual(shortTag, prefixOfLong),
                    name + " L is bound into the input, so L=32 must NOT be a prefix of L=64");

            // And both must still be BC's answers, so the divergence is the
            // specified one rather than two implementations disagreeing.
            Assertions.assertTrue(
                    Arrays.areEqual(oneShot(name, BC, key, bcSpec(32 * 8, custom), msg), shortTag),
                    name + " L=32 must agree with BC");
            Assertions.assertTrue(
                    Arrays.areEqual(oneShot(name, BC, key, bcSpec(64 * 8, custom), msg), longTag),
                    name + " L=64 must agree with BC");
        }
    }

    /**
     * The default output length must be the one OpenSSL reports, and it must be
     * the value BouncyCastle independently arrives at — both before init (the
     * keyless metadata query) and after.
     * <p>
     * This is the guard on "query, never transcribe": a hard-coded 32/64 table
     * would pass a self-consistency check and fail here only if it drifted, so
     * the assertion is against BC's number and against a real tag's length.
     */
    @Test
    public void defaultLengthMatchesBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("defaultLengthMatchesBouncyCastle");

        for (int i = 0; i < NAMES.length; i++)
        {
            String name = NAMES[i];

            Mac jo = Mac.getInstance(name, JSL);
            Mac bc = Mac.getInstance(name, BC);

            Assertions.assertEquals(bc.getMacLength(), jo.getMacLength(),
                    name + " default length before init must match BC");
            Assertions.assertEquals(DEFAULT_LENGTHS[i], jo.getMacLength(),
                    name + " default length must be SP 800-185's 2 * strength");

            SecretKey key = randomKey(sr, name);
            byte[] msg = new byte[50];
            sr.nextBytes(msg);

            jo.init(key);
            bc.init(key);
            byte[] joTag = jo.doFinal(msg);

            Assertions.assertEquals(DEFAULT_LENGTHS[i], joTag.length,
                    name + " an un-parameterised tag must be the default length");
            Assertions.assertTrue(Arrays.areEqual(bc.doFinal(msg), joTag),
                    name + " the un-parameterised tag must agree with BC");

            // A requested length must be reported by getMacLength too, so a
            // caller sizing its own buffer from it is not misled.
            Mac sized = Mac.getInstance(name, JSL);
            sized.init(key, joSpec(24 * 8, null));
            Assertions.assertEquals(24, sized.getMacLength(),
                    name + " getMacLength must report the requested length");
            Assertions.assertEquals(24, sized.doFinal(msg).length,
                    name + " the tag must be the requested length");
        }
    }

    /**
     * Negative path: the tag must actually depend on the message and the key.
     */
    @Test
    public void tamperedMessageAndWrongKeyChangeTheTag() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedMessageAndWrongKeyChangeTheTag");

        for (String name : NAMES)
        {
            SecretKey key = randomKey(sr, name);
            byte[] custom = randomCustom(sr);
            byte[] msg = new byte[64 + sr.nextInt(64)];
            sr.nextBytes(msg);

            byte[] tag = oneShot(name, JSL, key, joSpec(256, custom), msg);

            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= (byte) 0x01;
            Assertions.assertFalse(
                    Arrays.areEqual(tag, oneShot(name, JSL, key, joSpec(256, custom), tampered)),
                    name + " a one-bit change in the message must change the tag");

            SecretKey other = randomKey(sr, name);
            Assertions.assertFalse(
                    Arrays.areEqual(tag, oneShot(name, JSL, other, joSpec(256, custom), msg)),
                    name + " a different key must change the tag");
        }
    }

    /**
     * Parameter-spec rejections, each pinned by message.
     * <p>
     * The spec's own validation is checked here rather than only in a spec unit
     * test because it is load-bearing: a zero or negative length that reached
     * the NI would be read as "unspecified" and silently served the default,
     * and on most OpenSSL builds a zero forwarded as a real request produces a
     * zero-length MAC that compares equal to everything.
     */
    @Test
    public void parameterSpecRejections() throws Exception
    {
        for (String name : NAMES)
        {
            // Not a multiple of 8.
            IllegalArgumentException notByte = Assertions.assertThrows(
                    IllegalArgumentException.class, () -> new KMACParameterSpec(255));
            Assertions.assertEquals("macSizeInBits must be a multiple of 8", notByte.getMessage());

            // Zero and negative.
            IllegalArgumentException zero = Assertions.assertThrows(
                    IllegalArgumentException.class, () -> new KMACParameterSpec(0));
            Assertions.assertEquals("macSizeInBits must be positive", zero.getMessage());
            IllegalArgumentException negative = Assertions.assertThrows(
                    IllegalArgumentException.class, () -> new KMACParameterSpec(-8));
            Assertions.assertEquals("macSizeInBits must be positive", negative.getMessage());

            // A well-formed spec of the wrong type.
            Mac mac = Mac.getInstance(name, JSL);
            SecretKey key = new SecretKeySpec(new byte[32], name);
            InvalidAlgorithmParameterException wrongType = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> mac.init(key, new IvParameterSpec(new byte[12])));
            Assertions.assertEquals(
                    "expected KMACParameterSpec, got javax.crypto.spec.IvParameterSpec",
                    wrongType.getMessage());

            // And the mirror: a KMAC spec handed to a MAC that takes none.
            Mac hmac = Mac.getInstance("HmacSHA256", JSL);
            InvalidAlgorithmParameterException notSupported = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> hmac.init(new SecretKeySpec(new byte[32], "HmacSHA256"),
                            new KMACParameterSpec(256)));
            Assertions.assertEquals("params not supported", notSupported.getMessage());
        }
    }

    /**
     * Reset and reuse. KMAC is deterministic, so the same input through one
     * reused instance must give the identical tag, and the parameters must
     * survive the terminal call — a reset that dropped {@code S} or the
     * requested length would produce a plausible tag of the wrong shape.
     */
    @Test
    public void resetAndReuse() throws Exception
    {
        SecureRandom sr = seededRandom("resetAndReuse");

        for (String name : NAMES)
        {
            SecretKey key = randomKey(sr, name);
            byte[] custom = randomCustom(sr);
            byte[] a = new byte[70];
            byte[] b = new byte[130];
            sr.nextBytes(a);
            sr.nextBytes(b);

            Mac mac = Mac.getInstance(name, JSL);
            mac.init(key, joSpec(40 * 8, custom));

            byte[] first = mac.doFinal(a);
            byte[] second = mac.doFinal(b);
            byte[] third = mac.doFinal(a);

            Assertions.assertEquals(40, first.length);
            Assertions.assertEquals(40, second.length,
                    name + " the requested length must survive a terminal call");
            Assertions.assertTrue(Arrays.areEqual(first, third),
                    name + " a deterministic MAC must repeat on the same input after reset");
            Assertions.assertFalse(Arrays.areEqual(first, second),
                    name + " distinct inputs must give distinct tags");

            // The reused instance must still agree with a fresh BC one, which
            // is what proves S and L survived rather than merely staying
            // self-consistent.
            Assertions.assertTrue(
                    Arrays.areEqual(oneShot(name, BC, key, bcSpec(40 * 8, custom), b), second),
                    name + " a reused instance must still agree with BC");

            // engineReset mid-stream must discard the absorbed bytes.
            mac.update(a);
            mac.reset();
            Assertions.assertTrue(Arrays.areEqual(first, mac.doFinal(a)),
                    name + " reset must discard absorbed bytes");

            // Re-init WITHOUT a spec must restore the defaults, not keep the
            // previous init's length.
            mac.init(key);
            Assertions.assertEquals(name.equals("KMAC128") ? 32 : 64, mac.getMacLength(),
                    name + " re-init without a spec must restore the default length");
        }
    }

    /**
     * A clone must continue the source's state — key, {@code S}, requested
     * length and the bytes already absorbed.
     * <p>
     * Note that feeding two clones different remainders and observing
     * divergence proves nothing: two EMPTY clones diverge too. The check that
     * detects a hollow clone is that the clone's finished tag equals an
     * INDEPENDENT implementation's tag over the WHOLE message.
     */
    @Test
    public void cloneContinuesTheSameState() throws Exception
    {
        SecureRandom sr = seededRandom("cloneContinuesTheSameState");

        for (String name : NAMES)
        {
            SecretKey key = randomKey(sr, name);
            byte[] custom = randomCustom(sr);
            byte[] msg = new byte[200 + sr.nextInt(100)];
            sr.nextBytes(msg);
            int split = 1 + sr.nextInt(msg.length - 1);
            int bits = 40 * 8;

            byte[] reference = oneShot(name, BC, key, bcSpec(bits, custom), msg);

            Mac mac = Mac.getInstance(name, JSL);
            mac.init(key, joSpec(bits, custom));
            mac.update(msg, 0, split);

            Mac clone = (Mac) mac.clone();
            clone.update(msg, split, msg.length - split);

            Assertions.assertEquals(40, clone.getMacLength(),
                    name + " the clone must carry the requested length");
            Assertions.assertTrue(Arrays.areEqual(reference, clone.doFinal()),
                    name + " the clone must carry key, S, L and the absorbed bytes");

            // The source is unaffected and finishes the same message itself.
            mac.update(msg, split, msg.length - split);
            Assertions.assertTrue(Arrays.areEqual(reference, mac.doFinal()),
                    name + " cloning must not disturb the source");
        }
    }

    /**
     * Clones are independent: work done on one must not reach the other.
     */
    @Test
    public void cloneIsIndependentOfItsSource() throws Exception
    {
        SecureRandom sr = seededRandom("cloneIsIndependentOfItsSource");

        for (String name : NAMES)
        {
            SecretKey key = randomKey(sr, name);
            byte[] custom = randomCustom(sr);
            byte[] head = new byte[64];
            byte[] tailA = new byte[32];
            byte[] tailB = new byte[48];
            sr.nextBytes(head);
            sr.nextBytes(tailA);
            sr.nextBytes(tailB);
            int bits = 256;

            Mac mac = Mac.getInstance(name, JSL);
            mac.init(key, joSpec(bits, custom));
            mac.update(head);
            Mac clone = (Mac) mac.clone();

            mac.update(tailA);
            clone.update(tailB);

            byte[] fromSource = mac.doFinal();
            byte[] fromClone = clone.doFinal();

            Assertions.assertTrue(Arrays.areEqual(
                            oneShot(name, BC, key, bcSpec(bits, custom), Arrays.concatenate(head, tailA)),
                            fromSource),
                    name + " the source must finish head||tailA");
            Assertions.assertTrue(Arrays.areEqual(
                            oneShot(name, BC, key, bcSpec(bits, custom), Arrays.concatenate(head, tailB)),
                            fromClone),
                    name + " the clone must finish head||tailB");
        }
    }

    /**
     * Cloning at the state boundaries — before any update, and after a terminal
     * doFinal has reset the context.
     */
    @Test
    public void cloneAtStateBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("cloneAtStateBoundaries");

        for (String name : NAMES)
        {
            SecretKey key = randomKey(sr, name);
            byte[] custom = randomCustom(sr);
            byte[] msg = new byte[96];
            sr.nextBytes(msg);
            int bits = 288;

            byte[] reference = oneShot(name, BC, key, bcSpec(bits, custom), msg);

            // Clone immediately after init, before a single update.
            Mac fresh = Mac.getInstance(name, JSL);
            fresh.init(key, joSpec(bits, custom));
            Mac freshClone = (Mac) fresh.clone();
            Assertions.assertTrue(Arrays.areEqual(reference, freshClone.doFinal(msg)),
                    name + " a clone taken before any update must still MAC correctly");

            // Clone after a terminal doFinal, i.e. from a reset context.
            Mac used = Mac.getInstance(name, JSL);
            used.init(key, joSpec(bits, custom));
            used.doFinal(msg);
            Mac usedClone = (Mac) used.clone();
            Assertions.assertTrue(Arrays.areEqual(reference, usedClone.doFinal(msg)),
                    name + " a clone taken after doFinal must MAC from a clean state");
        }
    }

    /**
     * Every registered spelling must resolve to a working service producing the
     * same tag — not merely to a non-null Service object. Registration is not
     * usability, so each alias is driven through a real MAC and compared to the
     * primary's answer and to BC's.
     */
    @Test
    public void everySpellingProducesTheSameTag() throws Exception
    {
        SecureRandom sr = seededRandom("everySpellingProducesTheSameTag");

        for (int i = 0; i < NAMES.length; i++)
        {
            String primary = NAMES[i];
            SecretKey key = randomKey(sr, primary);
            byte[] custom = randomCustom(sr);
            byte[] msg = new byte[77];
            sr.nextBytes(msg);
            int bits = 320;

            byte[] reference = oneShot(primary, BC, key, bcSpec(bits, custom), msg);
            Assertions.assertTrue(Arrays.areEqual(reference,
                            oneShot(primary, JSL, key, joSpec(bits, custom), msg)),
                    primary + " primary must agree with BC");

            for (String alias : ALIASES[i])
            {
                Assertions.assertTrue(
                        Arrays.areEqual(reference, oneShot(alias, JSL, key, joSpec(bits, custom), msg)),
                        primary + " alias " + alias + " must produce the same tag");
            }
        }
    }

    /**
     * NIST SP 800-185 KMAC128 samples 1 and 2, each paired with a
     * modified-input differentiator so an implementation that ignored part of
     * its input cannot pass on the vector alone.
     */
    @Test
    public void sp800185KnownAnswerVectors() throws Exception
    {
        byte[] key = Hex.decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] data = Hex.decode("00010203");
        SecretKey secretKey = new SecretKeySpec(key, "KMAC128");

        // Sample #1: S = "", L = 256 bits.
        Assertions.assertEquals(
                "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
                Hex.toHexString(oneShot("KMAC128", JSL, secretKey, joSpec(256, new byte[0]), data)),
                "SP 800-185 KMAC128 sample #1");

        // Sample #2: S = "My Tagged Application", L = 256 bits.
        byte[] tagged = "My Tagged Application".getBytes("UTF-8");
        Assertions.assertEquals(
                "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
                Hex.toHexString(oneShot("KMAC128", JSL, secretKey, joSpec(256, tagged), data)),
                "SP 800-185 KMAC128 sample #2");

        // Differentiators: the two samples differ only in S, and flipping one
        // data bit must move the answer off the vector.
        byte[] flipped = Arrays.clone(data);
        flipped[0] ^= (byte) 0x01;
        Assertions.assertNotEquals(
                "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
                Hex.toHexString(oneShot("KMAC128", JSL, secretKey, joSpec(256, new byte[0]), flipped)),
                "a one-bit data change must leave the sample #1 vector");
        Assertions.assertNotEquals(
                "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
                Hex.toHexString(oneShot("KMAC128", JSL, secretKey, joSpec(264, new byte[0]), data)),
                "a different L must leave the sample #1 vector");
    }
}
