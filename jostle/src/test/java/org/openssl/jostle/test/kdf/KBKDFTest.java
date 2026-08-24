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

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KDFFeedbackParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.spec.KBKDFParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * SP 800-108 KBKDF coverage for the native {@code EVP_KDF "KBKDF"} surface
 * exposed as {@code SecretKeyFactory "KBKDF-HMAC-<digest>"} and
 * {@code "KBKDF-CMAC-AES<bits>"}.
 *
 * <p>Cross-validated against BouncyCastle's software
 * {@code KDFCounterBytesGenerator} and {@code KDFFeedbackBytesGenerator} with
 * random inputs, pins the NIST CAVP CounterMode KATs for both PRF families, and
 * exercises the negative path (each input must influence the derived key).</p>
 *
 * <p>BC agreement requires {@code useL == false} and {@code useSeparator ==
 * false}: OpenSSL defaults BOTH to true (the SP 800-108 canonical fixed input)
 * while BC emits the fixed input raw. That difference is invisible in a
 * Jostle-to-Jostle round trip, so {@link #useLAndSeparatorChangeTheOutput()}
 * pins the fact that the flags are live, and the agreement tests pin that OFF
 * is what matches an independent implementation.</p>
 */
public class KBKDFTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int TRIALS = 12;

    private static final String[] HMAC_ALGS = {
            "KBKDF-HMAC-SHA1", "KBKDF-HMAC-SHA224", "KBKDF-HMAC-SHA256",
            "KBKDF-HMAC-SHA384", "KBKDF-HMAC-SHA512"
    };

    private static final String[] CMAC_ALGS = {
            "KBKDF-CMAC-AES128", "KBKDF-CMAC-AES192", "KBKDF-CMAC-AES256"
    };

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
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static byte[] random(int length, SecureRandom sr)
    {
        byte[] bytes = new byte[length];
        sr.nextBytes(bytes);
        return bytes;
    }

    private static Digest bcDigestFor(String alg)
    {
        if (alg.endsWith("SHA1"))
        {
            return new SHA1Digest();
        }
        if (alg.endsWith("SHA224"))
        {
            return new SHA224Digest();
        }
        if (alg.endsWith("SHA256"))
        {
            return new SHA256Digest();
        }
        if (alg.endsWith("SHA384"))
        {
            return new SHA384Digest();
        }
        if (alg.endsWith("SHA512"))
        {
            return new SHA512Digest();
        }
        throw new IllegalArgumentException("no BC digest for " + alg);
    }

    private static int aesKeyBytesFor(String alg)
    {
        if (alg.endsWith("AES128"))
        {
            return 16;
        }
        if (alg.endsWith("AES192"))
        {
            return 24;
        }
        if (alg.endsWith("AES256"))
        {
            return 32;
        }
        throw new IllegalArgumentException("no AES size for " + alg);
    }

    @SuppressWarnings("deprecation")
    private static BlockCipher aesEngine()
    {
        return new AESEngine();
    }

    private static byte[] jostle(String alg, KBKDFParameterSpec spec) throws Exception
    {
        return SecretKeyFactory.getInstance(alg, JostleProvider.PROVIDER_NAME)
                .generateSecret(spec).getEncoded();
    }

    /** BC counter-mode reference: PRF(ki, [i]_r || fixedInput). */
    private static byte[] bcCounter(Mac prf, byte[] ki, byte[] fixedInput, int r, int len)
    {
        KDFCounterBytesGenerator gen = new KDFCounterBytesGenerator(prf);
        gen.init(new KDFCounterParameters(ki, fixedInput, r));
        byte[] out = new byte[len];
        gen.generateBytes(out, 0, len);
        return out;
    }

    /** BC feedback-mode reference: PRF(ki, K(i-1) || [i]_r || fixedInput). */
    private static byte[] bcFeedback(Mac prf, byte[] ki, byte[] iv, byte[] fixedInput, int r, int len)
    {
        KDFFeedbackBytesGenerator gen = new KDFFeedbackBytesGenerator(prf);
        gen.init(KDFFeedbackParameters.createWithCounter(ki, iv, fixedInput, r));
        byte[] out = new byte[len];
        gen.generateBytes(out, 0, len);
        return out;
    }

    /**
     * The fixed input goes in as the Context with no Label: OpenSSL concatenates
     * Label || [separator] || Context || [L], so with the separator and L off and
     * no Label the whole fixed input is the Context, matching BC exactly.
     */
    private static KBKDFParameterSpec rawSpec(byte[] ki, byte[] fixedInput, byte[] iv,
                                              KBKDFParameterSpec.Mode mode, int r, int len)
    {
        return new KBKDFParameterSpec(ki, null, fixedInput, iv, mode, r, false, false, len);
    }

    // ---------------------------------------------------------------- KATs

    /**
     * NIST CAVP SP 800-108 CounterMode, PRF = HMAC_SHA256, CTRLOCATION =
     * BEFORE_FIXED, RLEN = 8, COUNT = 0, L = 128.
     */
    @Test
    public void counterHmacSha256_cavpVector() throws Exception
    {
        byte[] ki = Hex.decode("3edc6b5b8f7aadbd713732b482b8f979286e1ea3b8f8f99c30c884cfe3349b83");
        byte[] fixed = Hex.decode(
                "98e9988bb4cc8b34d7922e1c68ad692ba2a1d9ae15149571675f17a77ad49e80"
                        + "c8d2a85e831a26445b1f0ff44d7084a17206b4896c8112daad18605a");
        byte[] expected = Hex.decode("6c037652990674a07844732d0ad985f9");

        Assertions.assertArrayEquals(expected,
                jostle("KBKDF-HMAC-SHA256",
                        rawSpec(ki, fixed, null, KBKDFParameterSpec.Mode.COUNTER, 8, 16)));

        // Differentiator: a single flipped fixed-input bit must change the key.
        // Without it a factory that ignored the Context would pass the vector
        // only by coincidence of the other inputs.
        byte[] tampered = Arrays.clone(fixed);
        tampered[0] ^= (byte) 0x01;
        Assertions.assertFalse(Arrays.areEqual(expected,
                jostle("KBKDF-HMAC-SHA256",
                        rawSpec(ki, tampered, null, KBKDFParameterSpec.Mode.COUNTER, 8, 16))),
                "flipping a fixed-input bit must change the derived key");
    }

    /**
     * NIST CAVP SP 800-108 CounterMode, PRF = CMAC_AES128, CTRLOCATION =
     * BEFORE_FIXED, RLEN = 8, COUNT = 0, L = 128.
     */
    @Test
    public void counterCmacAes128_cavpVector() throws Exception
    {
        byte[] ki = Hex.decode("dff1e50ac0b69dc40f1051d46c2b069c");
        byte[] fixed = Hex.decode(
                "c16e6e02c5a3dcc8d78b9ac1306877761310455b4e41469951d9e6c2245a064b"
                        + "33fd8c3b01203a7824485bf0a64060c4648b707d2607935699316ea5");
        byte[] expected = Hex.decode("8be8f0869b3c0ba97b71863d1b9f7813");

        Assertions.assertArrayEquals(expected,
                jostle("KBKDF-CMAC-AES128",
                        rawSpec(ki, fixed, null, KBKDFParameterSpec.Mode.COUNTER, 8, 16)));

        byte[] tamperedKi = Arrays.clone(ki);
        tamperedKi[0] ^= (byte) 0x01;
        Assertions.assertFalse(Arrays.areEqual(expected,
                jostle("KBKDF-CMAC-AES128",
                        rawSpec(tamperedKi, fixed, null, KBKDFParameterSpec.Mode.COUNTER, 8, 16))),
                "flipping a Ki bit must change the derived key");
    }

    // ----------------------------------------------------------- agreement

    @Test
    public void counterHmac_agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("counterHmac_agreesWithBouncyCastle");
        int[] rValues = {8, 16, 24, 32};

        for (String alg : HMAC_ALGS)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                byte[] ki = random(16 + sr.nextInt(48), sr);
                byte[] fixed = random(1 + sr.nextInt(96), sr);
                int r = rValues[sr.nextInt(rValues.length)];
                int len = 1 + sr.nextInt(200);

                byte[] mine = jostle(alg,
                        rawSpec(ki, fixed, null, KBKDFParameterSpec.Mode.COUNTER, r, len));
                byte[] theirs = bcCounter(new HMac(bcDigestFor(alg)), ki, fixed, r, len);

                Assertions.assertArrayEquals(theirs, mine,
                        alg + " counter r=" + r + " len=" + len);
            }
        }
    }

    @Test
    public void counterCmac_agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("counterCmac_agreesWithBouncyCastle");
        int[] rValues = {8, 16, 24, 32};

        for (String alg : CMAC_ALGS)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                byte[] ki = random(aesKeyBytesFor(alg), sr);
                byte[] fixed = random(1 + sr.nextInt(96), sr);
                int r = rValues[sr.nextInt(rValues.length)];
                int len = 1 + sr.nextInt(200);

                byte[] mine = jostle(alg,
                        rawSpec(ki, fixed, null, KBKDFParameterSpec.Mode.COUNTER, r, len));
                byte[] theirs = bcCounter(new CMac(aesEngine()), ki, fixed, r, len);

                Assertions.assertArrayEquals(theirs, mine,
                        alg + " counter r=" + r + " len=" + len);
            }
        }
    }

    /**
     * Feedback mode with an IV. This is why {@code KBKDFParameterSpec} carries
     * the IV at all: without it K(0) is empty and no real SP 800-108 feedback
     * peer can be matched.
     */
    @Test
    public void feedbackHmac_agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("feedbackHmac_agreesWithBouncyCastle");
        int[] rValues = {8, 16, 24, 32};

        for (String alg : HMAC_ALGS)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                byte[] ki = random(16 + sr.nextInt(48), sr);
                // OpenSSL requires the feedback IV to be exactly the PRF
                // output size (kbkdf.c "invalid seed length"); see
                // feedbackIvMustMatchThePrfOutputSize below.
                byte[] iv = random(bcDigestFor(alg).getDigestSize(), sr);
                byte[] fixed = random(1 + sr.nextInt(96), sr);
                int r = rValues[sr.nextInt(rValues.length)];
                int len = 1 + sr.nextInt(200);

                byte[] mine = jostle(alg,
                        rawSpec(ki, fixed, iv, KBKDFParameterSpec.Mode.FEEDBACK, r, len));
                byte[] theirs = bcFeedback(new HMac(bcDigestFor(alg)), ki, iv, fixed, r, len);

                Assertions.assertArrayEquals(theirs, mine,
                        alg + " feedback r=" + r + " len=" + len);
            }
        }
    }

    @Test
    public void feedbackCmac_agreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("feedbackCmac_agreesWithBouncyCastle");

        for (String alg : CMAC_ALGS)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                byte[] ki = random(aesKeyBytesFor(alg), sr);
                // CMAC's output size is the AES block size.
                byte[] iv = random(16, sr);
                byte[] fixed = random(1 + sr.nextInt(96), sr);
                int len = 1 + sr.nextInt(200);

                byte[] mine = jostle(alg,
                        rawSpec(ki, fixed, iv, KBKDFParameterSpec.Mode.FEEDBACK, 32, len));
                byte[] theirs = bcFeedback(new CMac(aesEngine()), ki, iv, fixed, 32, len);

                Assertions.assertArrayEquals(theirs, mine, alg + " feedback len=" + len);
            }
        }
    }

    // ------------------------------------------------------- negative path

    /**
     * Every caller-supplied input must influence the derived key. A factory
     * that dropped the Label, the Context or the IV would still round-trip
     * against itself, so each is varied one at a time against a fixed baseline.
     */
    @Test
    public void everyInputInfluencesTheDerivedKey() throws Exception
    {
        SecureRandom sr = seededRandom("everyInputInfluencesTheDerivedKey");
        byte[] ki = random(32, sr);
        byte[] label = random(9, sr);
        byte[] context = random(11, sr);
        byte[] iv = random(32, sr);  // SHA-256's output size; see feedbackIvMustMatchThePrfOutputSize

        byte[] base = jostle("KBKDF-HMAC-SHA256",
                new KBKDFParameterSpec(ki, label, context, iv,
                        KBKDFParameterSpec.Mode.FEEDBACK, 32, true, true, 40));

        byte[] otherKi = random(32, sr);
        byte[] otherLabel = random(9, sr);
        byte[] otherContext = random(11, sr);
        byte[] otherIv = random(32, sr);

        Assertions.assertFalse(Arrays.areEqual(base, jostle("KBKDF-HMAC-SHA256",
                        new KBKDFParameterSpec(otherKi, label, context, iv,
                                KBKDFParameterSpec.Mode.FEEDBACK, 32, true, true, 40))),
                "Ki must influence the derived key");
        Assertions.assertFalse(Arrays.areEqual(base, jostle("KBKDF-HMAC-SHA256",
                        new KBKDFParameterSpec(ki, otherLabel, context, iv,
                                KBKDFParameterSpec.Mode.FEEDBACK, 32, true, true, 40))),
                "Label must influence the derived key");
        Assertions.assertFalse(Arrays.areEqual(base, jostle("KBKDF-HMAC-SHA256",
                        new KBKDFParameterSpec(ki, label, otherContext, iv,
                                KBKDFParameterSpec.Mode.FEEDBACK, 32, true, true, 40))),
                "Context must influence the derived key");
        Assertions.assertFalse(Arrays.areEqual(base, jostle("KBKDF-HMAC-SHA256",
                        new KBKDFParameterSpec(ki, label, context, otherIv,
                                KBKDFParameterSpec.Mode.FEEDBACK, 32, true, true, 40))),
                "the feedback IV must influence the derived key");
        Assertions.assertFalse(Arrays.areEqual(base, jostle("KBKDF-HMAC-SHA256",
                        new KBKDFParameterSpec(ki, label, context, iv,
                                KBKDFParameterSpec.Mode.COUNTER, 32, true, true, 40))),
                "the mode must influence the derived key");
        // The digest comparison drops the IV: its required length is the PRF's
        // output size, so the same IV cannot be fed to SHA-256 and SHA-384.
        Assertions.assertFalse(Arrays.areEqual(
                        jostle("KBKDF-HMAC-SHA256", new KBKDFParameterSpec(
                                ki, label, context, null,
                                KBKDFParameterSpec.Mode.FEEDBACK, 32, true, true, 40)),
                        jostle("KBKDF-HMAC-SHA384", new KBKDFParameterSpec(
                                ki, label, context, null,
                                KBKDFParameterSpec.Mode.FEEDBACK, 32, true, true, 40))),
                "the PRF digest must influence the derived key");
    }

    /**
     * The two fixed-input flags are live, and OpenSSL's defaults are ON. This is
     * the property that decides whether Jostle agrees with BouncyCastle, and it
     * cannot be observed from a Jostle-only round trip — so it gets its own
     * assertion rather than being left implicit in the agreement tests.
     */
    @Test
    public void useLAndSeparatorChangeTheOutput() throws Exception
    {
        SecureRandom sr = seededRandom("useLAndSeparatorChangeTheOutput");
        byte[] ki = random(32, sr);
        byte[] label = random(7, sr);
        byte[] context = random(17, sr);

        byte[] bothOn = jostle("KBKDF-HMAC-SHA256", new KBKDFParameterSpec(
                ki, label, context, null, KBKDFParameterSpec.Mode.COUNTER, 32, true, true, 32));
        byte[] bothOff = jostle("KBKDF-HMAC-SHA256", new KBKDFParameterSpec(
                ki, label, context, null, KBKDFParameterSpec.Mode.COUNTER, 32, false, false, 32));
        byte[] lOnly = jostle("KBKDF-HMAC-SHA256", new KBKDFParameterSpec(
                ki, label, context, null, KBKDFParameterSpec.Mode.COUNTER, 32, true, false, 32));
        byte[] sepOnly = jostle("KBKDF-HMAC-SHA256", new KBKDFParameterSpec(
                ki, label, context, null, KBKDFParameterSpec.Mode.COUNTER, 32, false, true, 32));

        Assertions.assertFalse(Arrays.areEqual(bothOn, bothOff), "useL/useSeparator must be live");
        Assertions.assertFalse(Arrays.areEqual(bothOn, lOnly), "useSeparator alone must be live");
        Assertions.assertFalse(Arrays.areEqual(bothOn, sepOnly), "useL alone must be live");

        // The four-argument convenience constructor must pick the canonical
        // SP 800-108 form, i.e. both flags on. A default that silently differed
        // from the documented one is exactly the kind of drift a round trip
        // cannot see.
        byte[] viaDefaults = jostle("KBKDF-HMAC-SHA256",
                new KBKDFParameterSpec(ki, label, context, 32));
        Assertions.assertArrayEquals(bothOn, viaDefaults,
                "the short constructor must default to useL = useSeparator = true, r = 32, COUNTER");
    }

    /**
     * Two different output lengths must not merely be prefixes of each other in
     * counter mode... they legitimately ARE, because SP 800-108 counter mode is
     * a stream. What must NOT happen is the {@code [L]} field being ignored:
     * with {@code useL} on, changing L changes every block.
     */
    @Test
    public void outputLengthIsBoundInWhenUseLIsOn() throws Exception
    {
        SecureRandom sr = seededRandom("outputLengthIsBoundInWhenUseLIsOn");
        byte[] ki = random(32, sr);
        byte[] context = random(20, sr);

        byte[] shortKey = jostle("KBKDF-HMAC-SHA256", new KBKDFParameterSpec(
                ki, null, context, null, KBKDFParameterSpec.Mode.COUNTER, 32, true, true, 16));
        byte[] longKey = jostle("KBKDF-HMAC-SHA256", new KBKDFParameterSpec(
                ki, null, context, null, KBKDFParameterSpec.Mode.COUNTER, 32, true, true, 32));

        Assertions.assertFalse(
                Arrays.areEqual(shortKey, Arrays.copyOfRange(longKey, 0, shortKey.length)),
                "with useL on, L is bound into the input so lengths must not share a prefix");

        // With useL off, L is not bound in and counter mode IS a stream: the
        // shorter derivation must be a prefix of the longer one. Pinning both
        // halves proves the flag selects between two real behaviours.
        byte[] shortRaw = jostle("KBKDF-HMAC-SHA256", new KBKDFParameterSpec(
                ki, null, context, null, KBKDFParameterSpec.Mode.COUNTER, 32, false, false, 16));
        byte[] longRaw = jostle("KBKDF-HMAC-SHA256", new KBKDFParameterSpec(
                ki, null, context, null, KBKDFParameterSpec.Mode.COUNTER, 32, false, false, 32));
        Assertions.assertArrayEquals(shortRaw, Arrays.copyOfRange(longRaw, 0, shortRaw.length),
                "with useL off the shorter derivation must be a prefix of the longer");
    }

    /**
     * The feedback IV must be exactly the PRF's output size — OpenSSL's
     * {@code kbkdf_derive} refuses any other non-zero length with "invalid
     * seed length". Not a Java-side check (the spec does not know which PRF it
     * will be handed to), so this pins BOTH branches against the real
     * provider: the exact size derives, one byte either side is refused, and
     * absent is accepted as "no IV".
     */
    @Test
    public void feedbackIvMustMatchThePrfOutputSize() throws Exception
    {
        SecureRandom sr = seededRandom("feedbackIvMustMatchThePrfOutputSize");
        byte[] ki = random(32, sr);
        byte[] context = random(20, sr);

        for (String alg : HMAC_ALGS)
        {
            int h = bcDigestFor(alg).getDigestSize();

            Assertions.assertEquals(32, jostle(alg,
                    rawSpec(ki, context, random(h, sr),
                            KBKDFParameterSpec.Mode.FEEDBACK, 32, 32)).length,
                    alg + " must accept an IV of exactly " + h + " bytes");

            for (int bad : new int[]{h - 1, h + 1})
            {
                OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                        () -> jostle(alg, rawSpec(ki, context, random(bad, sr),
                                KBKDFParameterSpec.Mode.FEEDBACK, 32, 32)),
                        alg + " must refuse an IV of " + bad + " bytes");
                Assertions.assertTrue(e.getMessage().contains("invalid seed length"),
                        "unexpected message: " + e.getMessage());
            }
        }

        // CMAC's output size is the AES block size regardless of key size.
        for (String alg : CMAC_ALGS)
        {
            byte[] cmacKi = random(aesKeyBytesFor(alg), sr);
            Assertions.assertEquals(32, jostle(alg,
                    rawSpec(cmacKi, context, random(16, sr),
                            KBKDFParameterSpec.Mode.FEEDBACK, 32, 32)).length,
                    alg + " must accept a 16-byte IV");
            OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                    () -> jostle(alg, rawSpec(cmacKi, context, random(17, sr),
                            KBKDFParameterSpec.Mode.FEEDBACK, 32, 32)));
            Assertions.assertTrue(e.getMessage().contains("invalid seed length"),
                    "unexpected message: " + e.getMessage());
        }

        // An absent IV is "no IV", not a zero-length one that trips the check.
        Assertions.assertEquals(32, jostle("KBKDF-HMAC-SHA256",
                rawSpec(ki, context, null, KBKDFParameterSpec.Mode.FEEDBACK, 32, 32)).length);
    }

    @Test
    public void derivationIsDeterministic() throws Exception
    {
        SecureRandom sr = seededRandom("derivationIsDeterministic");
        byte[] ki = random(32, sr);
        byte[] context = random(20, sr);
        KBKDFParameterSpec spec = new KBKDFParameterSpec(ki, null, context, 48);

        Assertions.assertArrayEquals(jostle("KBKDF-HMAC-SHA256", spec),
                jostle("KBKDF-HMAC-SHA256", spec));
    }

    // -------------------------------------------------------- spec contract

    @Test
    public void specRejectsInvalidArguments()
    {
        byte[] ki = new byte[32];

        Assertions.assertEquals("ki is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new KBKDFParameterSpec(null, null, null, 16)).getMessage());

        Assertions.assertEquals("output length must be positive", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new KBKDFParameterSpec(ki, null, null, 0)).getMessage());

        Assertions.assertEquals("output length must be positive", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new KBKDFParameterSpec(ki, null, null, -1)).getMessage());

        Assertions.assertEquals("output length must be positive", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new KBKDFParameterSpec(ki, null, null, Integer.MIN_VALUE)).getMessage());

        Assertions.assertEquals("mode is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new KBKDFParameterSpec(ki, null, null, null, null, 32, true, true, 16))
                .getMessage());

        for (int badR : new int[]{-1, 0, 1, 7, 9, 33, 64, Integer.MIN_VALUE})
        {
            Assertions.assertEquals("r must be one of 8, 16, 24 or 32 bits, got " + badR,
                    Assertions.assertThrows(IllegalArgumentException.class,
                            () -> new KBKDFParameterSpec(ki, null, null, null,
                                    KBKDFParameterSpec.Mode.COUNTER, badR, true, true, 16))
                            .getMessage());
        }

        for (int goodR : new int[]{8, 16, 24, 32})
        {
            Assertions.assertEquals(goodR, new KBKDFParameterSpec(ki, null, null, null,
                    KBKDFParameterSpec.Mode.COUNTER, goodR, true, true, 16).getR());
        }
    }

    /** Accessors must hand back copies, not the spec's live arrays. */
    @Test
    public void specAccessorsReturnCopies()
    {
        byte[] ki = new byte[]{1, 2, 3, 4};
        byte[] label = new byte[]{5, 6};
        byte[] context = new byte[]{7, 8};
        byte[] iv = new byte[]{9, 10};
        KBKDFParameterSpec spec = new KBKDFParameterSpec(ki, label, context, iv,
                KBKDFParameterSpec.Mode.FEEDBACK, 32, true, true, 16);

        spec.getKI()[0] = (byte) 0xff;
        spec.getLabel()[0] = (byte) 0xff;
        spec.getContext()[0] = (byte) 0xff;
        spec.getIV()[0] = (byte) 0xff;

        Assertions.assertEquals(1, spec.getKI()[0]);
        Assertions.assertEquals(5, spec.getLabel()[0]);
        Assertions.assertEquals(7, spec.getContext()[0]);
        Assertions.assertEquals(9, spec.getIV()[0]);

        // Constructor copies too: mutating the caller's array must not change
        // what the spec holds.
        ki[0] = (byte) 0xff;
        Assertions.assertEquals(1, spec.getKI()[0]);
    }

    @Test
    public void factoryRejectsWrongKeySpec() throws Exception
    {
        SecretKeyFactory f = SecretKeyFactory.getInstance("KBKDF-HMAC-SHA256",
                JostleProvider.PROVIDER_NAME);

        Assertions.assertEquals("unsupported KeySpec null", Assertions.assertThrows(
                InvalidKeySpecException.class, () -> f.generateSecret(null)).getMessage());

        Assertions.assertTrue(Assertions.assertThrows(InvalidKeySpecException.class,
                        () -> f.generateSecret(new javax.crypto.spec.PBEKeySpec("x".toCharArray())))
                .getMessage().startsWith("unsupported KeySpec javax.crypto.spec.PBEKeySpec"));
    }

    /**
     * Every registered KBKDF name must actually derive. Registration is not
     * usability — {@code getInstance} succeeding says nothing about the PRF
     * name reaching a provider that serves it.
     */
    @Test
    public void everyRegisteredNameDerives() throws Exception
    {
        SecureRandom sr = seededRandom("everyRegisteredNameDerives");

        for (String alg : HMAC_ALGS)
        {
            byte[] out = jostle(alg, new KBKDFParameterSpec(random(32, sr), null, random(8, sr), 32));
            Assertions.assertEquals(32, out.length, alg);
            Assertions.assertFalse(Arrays.areEqual(new byte[32], out), alg + " produced zeros");
        }
        for (String alg : CMAC_ALGS)
        {
            byte[] out = jostle(alg,
                    new KBKDFParameterSpec(random(aesKeyBytesFor(alg), sr), null, random(8, sr), 32));
            Assertions.assertEquals(32, out.length, alg);
            Assertions.assertFalse(Arrays.areEqual(new byte[32], out), alg + " produced zeros");
        }
    }
}
