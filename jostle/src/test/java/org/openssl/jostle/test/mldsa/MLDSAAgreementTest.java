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

package org.openssl.jostle.test.mldsa;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAPrivateKeySpec;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Cross-implementation agreement for the WHOLE base-provider ({@code JSL})
 * ML-DSA surface, against BouncyCastle 1.86.
 * <p>
 * Non-FIPS counterpart of {@code FIPSMLDSAAgreementTest}. Neither substitutes
 * for the other: they drive different native libraries and different lib ctxs,
 * and the FIPS half is gated on what the loaded module can fetch.
 * <p>
 * <b>What "agrees" means here, and why it is not the signature bytes.</b>
 * Jostle's ML-DSA signs HEDGED — two signings of one message differ —
 * while BouncyCastle's JCE ML-DSA is DETERMINISTIC, and Jostle exposes no
 * deterministic ML-DSA. So signature byte-equality is unavailable and is not
 * asserted; each direction is cross-verified against the other implementation
 * instead, which a wrong-but-self-consistent implementation cannot satisfy.
 * Byte equality is asserted where it IS available and load-bearing: from one
 * shared 32-byte seed the two providers' key encodings are compared byte for
 * byte ({@link #sharedSeedYieldsByteEqualKeyEncodings}), and the external-mu
 * digest is compared byte for byte ({@link #externalMuAgreesWithBouncyCastle}).
 * <p>
 * <b>Reference provider.</b> Every BouncyCastle object this class uses asserts
 * its own provider name before its result is believed. Without that, a driver
 * that resolved the reference back to JSL would compare Jostle with itself and
 * pass — and {@code assertEveryServiceDriven} catches Throwable per entry, so
 * it would pass silently.
 * <p>
 * Depth stays elsewhere: {@link MLDSATest} keeps the parameter-spec contracts,
 * state-machine sequences, seed handling and context coverage,
 * {@link MLDSALimitTest} the NI rejections.
 * <p>
 * <b>Falsification (2026-09-19).</b> RED: dropping the {@code ML-DSA-87} arm
 * from {@link #bcSignatureName} failed {@link #everyRegisteredMlDsaServiceIsDriven}
 * naming {@code Signature.ML-DSA-87} and its OID alias, while
 * {@code SLHDSAAgreementTest}'s guard stayed green. RED: replacing the BC
 * verifier with a JSL verifier failed the reference-provider assertion in the
 * same cell. GREEN: restored, both green.
 * <p>
 * Inputs come from a per-test SHA1PRNG whose seed is logged.
 */
public class MLDSAAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** The three JCA types {@code ProvMLDSA} registers under. */
    private static final String[] GUARDED_TYPES = {"KeyFactory", "KeyPairGenerator", "Signature"};

    /** The three parameter sets, under the name both providers register. */
    private static final String[] PARAM_SETS = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};

    /**
     * The parameter set every name that does not pin one is driven with. The
     * bare names and the two mu names accept any ML-DSA key.
     */
    private static final String DEFAULT_SET = "ML-DSA-65";

    /**
     * NIST CSOR id-ml-dsa-44/65/87, as the SubjectPublicKeyInfo must carry
     * them. Dotted literals are deliberate in tests (they are the wire fact
     * being pinned); production uses the oids constants.
     */
    private static final Map<String, String> SPKI_OID = new LinkedHashMap<String, String>();

    static
    {
        SPKI_OID.put("ML-DSA-44", "2.16.840.1.101.3.4.3.17");
        SPKI_OID.put("ML-DSA-65", "2.16.840.1.101.3.4.3.18");
        SPKI_OID.put("ML-DSA-87", "2.16.840.1.101.3.4.3.19");
    }

    private static final int TRIALS = 10;

    private static final SecureRandom RANDOM = new SecureRandom();

    /** One keypair per parameter set, shared across cells; keygen is not the subject. */
    private static final Map<String, KeyPair> KEY_PAIRS = new HashMap<String, KeyPair>();

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

    // -----------------------------------------------------------------
    // Provider plumbing
    // -----------------------------------------------------------------

    /** A JSL keypair for one parameter set, generated once per JVM. */
    private static synchronized KeyPair keyPair(String paramSet) throws Exception
    {
        KeyPair kp = KEY_PAIRS.get(paramSet);
        if (kp == null)
        {
            kp = KeyPairGenerator.getInstance(paramSet, JSL).generateKeyPair();
            KEY_PAIRS.put(paramSet, kp);
        }
        return kp;
    }

    /**
     * A BouncyCastle Signature under {@code alg}, with its provider asserted.
     * <p>
     * The assertion is the point: a reference that silently resolved back to
     * JSL would make every agreement cell compare Jostle with itself.
     */
    private static Signature bcSignature(String alg) throws Exception
    {
        Signature s = Signature.getInstance(alg, BC);
        Assertions.assertEquals(BC, s.getProvider().getName(),
                "the reference signature for " + alg + " did not come from BouncyCastle");
        return s;
    }

    /** A BouncyCastle KeyFactory, with its provider asserted. */
    private static KeyFactory bcKeyFactory(String alg) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(alg, BC);
        Assertions.assertEquals(BC, kf.getProvider().getName(),
                "the reference key factory for " + alg + " did not come from BouncyCastle");
        return kf;
    }

    /**
     * The name a registered JSL service resolves to in the registrar's own
     * alias table. Resolving the alias first is what stops the driver guessing
     * a parameter set from an OID, which contains no "44" / "65" / "87".
     */
    private static String primaryOf(String type, String alg)
    {
        Provider provider = Security.getProvider(JSL);
        String primary = provider.getProperty("Alg.Alias." + type + "." + alg);
        return (primary == null ? alg : primary).toUpperCase(Locale.ROOT);
    }

    /** The parameter set a registered name operates on, resolved through the primary. */
    private static String paramSetOf(String type, String alg)
    {
        String primary = primaryOf(type, alg);
        for (String set : PARAM_SETS)
        {
            if (primary.equals(set))
            {
                return set;
            }
        }
        return DEFAULT_SET;
    }

    /**
     * BouncyCastle's JCE spelling for one of our registered Signature names.
     * <p>
     * Measured on bcprov 1.86, not guessed: BC serves {@code ML-DSA},
     * {@code ML-DSA-44/65/87}, {@code ML-DSA-CALCULATE-MU} and
     * {@code ML-DSA-EXTERNAL-MU}, but NOT the unhyphenated {@code MLDSA} as a
     * Signature. THROWS on an unknown name, so a newly registered variant
     * fails the completeness guard rather than going unexercised.
     */
    private static String bcSignatureName(String type, String alg)
    {
        String primary = primaryOf(type, alg);
        if ("MLDSA".equals(primary))
        {
            return "ML-DSA";
        }
        if ("ML-DSA-44".equals(primary) || "ML-DSA-65".equals(primary) || "ML-DSA-87".equals(primary))
        {
            return primary;
        }
        if ("ML-DSA-CALCULATE-MU".equals(primary) || "ML-DSA-EXTERNAL-MU".equals(primary))
        {
            return primary;
        }
        throw new IllegalStateException("no BouncyCastle reference defined for Signature." + alg
                + " (primary " + primary + ") — teach bcSignatureName rather than leaving it unexercised");
    }

    private static byte[] sign(String provider, String alg, PrivateKey key, byte[] msg, byte[] ctx)
            throws Exception
    {
        Signature s = BC.equals(provider) ? bcSignature(alg) : Signature.getInstance(alg, JSL);
        if (ctx != null)
        {
            s.setParameter(BC.equals(provider)
                    ? new org.bouncycastle.jcajce.spec.ContextParameterSpec(ctx)
                    : new ContextParameterSpec(ctx));
        }
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    private static boolean verify(String provider, String alg, PublicKey key, byte[] msg, byte[] sig,
                                  byte[] ctx) throws Exception
    {
        Signature s = BC.equals(provider) ? bcSignature(alg) : Signature.getInstance(alg, JSL);
        if (ctx != null)
        {
            s.setParameter(BC.equals(provider)
                    ? new org.bouncycastle.jcajce.spec.ContextParameterSpec(ctx)
                    : new ContextParameterSpec(ctx));
        }
        s.initVerify(key);
        s.update(msg);
        return s.verify(sig);
    }

    /** The BC view of a JSL public key, crossed through its encoding. */
    private static PublicKey bcPublic(PublicKey jslKey) throws Exception
    {
        return bcKeyFactory("ML-DSA").generatePublic(new X509EncodedKeySpec(jslKey.getEncoded()));
    }

    /** The BC view of a JSL private key, crossed through its encoding. */
    private static PrivateKey bcPrivate(PrivateKey jslKey) throws Exception
    {
        return bcKeyFactory("ML-DSA").generatePrivate(new PKCS8EncodedKeySpec(jslKey.getEncoded()));
    }

    // -----------------------------------------------------------------
    // Completeness guards
    // -----------------------------------------------------------------

    /**
     * Every ML-DSA service JSL registers is DRIVEN against BouncyCastle,
     * discovered by SPI class-name prefix, aliases included — which is what
     * covers the three CSOR OID spellings and the unhyphenated {@code MLDSA}.
     */
    @Test
    public void everyRegisteredMlDsaServiceIsDriven() throws Exception
    {
        final SecureRandom sr = seededRandom("everyRegisteredMlDsaServiceIsDriven");

        ProviderSurfaceGuard.assertEveryServiceDriven(Security.getProvider(JSL),
                CipherFamilies.MLDSA_PREFIX, "ML-DSA (JSL)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        String set = paramSetOf(type, alg);
                        KeyPair kp = keyPair(set);
                        byte[] msg = new byte[1 + sr.nextInt(256)];
                        sr.nextBytes(msg);

                        if ("Signature".equals(type))
                        {
                            driveSignature(type, alg, set, kp, msg);
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            PublicKey pub = KeyFactory.getInstance(alg, JSL)
                                    .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
                            Assertions.assertTrue(
                                    Arrays.areEqual(kp.getPublic().getEncoded(), pub.getEncoded()),
                                    alg + ": re-encoded a public key differently");
                            PrivateKey priv = KeyFactory.getInstance(alg, JSL)
                                    .generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
                            // BC must accept what this KeyFactory produced.
                            Assertions.assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(),
                                            bcPublic(pub).getEncoded()),
                                    alg + ": BouncyCastle re-encoded the crossed public key differently");
                            byte[] sig = sign(JSL, set, priv, msg, null);
                            Assertions.assertTrue(verify(BC, set, bcPublic(pub), msg, sig, null),
                                    alg + ": BouncyCastle rejected a signature from the crossed key");
                        }
                        else if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, JSL);
                            // The bare names take any set; pin one so the driver
                            // does not depend on an SPI default.
                            if (DEFAULT_SET.equals(set) && !primaryOf(type, alg).equals(DEFAULT_SET))
                            {
                                kpg.initialize(MLDSAParameterSpec.fromName(DEFAULT_SET));
                            }
                            KeyPair generated = kpg.generateKeyPair();
                            byte[] sig = sign(JSL, set, generated.getPrivate(), msg, null);
                            Assertions.assertTrue(
                                    verify(BC, set, bcPublic(generated.getPublic()), msg, sig, null),
                                    alg + ": BouncyCastle rejected a signature from a generated keypair");
                        }
                        else
                        {
                            throw new IllegalStateException("no drive defined for " + type + "." + alg
                                    + " — teach this driver rather than letting it go unexercised");
                        }
                    }
                });
    }

    /**
     * One Signature name, driven against BouncyCastle. Split out of the driver
     * because the two mu names are a different operation from a signature.
     */
    private static void driveSignature(String type, String alg, String set, KeyPair kp, byte[] msg)
            throws Exception
    {
        String bcAlg = bcSignatureName(type, alg);
        String primary = primaryOf(type, alg);

        if ("ML-DSA-CALCULATE-MU".equals(primary))
        {
            byte[] mu = sign(JSL, alg, kp.getPrivate(), msg, null);
            Signature bcCalc = bcSignature(bcAlg);
            bcCalc.initSign(bcPrivate(kp.getPrivate()));
            bcCalc.update(msg);
            Assertions.assertArrayEquals(bcCalc.sign(), mu,
                    alg + ": mu differs from BouncyCastle's");
            return;
        }

        if ("ML-DSA-EXTERNAL-MU".equals(primary))
        {
            byte[] mu = sign(JSL, "ML-DSA-CALCULATE-MU", kp.getPrivate(), msg, null);
            byte[] sig = sign(JSL, alg, kp.getPrivate(), mu, null);
            Assertions.assertTrue(verify(BC, bcAlg, bcPublic(kp.getPublic()), mu, sig, null),
                    alg + ": BouncyCastle rejected an external-mu signature");
            return;
        }

        byte[] sig = sign(JSL, alg, kp.getPrivate(), msg, null);
        Assertions.assertTrue(verify(BC, bcAlg, bcPublic(kp.getPublic()), msg, sig, null),
                alg + ": BouncyCastle rejected a JSL signature");
        byte[] bcSig = sign(BC, bcAlg, bcPrivate(kp.getPrivate()), msg, null);
        Assertions.assertTrue(verify(JSL, alg, kp.getPublic(), msg, bcSig, null),
                alg + ": JSL rejected a BouncyCastle signature");
    }

    /** The removal direction, at type granularity. */
    @Test
    public void everyGuardedTypeIsStillRegistered()
    {
        SortedSet<String> surface = ProviderSurfaceGuard.registeredSurface(
                Security.getProvider(JSL), CipherFamilies.MLDSA_PREFIX, GUARDED_TYPES);

        SortedSet<String> missing = new TreeSet<String>();
        for (String type : GUARDED_TYPES)
        {
            boolean found = false;
            for (String entry : surface)
            {
                if (entry.startsWith(type + "."))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                missing.add(type);
            }
        }
        Assertions.assertTrue(missing.isEmpty(),
                "JSL no longer registers any ML-DSA service of these types: " + missing);
    }

    // -----------------------------------------------------------------
    // Signature agreement
    // -----------------------------------------------------------------

    /**
     * Every parameter set, both directions, with the two differentiators a
     * cross-verification needs: a tampered message and a foreign key.
     */
    @Test
    public void signaturesCrossVerifyWithBouncyCastleBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("signaturesCrossVerifyWithBouncyCastleBothDirections");

        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            PrivateKey bcPriv = bcPrivate(kp.getPrivate());

            for (int t = 0; t < TRIALS; t++)
            {
                byte[] msg = new byte[1 + sr.nextInt(1024)];
                sr.nextBytes(msg);

                byte[] jslSig = sign(JSL, set, kp.getPrivate(), msg, null);
                Assertions.assertTrue(verify(BC, set, bcPub, msg, jslSig, null),
                        set + ": BouncyCastle rejected a JSL signature");

                byte[] bcSig = sign(BC, set, bcPriv, msg, null);
                Assertions.assertTrue(verify(JSL, set, kp.getPublic(), msg, bcSig, null),
                        set + ": JSL rejected a BouncyCastle signature");

                byte[] tampered = Arrays.clone(msg);
                tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(verify(JSL, set, kp.getPublic(), tampered, bcSig, null),
                        set + ": JSL accepted a signature over a tampered message");
                Assertions.assertFalse(verify(BC, set, bcPub, tampered, jslSig, null),
                        set + ": BouncyCastle accepted a signature over a tampered message");

                byte[] mangled = Arrays.clone(jslSig);
                mangled[sr.nextInt(mangled.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(verify(BC, set, bcPub, msg, mangled, null),
                        set + ": BouncyCastle accepted a tampered signature");
            }

            // A key from a DIFFERENT pair of the same set must not verify.
            KeyPair other = KeyPairGenerator.getInstance(set, JSL).generateKeyPair();
            byte[] msg = new byte[64];
            sr.nextBytes(msg);
            byte[] sig = sign(JSL, set, kp.getPrivate(), msg, null);
            Assertions.assertFalse(verify(BC, set, bcPublic(other.getPublic()), msg, sig, null),
                    set + ": BouncyCastle accepted a signature under the wrong public key");
        }
    }

    /**
     * Jostle signs HEDGED, BouncyCastle's JCE DETERMINISTICALLY. Both halves
     * are pinned, so a change on either side is reported here rather than as a
     * byte mismatch in an agreement cell — and this is why
     * {@link #signaturesCrossVerifyWithBouncyCastleBothDirections} compares
     * behaviour, not bytes.
     */
    @Test
    public void jostleSignsHedgedWhileBouncyCastleSignsDeterministically() throws Exception
    {
        SecureRandom sr = seededRandom("jostleSignsHedgedWhileBouncyCastleSignsDeterministically");
        byte[] msg = new byte[128];
        sr.nextBytes(msg);

        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            Assertions.assertFalse(Arrays.areEqual(sign(JSL, set, kp.getPrivate(), msg, null),
                            sign(JSL, set, kp.getPrivate(), msg, null)),
                    set + ": JSL now signs deterministically — the byte comparison can be tightened");

            PrivateKey bcPriv = bcPrivate(kp.getPrivate());
            Assertions.assertTrue(Arrays.areEqual(sign(BC, set, bcPriv, msg, null),
                            sign(BC, set, bcPriv, msg, null)),
                    set + ": BouncyCastle no longer signs deterministically");
        }
    }

    /**
     * The ML-DSA context string is load-bearing on both sides: a signature made
     * under one context must not verify under another, and each provider agrees
     * with the other about which context is wrong.
     * <p>
     * Without this the context could be ignored by both and every agreement
     * cell above would still pass.
     */
    @Test
    public void theContextStringIsLoadBearingOnBothSides() throws Exception
    {
        SecureRandom sr = seededRandom("theContextStringIsLoadBearingOnBothSides");

        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            byte[] msg = new byte[96];
            sr.nextBytes(msg);
            byte[] ctxA = new byte[8];
            byte[] ctxB = new byte[8];
            sr.nextBytes(ctxA);
            do
            {
                sr.nextBytes(ctxB);
            }
            while (Arrays.areEqual(ctxA, ctxB));

            byte[] sig = sign(JSL, set, kp.getPrivate(), msg, ctxA);
            Assertions.assertTrue(verify(BC, set, bcPub, msg, sig, ctxA),
                    set + ": BouncyCastle rejected a signature under its own context");
            Assertions.assertFalse(verify(BC, set, bcPub, msg, sig, ctxB),
                    set + ": BouncyCastle accepted a signature under a DIFFERENT context");
            Assertions.assertFalse(verify(JSL, set, kp.getPublic(), msg, sig, ctxB),
                    set + ": JSL accepted a signature under a DIFFERENT context");
            Assertions.assertFalse(verify(BC, set, bcPub, msg, sig, null),
                    set + ": BouncyCastle accepted a context signature with no context");
        }
    }

    /**
     * The mu digest is byte-equal across the two providers, and an external-mu
     * signature crosses in both directions.
     * <p>
     * BouncyCastle 1.86 DOES serve both mu names through the JCE
     * ({@code SignatureSpi$MLDSACalcMu} / {@code $MLDSAExtMu}), measured
     * 2026-09-19 — so neither needs a lightweight fallback.
     */
    @Test
    public void externalMuAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("externalMuAgreesWithBouncyCastle");

        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            PrivateKey bcPriv = bcPrivate(kp.getPrivate());

            for (int t = 0; t < TRIALS; t++)
            {
                byte[] msg = new byte[1 + sr.nextInt(512)];
                sr.nextBytes(msg);

                byte[] mu = sign(JSL, "ML-DSA-CALCULATE-MU", kp.getPrivate(), msg, null);
                Signature bcCalc = bcSignature("ML-DSA-CALCULATE-MU");
                bcCalc.initSign(bcPriv);
                bcCalc.update(msg);
                byte[] bcMu = bcCalc.sign();
                Assertions.assertArrayEquals(bcMu, mu, set + ": mu differs from BouncyCastle's");
                Assertions.assertEquals(64, mu.length, set + ": mu is not 64 bytes");

                byte[] jslSig = sign(JSL, "ML-DSA-EXTERNAL-MU", kp.getPrivate(), mu, null);
                Assertions.assertTrue(verify(BC, "ML-DSA-EXTERNAL-MU", bcPub, bcMu, jslSig, null),
                        set + ": BouncyCastle rejected a JSL external-mu signature");

                byte[] bcSig = sign(BC, "ML-DSA-EXTERNAL-MU", bcPriv, bcMu, null);
                Assertions.assertTrue(verify(JSL, "ML-DSA-EXTERNAL-MU", kp.getPublic(), mu, bcSig, null),
                        set + ": JSL rejected a BouncyCastle external-mu signature");

                // A mu that is not this message's must not verify.
                byte[] wrongMu = Arrays.clone(mu);
                wrongMu[sr.nextInt(wrongMu.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(
                        verify(BC, "ML-DSA-EXTERNAL-MU", bcPub, wrongMu, jslSig, null),
                        set + ": BouncyCastle accepted an external-mu signature over the wrong mu");
            }
        }
    }

    /**
     * The same message split several ways produces a signature BouncyCastle
     * verifies, on every parameter set.
     * <p>
     * Chunking is a dimension of the {@code update} contract that the
     * per-name completeness guard cannot see. The independent verifier is the
     * point: {@code MLDSATest}'s chunking matrix verifies with Jostle, so a
     * buffering fault shared by our signer and verifier passes it.
     */
    @Test
    public void chunkedUpdatesProduceSignaturesBouncyCastleVerifies() throws Exception
    {
        SecureRandom sr = seededRandom("chunkedUpdatesProduceSignaturesBouncyCastleVerifies");

        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            byte[] msg = new byte[1 + sr.nextInt(600)];
            sr.nextBytes(msg);

            for (int step : new int[]{0, 1, 31, 32, 33, 64})
            {
                Signature s = Signature.getInstance(set, JSL);
                s.initSign(kp.getPrivate());
                if (step == 0)
                {
                    s.update(msg);
                }
                else
                {
                    for (int off = 0; off < msg.length; off += step)
                    {
                        s.update(msg, off, Math.min(step, msg.length - off));
                    }
                }
                byte[] sig = s.sign();
                Assertions.assertTrue(verify(BC, set, bcPub, msg, sig, null),
                        set + ": BouncyCastle rejected a signature built from " + step + "-byte chunks");
            }

            // Random splits, so the boundaries do not always fall on a power of two.
            for (int t = 0; t < TRIALS; t++)
            {
                Signature s = Signature.getInstance(set, JSL);
                s.initSign(kp.getPrivate());
                int off = 0;
                while (off < msg.length)
                {
                    int n = 1 + sr.nextInt(msg.length - off);
                    s.update(msg, off, n);
                    off += n;
                }
                Assertions.assertTrue(verify(BC, set, bcPub, msg, s.sign(), null),
                        set + ": BouncyCastle rejected a signature built from random splits");
            }
        }
    }

    // -----------------------------------------------------------------
    // Key encodings
    // -----------------------------------------------------------------

    /**
     * A generated ML-DSA keypair round-trips through BouncyCastle byte for
     * byte, on both halves and in both directions, and still operates.
     */
    @Test
    public void keysRoundTripThroughBothKeyFactories() throws Exception
    {
        SecureRandom sr = seededRandom("keysRoundTripThroughBothKeyFactories");

        for (String set : PARAM_SETS)
        {
            KeyFactory jslKf = KeyFactory.getInstance(set, JSL);
            KeyPair jslPair = keyPair(set);

            Assertions.assertTrue(Arrays.areEqual(jslPair.getPublic().getEncoded(),
                            bcPublic(jslPair.getPublic()).getEncoded()),
                    set + ": BouncyCastle re-encoded a JSL public key differently");
            Assertions.assertTrue(Arrays.areEqual(jslPair.getPrivate().getEncoded(),
                            bcPrivate(jslPair.getPrivate()).getEncoded()),
                    set + ": BouncyCastle re-encoded a JSL private key differently");

            KeyPair bcPair = KeyPairGenerator.getInstance(set, BC).generateKeyPair();
            PublicKey viaJslPub = jslKf.generatePublic(
                    new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));
            PrivateKey viaJslPriv = jslKf.generatePrivate(
                    new PKCS8EncodedKeySpec(bcPair.getPrivate().getEncoded()));
            Assertions.assertTrue(Arrays.areEqual(bcPair.getPublic().getEncoded(),
                            viaJslPub.getEncoded()),
                    set + ": JSL re-encoded a BouncyCastle public key differently");
            Assertions.assertTrue(Arrays.areEqual(bcPair.getPrivate().getEncoded(),
                            viaJslPriv.getEncoded()),
                    set + ": JSL re-encoded a BouncyCastle private key differently");

            byte[] msg = new byte[64];
            sr.nextBytes(msg);
            byte[] sig = sign(JSL, set, viaJslPriv, msg, null);
            Signature bcCheck = bcSignature(set);
            bcCheck.initVerify(bcPair.getPublic());
            bcCheck.update(msg);
            Assertions.assertTrue(bcCheck.verify(sig),
                    set + ": a round-tripped BouncyCastle keypair no longer matches its own public key");
        }
    }

    /**
     * From ONE shared 32-byte seed, the two providers derive byte-identical
     * keys — the strongest agreement available for a family whose signatures
     * cannot be byte-compared.
     * <p>
     * Sign-here / verify-there cannot see two implementations that expand a
     * seed differently but each verify their own key. Both sides take the seed
     * through their OWN {@code MLDSAPrivateKeySpec}, so the two encodings have
     * independent sources.
     */
    @Test
    public void sharedSeedYieldsByteEqualKeyEncodings() throws Exception
    {
        SecureRandom sr = seededRandom("sharedSeedYieldsByteEqualKeyEncodings");

        org.bouncycastle.jcajce.spec.MLDSAParameterSpec[] bcSpecs = {
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44,
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65,
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87};

        for (int i = 0; i < PARAM_SETS.length; i++)
        {
            String set = PARAM_SETS[i];
            for (int t = 0; t < TRIALS; t++)
            {
                byte[] seed = new byte[32];
                sr.nextBytes(seed);

                MLDSAPrivateKey jslPriv = (MLDSAPrivateKey) KeyFactory.getInstance(set, JSL)
                        .generatePrivate(new MLDSAPrivateKeySpec(MLDSAParameterSpec.fromName(set), seed));
                org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey bcPriv =
                        (org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) bcKeyFactory(set)
                                .generatePrivate(new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(
                                        bcSpecs[i], seed));

                Assertions.assertArrayEquals(bcPriv.getPublicKey().getEncoded(),
                        jslPriv.getPublicKey().getEncoded(),
                        set + ": one seed produced two different public keys");
                Assertions.assertArrayEquals(bcPriv.getPrivateKey(true).getEncoded(),
                        jslPriv.getPrivateKey(true).getEncoded(),
                        set + ": one seed produced two different seed-form private keys");
                Assertions.assertArrayEquals(bcPriv.getPrivateData(), jslPriv.getPrivateData(),
                        set + ": one seed expanded to two different private keys");
                Assertions.assertArrayEquals(seed, jslPriv.getSeed(),
                        set + ": JSL did not carry the seed it was given");
                Assertions.assertArrayEquals(seed, bcPriv.getSeed(),
                        set + ": BouncyCastle did not carry the seed it was given");
            }
        }
    }

    /**
     * A seed-imported private key encodes SEED-ONLY on JSL and EXPANDED on
     * BouncyCastle. Pinned in both halves rather than tolerated, so a change on
     * either side is reported here and not as an interop failure elsewhere.
     * <p>
     * Ours is the form RFC 9881 §6 recommends: "the seed-only format is
     * RECOMMENDED as it is the most compact representation" (standards library
     * RFC-9881.txt, INDEX hash
     * 20ae3b519bc69e32989fa6e625ab8746453eddf457e20ddbfd79d841a44237a2). Each
     * side decodes the other, asserted below. A GENERATED keypair is expanded
     * on both sides and round-trips byte-for-byte, which is why
     * {@link #keysRoundTripThroughBothKeyFactories} can assert bytes in both
     * directions and this cannot.
     */
    @Test
    public void aSeedImportedPrivateKeyEncodesSeedOnlyHereAndExpandedAtBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom(
                "aSeedImportedPrivateKeyEncodesSeedOnlyHereAndExpandedAtBouncyCastle");

        org.bouncycastle.jcajce.spec.MLDSAParameterSpec[] bcSpecs = {
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44,
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65,
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87};

        for (int i = 0; i < PARAM_SETS.length; i++)
        {
            String set = PARAM_SETS[i];
            byte[] seed = new byte[32];
            sr.nextBytes(seed);

            PrivateKey jslPriv = KeyFactory.getInstance(set, JSL)
                    .generatePrivate(new MLDSAPrivateKeySpec(MLDSAParameterSpec.fromName(set), seed));
            PrivateKey bcPriv = bcKeyFactory(set).generatePrivate(
                    new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(bcSpecs[i], seed));

            byte[] jslEnc = jslPriv.getEncoded();
            byte[] bcEnc = bcPriv.getEncoded();
            Assertions.assertFalse(Arrays.areEqual(jslEnc, bcEnc),
                    set + ": the two encoders now agree on a seed import — if one of them changed, "
                            + "this pin is stale");
            Assertions.assertEquals(54, jslEnc.length,
                    set + ": JSL no longer emits the seed-only form for a seed import");
            Assertions.assertTrue(bcEnc.length > 54,
                    set + ": BouncyCastle no longer emits the expanded form for a seed import");

            // Each side still decodes the other, and the material is the same.
            Assertions.assertArrayEquals(seed,
                    ((org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) bcKeyFactory(set)
                            .generatePrivate(new PKCS8EncodedKeySpec(jslEnc))).getSeed(),
                    set + ": BouncyCastle lost the seed decoding the JSL seed-only form");
            Assertions.assertArrayEquals(
                    ((MLDSAPrivateKey) jslPriv).getPrivateData(),
                    ((MLDSAPrivateKey) KeyFactory.getInstance(set, JSL)
                            .generatePrivate(new PKCS8EncodedKeySpec(bcEnc))).getPrivateData(),
                    set + ": JSL decoded BouncyCastle's expanded form to different material");
        }
    }

    /**
     * The SubjectPublicKeyInfo carries the CSOR OID for the parameter set, with
     * absent parameters — the fact a relying party keys off. Asserting the key
     * merely "re-derives" would not see a wrong OID.
     */
    @Test
    public void subjectPublicKeyInfoCarriesTheRegisteredOid() throws Exception
    {
        for (Map.Entry<String, String> e : SPKI_OID.entrySet())
        {
            KeyPair kp = keyPair(e.getKey());
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
            Assertions.assertEquals(e.getValue(), spki.getAlgorithm().getAlgorithm().getId(),
                    e.getKey() + ": wrong SubjectPublicKeyInfo algorithm OID");
            Assertions.assertNull(spki.getAlgorithm().getParameters(),
                    e.getKey() + ": the ML-DSA AlgorithmIdentifier must carry absent parameters");

            // And the OID alias resolves to a Signature that works with the key.
            byte[] msg = new byte[48];
            RANDOM.nextBytes(msg);
            byte[] sig = sign(JSL, e.getValue(), kp.getPrivate(), msg, null);
            Assertions.assertTrue(verify(BC, e.getKey(), bcPublic(kp.getPublic()), msg, sig, null),
                    e.getKey() + ": a signature made under the OID alias did not verify at BouncyCastle");
        }
    }
}
