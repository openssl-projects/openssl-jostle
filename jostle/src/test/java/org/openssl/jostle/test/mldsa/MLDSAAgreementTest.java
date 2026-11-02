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
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAPrivateKeySpec;
import org.openssl.jostle.jcajce.spec.MLDSAPublicKeySpec;
import org.openssl.jostle.test.util.BarePrivateKeyForms;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.MLDSAProxyPrivateKey;
import org.openssl.jostle.util.asn1.KeyInfoCanonicalizer;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
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
 * Jostle's ML-DSA signs HEDGED - two signings of one message differ -
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
 * pass - and {@code assertEveryServiceDriven} catches Throwable per entry, so
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

    private static MLDSAParameterSpec[] joSpec = new MLDSAParameterSpec[]{
            MLDSAParameterSpec.ml_dsa_44,
            MLDSAParameterSpec.ml_dsa_65,
            MLDSAParameterSpec.ml_dsa_87,

    };

    // MLDSAParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
    private static org.bouncycastle.jcajce.spec.MLDSAParameterSpec[] bcSpec =
            new org.bouncycastle.jcajce.spec.MLDSAParameterSpec[]{
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44,
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65,
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87,
    };

    private static Map<org.bouncycastle.jcajce.spec.MLDSAParameterSpec,
            MLDSAParameterSpec> bcToJostle = new HashMap<>();

    private static Map<MLDSAParameterSpec,
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec> jostleToBc = new HashMap<>();

    static
    {
        for (int i = 0; i < joSpec.length; i++)
        {
            bcToJostle.put(bcSpec[i], joSpec[i]);
            jostleToBc.put(joSpec[i], bcSpec[i]);
        }
    }

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
                + " (primary " + primary + ") - teach bcSignatureName rather than leaving it unexercised");
    }

    private static byte[] sign(String provider, String alg, PrivateKey key, byte[] msg, byte[] ctx)
            throws Exception
    {
        Signature s = BC.equals(provider) ? bcSignature(alg) : Signature.getInstance(alg, JSL);
        if (ctx != null)
        {
            s.setParameter(BC.equals(provider)
                    // ContextParameterSpec: BouncyCastle's is qualified, jostle's is imported
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
     * discovered by SPI class-name prefix, aliases included - which is what
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
                                    + " - teach this driver rather than letting it go unexercised");
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
     * byte mismatch in an agreement cell - and this is why
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
                    set + ": JSL now signs deterministically - the byte comparison can be tightened");

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
     * ({@code SignatureSpi$MLDSACalcMu} / {@code $MLDSAExtMu}), so neither needs a
     * lightweight fallback.
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
     * keys - the strongest agreement available for a family whose signatures
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

        // MLDSAParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
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
                // MLDSAPrivateKey is qualified where BouncyCastle's is meant: jostle's of that name is imported
                org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey bcPriv =
                        (org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) bcKeyFactory(set)
                                // MLDSAPrivateKeySpec: BouncyCastle's is qualified, jostle's is imported
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
                    set + ": the two encoders now agree on a seed import - if one of them changed, "
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
     * absent parameters - the fact a relying party keys off. Asserting the key
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

    /**
     * The generic generators used without initialize() agree with BouncyCastle's generic generator used the same
     * way: BouncyCastle reads the same parameter set from our encoding as its own default key carries (ML-DSA-87),
     * and each side verifies the other's signature.
     */
    @Test
    public void bareGenericGeneratorsAgreeWithBouncyCastlesDefault() throws Exception
    {
        KeyPair bc = KeyPairGenerator.getInstance("ML-DSA", BC).generateKeyPair();
        String bcDefault = ((MLDSAKey) bc.getPublic()).getParameterSpec().getName();
        Assertions.assertEquals("ML-DSA-87", bcDefault, "BouncyCastle's default moved");
        PublicKey bcPubAtJsl = KeyFactory.getInstance("ML-DSA", JSL)
                .generatePublic(new X509EncodedKeySpec(bc.getPublic().getEncoded()));
        for (String name : new String[]{"ML-DSA", "MLDSA"})
        {
            KeyPair jsl = KeyPairGenerator.getInstance(name, JSL).generateKeyPair();
            PublicKey jslPubAtBc = bcPublic(jsl.getPublic());
            Assertions.assertEquals(bcDefault, ((MLDSAKey) jslPubAtBc).getParameterSpec().getName(), name);

            byte[] msg = new byte[1 + RANDOM.nextInt(256)];
            RANDOM.nextBytes(msg);
            byte[] jslSig = sign(JSL, "ML-DSA", jsl.getPrivate(), msg, null);
            Assertions.assertTrue(verify(BC, "ML-DSA", jslPubAtBc, msg, jslSig, null), name + ": JSL signed");
            byte[] bcSig = sign(BC, "ML-DSA", bc.getPrivate(), msg, null);
            Assertions.assertTrue(verify(JSL, "ML-DSA", bcPubAtJsl, msg, bcSig, null), name + ": BC signed");
            msg[0] ^= 1;
            Assertions.assertFalse(verify(BC, "ML-DSA", jslPubAtBc, msg, jslSig, null), name + ": tampered");
        }
    }

    // -----------------------------------------------------------------
    // Divergences and contracts, both halves pinned
    // -----------------------------------------------------------------

    /**
     * An external mu of the wrong length is a SignatureException on both sides, refused at different calls: we
     * refuse an update that takes the total past 64 bytes, BouncyCastle accepts any update and refuses at sign
     * and verify.
     */
    @Test
    public void aWrongLengthExternalMuIsASignatureExceptionOnBothSides() throws Exception
    {
        KeyPair kp = keyPair(DEFAULT_SET);
        PublicKey bcPub = bcPublic(kp.getPublic());
        PrivateKey bcPriv = bcPrivate(kp.getPrivate());
        byte[] sig = sign(JSL, DEFAULT_SET, kp.getPrivate(), new byte[1], null);
        for (int len : new int[]{0, 63, 65})
        {
            byte[] mu = new byte[len];
            RANDOM.nextBytes(mu);

            Signature jslSign = Signature.getInstance("ML-DSA-EXTERNAL-MU", JSL);
            jslSign.initSign(kp.getPrivate());
            Signature jslVerify = Signature.getInstance("ML-DSA-EXTERNAL-MU", JSL);
            jslVerify.initVerify(kp.getPublic());
            SignatureException e;
            if (len > 64)
            {
                e = Assertions.assertThrows(SignatureException.class, () -> jslSign.update(mu));
                assertExternalMuRefusal(e, len);
                e = Assertions.assertThrows(SignatureException.class, () -> jslVerify.update(mu));
            }
            else
            {
                jslSign.update(mu);
                e = Assertions.assertThrows(SignatureException.class, jslSign::sign);
                assertExternalMuRefusal(e, len);
                jslVerify.update(mu);
                e = Assertions.assertThrows(SignatureException.class, () -> jslVerify.verify(sig));
            }
            assertExternalMuRefusal(e, len);

            Signature bcSign = bcSignature("ML-DSA-EXTERNAL-MU");
            bcSign.initSign(bcPriv);
            bcSign.update(mu);
            e = Assertions.assertThrows(SignatureException.class, bcSign::sign);
            Assertions.assertEquals("mu value must be 64 bytes", e.getMessage(), "BC sign, length " + len);
            Signature bcVerify = bcSignature("ML-DSA-EXTERNAL-MU");
            bcVerify.initVerify(bcPub);
            bcVerify.update(mu);
            e = Assertions.assertThrows(SignatureException.class, () -> bcVerify.verify(sig));
            Assertions.assertEquals("mu value must be 64 bytes", e.getMessage(), "BC verify, length " + len);
        }
    }

    private static void assertExternalMuRefusal(SignatureException e, int len)
    {
        Assertions.assertEquals("external Mu invalid length", e.getMessage(), "length " + len);
        Assertions.assertEquals(IllegalArgumentException.class, e.getCause().getClass(), "length " + len);
    }

    /**
     * A key holding only its public half, through each provider's own proxy class: signing refuses at init on
     * both sides, each with its own message, and CALCULATE-MU computes the same mu on both.
     */
    @Test
    public void aPublicOnlyProxyKeySignsNothingAndComputesMuOnBothSides() throws Exception
    {
        SecureRandom sr = seededRandom("aPublicOnlyProxyKeySignsNothingAndComputesMuOnBothSides");
        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            // A generated pair shares one native key, so the proxy wraps a public key decoded on its own.
            PublicKey publicOnly = KeyFactory.getInstance(set, JSL)
                    .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey jslProxy = new MLDSAProxyPrivateKey(publicOnly);
            // MLDSAProxyPrivateKey is qualified where BouncyCastle's is meant: jostle's test copy is imported
            PrivateKey bcProxy = new org.bouncycastle.jcajce.MLDSAProxyPrivateKey(bcPublic(kp.getPublic()));
            for (String alg : new String[]{set, "ML-DSA-EXTERNAL-MU"})
            {
                InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                        () -> Signature.getInstance(alg, JSL).initSign(jslProxy));
                Assertions.assertEquals("key has no private half", e.getMessage(), set + " " + alg);
                e = Assertions.assertThrows(InvalidKeyException.class, () -> bcSignature(alg).initSign(bcProxy));
                Assertions.assertEquals("unknown private key passed to ML-DSA", e.getMessage(), set + " " + alg);
            }
            byte[] msg = new byte[1 + sr.nextInt(300)];
            sr.nextBytes(msg);
            byte[] jslMu = sign(JSL, "ML-DSA-CALCULATE-MU", jslProxy, msg, null);
            byte[] bcMu = sign(BC, "ML-DSA-CALCULATE-MU", bcProxy, msg, null);
            Assertions.assertArrayEquals(bcMu, jslMu, set + ": the proxy keys computed different mu");
            Assertions.assertArrayEquals(sign(BC, "ML-DSA-CALCULATE-MU", bcPrivate(kp.getPrivate()), msg, null),
                    jslMu, set + ": the proxy key's mu differs from the full key's");
        }
    }

    /**
     * CALCULATE-MU on the verify side compares the mu derived from the public key and the message with the 64
     * bytes passed as the signature: BouncyCastle's mu verifies here, and the negatives answer false. A
     * wrong-length input answers false here and BouncyCastle lets its DataLengthException out raw (a broken
     * contract, recorded, not followed).
     */
    @Test
    public void aMuVerifiesOnTheCalculateMuVerifySideOfBothProviders() throws Exception
    {
        SecureRandom sr = seededRandom("aMuVerifiesOnTheCalculateMuVerifySideOfBothProviders");
        String alg = "ML-DSA-CALCULATE-MU";
        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            byte[] msg = new byte[1 + sr.nextInt(300)];
            sr.nextBytes(msg);
            byte[] ctx = new byte[1 + sr.nextInt(32)];
            sr.nextBytes(ctx);

            byte[] jslMu = sign(JSL, alg, kp.getPrivate(), msg, ctx);
            byte[] bcMu = sign(BC, alg, bcPrivate(kp.getPrivate()), msg, ctx);
            Assertions.assertArrayEquals(bcMu, jslMu, set);
            Assertions.assertTrue(verify(JSL, alg, kp.getPublic(), msg, bcMu, ctx), set + ": JSL refused BC's mu");
            Assertions.assertTrue(verify(JSL, alg, kp.getPublic(), msg, jslMu, ctx), set + ": JSL refused its mu");

            byte[] flipped = jslMu.clone();
            flipped[sr.nextInt(flipped.length)] ^= 1;
            Assertions.assertFalse(verify(JSL, alg, kp.getPublic(), msg, flipped, ctx), set);
            byte[] otherMsg = msg.clone();
            otherMsg[0] ^= 1;
            Assertions.assertFalse(verify(JSL, alg, kp.getPublic(), otherMsg, jslMu, ctx), set + ": message ignored");
            Assertions.assertFalse(verify(JSL, alg, kp.getPublic(), msg, jslMu, null), set + ": context ignored");

            byte[] shortMu = Arrays.copyOfRange(jslMu, 0, 63);
            Assertions.assertFalse(verify(JSL, alg, kp.getPublic(), msg, shortMu, ctx), set);
            Assertions.assertThrows(DataLengthException.class, () -> verify(BC, alg, bcPub, msg, shortMu, ctx),
                    set + ": BouncyCastle now answers a short mu without its raw DataLengthException");
        }
    }

    /**
     * A PKCS#8 private key re-encodes in the form it was given: seed-only, both and expanded, through either
     * provider's KeyFactory and back. From one shared seed the seed-only encodings are byte-equal.
     */
    @Test
    public void aPkcs8PrivateKeyKeepsItsFormThroughBothKeyFactories() throws Exception
    {
        SecureRandom sr = seededRandom("aPkcs8PrivateKeyKeepsItsFormThroughBothKeyFactories");
        for (int i = 0; i < PARAM_SETS.length; i++)
        {
            String set = PARAM_SETS[i];
            byte[] seed = new byte[32];
            sr.nextBytes(seed);
            // MLDSAPrivateKey and MLDSAPrivateKeySpec are qualified where BouncyCastle's are meant
            org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey bcPriv =
                    (org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) bcKeyFactory(set).generatePrivate(
                            new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(bcSpec[i], seed));

            byte[] bcSeedOnly = bcPriv.getPrivateKey(true).getEncoded();
            byte[] bcBoth = bcPriv.getEncoded();
            MLDSAPrivateKey jslFromSeed = (MLDSAPrivateKey) KeyFactory.getInstance(set, JSL)
                    .generatePrivate(new MLDSAPrivateKeySpec(MLDSAParameterSpec.fromName(set), seed));
            byte[] jslExpanded = KeyFactory.getInstance(set, JSL).generatePrivate(new MLDSAPrivateKeySpec(
                    MLDSAParameterSpec.fromName(set), jslFromSeed.getPrivateData(),
                    jslFromSeed.getPublicKey().getPublicData())).getEncoded();

            Assertions.assertEquals(0x80, KeyInfoCanonicalizer.privateKeyFirstByte(bcSeedOnly), set);
            Assertions.assertEquals(0x30, KeyInfoCanonicalizer.privateKeyFirstByte(bcBoth), set);
            Assertions.assertEquals(0x04, KeyInfoCanonicalizer.privateKeyFirstByte(jslExpanded), set);
            Assertions.assertArrayEquals(bcSeedOnly, jslFromSeed.getEncoded(), set + ": one seed, two seed forms");

            for (byte[] enc : new byte[][]{bcSeedOnly, bcBoth, jslExpanded})
            {
                byte[] viaJsl = KeyFactory.getInstance(set, JSL).generatePrivate(new PKCS8EncodedKeySpec(enc))
                        .getEncoded();
                Assertions.assertArrayEquals(enc, viaJsl, set + ": JSL changed the form");
                byte[] viaBc = bcKeyFactory(set).generatePrivate(new PKCS8EncodedKeySpec(viaJsl)).getEncoded();
                Assertions.assertArrayEquals(enc, viaBc, set + ": BouncyCastle changed the form");
            }
        }
    }

    /**
     * A bare PKCS#8 private key, the seed or the expanded key with no CHOICE tag, imports and re-encodes in the
     * structured form of what it carried, including one whose first byte equals a tag.
     */
    @Test
    public void aBarePkcs8PrivateKeyImportsAndEncodesStructured() throws Exception
    {
        SecureRandom sr = seededRandom("aBarePkcs8PrivateKeyImportsAndEncodesStructured");
        for (String set : PARAM_SETS)
        {
            BarePrivateKeyForms.assertMLDSA(JSL, set, sr);
        }
    }

    /**
     * BouncyCastle reads both bare forms too, and re-encodes them bare where JSL writes the structured form: a
     * recorded divergence. Its reading is the same key: it signs, and the generated public key verifies.
     */
    @Test
    public void bouncyCastleKeepsABarePkcs8PrivateKeyBare() throws Exception
    {
        SecureRandom sr = seededRandom("bouncyCastleKeepsABarePkcs8PrivateKeyBare");
        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            MLDSAPrivateKey priv = (MLDSAPrivateKey) kp.getPrivate();
            for (byte[] content : new byte[][]{priv.getSeed(), priv.getPrivateData()})
            {
                byte[] bare = BarePrivateKeyForms.bare(priv.getEncoded(), content);
                PrivateKey bcKey = bcKeyFactory(set).generatePrivate(new PKCS8EncodedKeySpec(bare));
                Assertions.assertArrayEquals(bare, bcKey.getEncoded(), set + ": BouncyCastle no longer keeps it bare");
                byte[] ours = KeyFactory.getInstance(set, JSL).generatePrivate(new PKCS8EncodedKeySpec(bare))
                        .getEncoded();
                Assertions.assertFalse(Arrays.areEqual(bare, ours), set + ": JSL kept the bare form");

                byte[] msg = new byte[1 + sr.nextInt(256)];
                sr.nextBytes(msg);
                byte[] sig = sign(BC, set, bcKey, msg, null);
                Assertions.assertTrue(verify(JSL, set, kp.getPublic(), msg, sig, null), set + ": a different key");
            }
        }
    }

    // Moved from MLDSATest: cells that compare with BouncyCastle.

    @Test
    public void testSingleByteUpdateSign() throws Exception
    {
        SecureRandom sr = seededRandom("testSingleByteUpdateSign");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

        byte[] message = new byte[1025];
        sr.nextBytes(message);

        Signature signatureJo = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        signatureJo.initSign(keyPair.getPrivate());
        signatureJo.update(message);
        byte[] signatureBytes = signatureJo.sign();


        for (int i = 0; i < message.length; i++)
        {
            signatureJo.update(message[i]);
        }

        byte[] sigBytesSingleByteUpdate = signatureJo.sign();

        // -- you cannot compare signatures directly..

        //
        // Verify both signature against BC
        //
        Signature verifierBc = Signature.getInstance("MLDSA", "BC");
        verifierBc.initVerify(pubKeyBC);
        verifierBc.update(message);
        Assertions.assertTrue(verifierBc.verify(signatureBytes));

        verifierBc.update(message);
        Assertions.assertTrue(verifierBc.verify(sigBytesSingleByteUpdate));

    }

    @Test
    public void testSingleByteUpdateVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testSingleByteUpdateVerify");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));


        byte[] message = new byte[1025];
        sr.nextBytes(message);


        Signature signatureBc = Signature.getInstance("MLDSA", "BC");
        signatureBc.initSign(privKeyBC);
        signatureBc.update(message);
        byte[] signatureBytesBc = signatureBc.sign();


        Signature verifierJo = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        verifierJo.initVerify(keyPair.getPublic());

        // whole message in one
        verifierJo.update(message);
        Assertions.assertTrue(verifierJo.verify(signatureBytesBc));

        // Pass in each byte
        for (int i = 0; i < message.length; i++)
        {
            verifierJo.update(message[i]);
        }
        Assertions.assertTrue(verifierJo.verify(signatureBytesBc));

        // Damage message
        message[0] ^= 1;

        // Should fail verification
        verifierJo.update(message);
        Assertions.assertFalse(verifierJo.verify(signatureBytesBc));

        for (int i = 0; i < message.length; i++)
        {
            verifierJo.update(message[i]);
        }
        Assertions.assertFalse(verifierJo.verify(signatureBytesBc));
    }

    @Test
    public void testCalculateRawMu() throws Exception
    {
        SecureRandom sr = seededRandom("testCalculateRawMu");
        for (MLDSAParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

            // Random content AND random length per CLAUDE.md "Random message
            // content AND length" - a single fixed message would miss bugs in
            // mu computation that ignores parts of the input, or external-mu
            // sign/verify desync tied to message-bit patterns.
            byte[] msg = new byte[16 + sr.nextInt(256)];
            sr.nextBytes(msg);

            Signature jostle = Signature.getInstance("ML-DSA-CALCULATE-MU", JostleProvider.PROVIDER_NAME);
            jostle.initSign(keyPair.getPrivate());
            jostle.update(msg);
            byte[] jostleMuBytes = jostle.sign();

            Assertions.assertEquals(jostleMuBytes.length, 64);


            Signature bc = Signature.getInstance("ML-DSA-CALCULATE-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initSign(privKeyBC);
            bc.update(msg);
            byte[] bcMuBytes = bc.sign();

            Assertions.assertEquals(bcMuBytes.length, 64);

            Assertions.assertArrayEquals(bcMuBytes, jostleMuBytes);

            // Mu is the same between both providers.
            // Create a signature from the external mu.

            jostle = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
            jostle.initSign(keyPair.getPrivate());
            jostle.update(jostleMuBytes);
            byte[] jostleSigFromExternalMu = jostle.sign();


            // Check that BC in external Mu mode will verify the signature.
            bc = Signature.getInstance("ML-DSA-EXTERNAL-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initVerify(pubKeyBC);
            bc.update(jostleMuBytes);
            Assertions.assertTrue(bc.verify(jostleSigFromExternalMu));

            // Use BC to create a signature from an external mu

            bc = Signature.getInstance("ML-DSA-EXTERNAL-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initSign(privKeyBC);
            bc.update(bcMuBytes);
            byte[] bcSigFromExternalMu = bc.sign();

            // Use jostle to verify an external signature
            jostle = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
            jostle.initVerify(keyPair.getPublic());
            jostle.update(jostleMuBytes);
            Assertions.assertTrue(jostle.verify(bcSigFromExternalMu));


//            //
//            // Using proxy private key
//            //
//            Signature jostle = Signature.getInstance("ML-DSA-CALCULATE-MU", JostleProvider.PROVIDER_NAME);
//            jostle.initSign(keyPair.getPrivate());
//            jostle.update(msg);
//            byte[] jostleMuBytes = jostle.sign();
//
//            Assertions.assertEquals(jostleMuBytes.length, 64);


        }
    }

    @Test
    public void testCalculateRawMuProxyKey() throws Exception
    {
        SecureRandom sr = seededRandom("testCalculateRawMuProxyKey");
        for (MLDSAParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

            // Random content AND random length per CLAUDE.md "Random message
            // content AND length" - a single fixed message would miss bugs in
            // mu computation that ignores parts of the input, or external-mu
            // sign/verify desync tied to message-bit patterns.
            byte[] msg = new byte[16 + sr.nextInt(256)];
            sr.nextBytes(msg);

            Signature jostle = Signature.getInstance("ML-DSA-CALCULATE-MU", JostleProvider.PROVIDER_NAME);
            jostle.initSign(new MLDSAProxyPrivateKey(keyPair.getPublic()));
            jostle.update(msg);
            byte[] jostleMuBytes = jostle.sign();

            Assertions.assertEquals(jostleMuBytes.length, 64);


            Signature bc = Signature.getInstance("ML-DSA-CALCULATE-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initSign(privKeyBC);
            bc.update(msg);
            byte[] bcMuBytes = bc.sign();

            Assertions.assertEquals(bcMuBytes.length, 64);

            Assertions.assertArrayEquals(bcMuBytes, jostleMuBytes);

            // Mu is the same between both providers.
            // Create a signature from the external mu.

            jostle = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
            jostle.initSign(keyPair.getPrivate());
            jostle.update(jostleMuBytes);
            byte[] jostleSigFromExternalMu = jostle.sign();


            // Check that BC in external Mu mode will verify the signature.
            bc = Signature.getInstance("ML-DSA-EXTERNAL-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initVerify(pubKeyBC);
            bc.update(jostleMuBytes);
            Assertions.assertTrue(bc.verify(jostleSigFromExternalMu));

            // Use BC to create a signature from an external mu

            bc = Signature.getInstance("ML-DSA-EXTERNAL-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initSign(privKeyBC);
            bc.update(bcMuBytes);
            byte[] bcSigFromExternalMu = bc.sign();

            // Use jostle to verify an external signature
            jostle = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
            jostle.initVerify(keyPair.getPublic());
            jostle.update(jostleMuBytes);
            Assertions.assertTrue(jostle.verify(bcSigFromExternalMu));


        }
    }

    @Test
    public void testKeyGen() throws Exception
    {
        SecureRandom sr = seededRandom("testKeyGen");
        for (MLDSAParameterSpec spec : joSpec)
        {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            //
            // Verify encoded key can be handled by BC and is usable
            //
            KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

            byte[] msg = new byte[65];

            sr.nextBytes(msg);

            Signature signatureBC = Signature.getInstance("MLDSA", "BC");
            signatureBC.initSign(privKeyBC);
            signatureBC.update(msg);
            byte[] signature = signatureBC.sign();

            Signature verifierBC = Signature.getInstance("MLDSA", "BC");
            verifierBC.initVerify(pubKeyBC);
            verifierBC.update(msg);

            Assertions.assertTrue(verifierBC.verify(signature));
        }
    }

    @Test
    public void testKeyRecovery() throws Exception
    {
        SecureRandom sr = seededRandom("testKeyRecovery");
        for (org.bouncycastle.jcajce.spec.MLDSAParameterSpec spec : bcSpec)
        {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKeyX509 = keyPair.getPublic().getEncoded();
            byte[] privateKeyX509 = keyPair.getPrivate().getEncoded();


            KeyFactory jostleFactory = KeyFactory.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            PrivateKey privateKey = jostleFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyX509));
            PublicKey publicKey = jostleFactory.generatePublic(new X509EncodedKeySpec(publicKeyX509));


            byte[] msg = new byte[65];
            sr.nextBytes(msg);

            Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            signature.initSign(privateKey);
            signature.update(msg);
            byte[] signatureBytes = signature.sign();

            Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            verifier.initVerify(publicKey);
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(signatureBytes));
        }

    }

    @Test
    public void testSeedImportRoundTrip() throws Exception
    {
        // Regression for the seed-import path: MLDSAPrivateKeySpec(params, seed)
        // must deterministically expand the 32-byte seed into a full key pair
        // via EVP_PKEY_fromdata. The previous EVP_PKEY_new_raw_private_key_ex
        // path mapped the seed to PRIV_KEY, which the provider rejected, so
        // every seed import threw - and nothing exercised it.
        SecureRandom sr = seededRandom("testSeedImportRoundTrip");
        for (MLDSAParameterSpec spec : joSpec)
        {
            byte[] seed = new byte[32];
            sr.nextBytes(seed);

            KeyFactory jostleFactory = KeyFactory.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);

            // Previously-dead path: importing a seed must succeed.
            MLDSAPrivateKey priv = (MLDSAPrivateKey) jostleFactory.generatePrivate(
                    new MLDSAPrivateKeySpec(spec, seed));

            // Deterministic expansion: the same seed yields byte-identical
            // expanded private data on a second import.
            MLDSAPrivateKey priv2 = (MLDSAPrivateKey) jostleFactory.generatePrivate(
                    new MLDSAPrivateKeySpec(spec, seed));
            Assertions.assertArrayEquals(priv.getPrivateData(), priv2.getPrivateData());

            // Both halves were derived (fromdata produced the public key too).
            MLDSAPublicKey pub = priv.getPublicKey();
            Assertions.assertNotNull(pub.getEncoded());

            byte[] msg = new byte[65];
            sr.nextBytes(msg);
            Signature signer = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            signer.initSign(priv);
            signer.update(msg);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            verifier.initVerify(pub);
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig));

            // Negative path: a tampered message must not verify against the sig.
            byte[] tampered = Arrays.clone(msg);
            tampered[0] ^= 0x01;
            Signature verifier2 = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            verifier2.initVerify(pub);
            verifier2.update(tampered);
            Assertions.assertFalse(verifier2.verify(sig));

            // The seed-derived expanded key round-trips through BC's KeyFactory.
            KeyFactory bcFactory = KeyFactory.getInstance("MLDSA", "BC");
            PublicKey bcPub = bcFactory.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
            Assertions.assertNotNull(bcPub);
        }
    }

    @Test
    public void testExpandedKeySeedFallback() throws Exception
    {
        // A key imported from an expanded (long-form) encoding has no seed:
        // getSeed() must return null (not throw), and getPrivateKey(true) must
        // fall back to the expanded key instead of surfacing an OpenSSL error.
        SecureRandom sr = seededRandom("testExpandedKeySeedFallback");
        for (org.bouncycastle.jcajce.spec.MLDSAParameterSpec spec : bcSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            // MLDSAPrivateKey is qualified where BouncyCastle's is meant: jostle's of that name is imported
            byte[] privateData =
                    ((org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) keyPair.getPrivate()).getPrivateData();
            // MLDSAPublicKey is qualified where BouncyCastle's is meant: jostle's of that name is imported
            byte[] publicData =
                    ((org.bouncycastle.jcajce.interfaces.MLDSAPublicKey) keyPair.getPublic()).getPublicData();

            KeyFactory jostleFactory = KeyFactory.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            MLDSAPrivateKey priv = (MLDSAPrivateKey) jostleFactory.generatePrivate(
                    new MLDSAPrivateKeySpec(bcToJostle.get(spec), privateData, publicData));

            // No seed present on an expanded import.
            Assertions.assertNull(priv.getSeed());

            // Fallback must not throw and must yield a usable signing key.
            MLDSAPrivateKey fallback = priv.getPrivateKey(true);
            Assertions.assertNotNull(fallback);

            byte[] msg = new byte[65];
            sr.nextBytes(msg);
            Signature signer = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            signer.initSign(fallback);
            signer.update(msg);
            Assertions.assertNotNull(signer.sign());
        }
    }

    @Test
    public void testLoadRawKey() throws Exception
    {
        SecureRandom sr = seededRandom("testLoadRawKey");

        for (org.bouncycastle.jcajce.spec.MLDSAParameterSpec spec : bcSpec)
        {
            // Generate on BC
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Get the raw encoding, not the X509 / PKCS8 version
            byte[] publicKey =
                    ((org.bouncycastle.jcajce.interfaces.MLDSAPublicKey) keyPair.getPublic()).getPublicData();
            byte[] privateKey =
                    ((org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) keyPair.getPrivate()).getPrivateData();

            // Jostle specs
            MLDSAPrivateKeySpec privateKeySpec = new MLDSAPrivateKeySpec(bcToJostle.get(spec), privateKey, publicKey);
            MLDSAPublicKeySpec publicKeySpec = new MLDSAPublicKeySpec(bcToJostle.get(spec), publicKey);

            // Jostle KeyFactory
            KeyFactory keyFactory = KeyFactory.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            PrivateKey privKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);

            byte[] msg = new byte[65];
            sr.nextBytes(msg);
            Signature signatureJostle = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            signatureJostle.initSign(privKey);
            signatureJostle.update(msg);
            byte[] signature = signatureJostle.sign();

            Signature verifierJostle = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            verifierJostle.initVerify(pubKey);
            verifierJostle.update(msg);
            Assertions.assertTrue(verifierJostle.verify(signature));
        }

    }

    private void crossProviderVerification(String algoName, MLDSAParameterSpec specJostle,
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec specBC, SecureRandom sr) throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(specJostle);
        KeyPair keyPair = keyGen.generateKeyPair();


        byte[] publicKey = ((MLDSAPublicKey) keyPair.getPublic()).getPublicData();
        byte[] privateKey = ((MLDSAPrivateKey) keyPair.getPrivate()).getPrivateData();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        // MLDSAPrivateKeySpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
        PrivateKey privKeyBC =
                factory.generatePrivate(new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(specBC, privateKey,
                        publicKey));
        // MLDSAPublicKeySpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
        PublicKey pubKeyBC = factory.generatePublic(new org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec(specBC,
                publicKey));


        byte[] msg = new byte[2049];
        sr.nextBytes(msg);


        Signature bcSigner = Signature.getInstance(algoName, "BC");
        bcSigner.initSign(privKeyBC);
        bcSigner.update(msg);
        byte[] bcSignature = bcSigner.sign();


        Signature signatureJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        signatureJostle.initSign(keyPair.getPrivate());
        signatureJostle.update(msg);
        byte[] jostleSignature = signatureJostle.sign();


        // BC verifies jostle
        Signature bcVerifier = Signature.getInstance(algoName, "BC");
        bcVerifier.initVerify(pubKeyBC);
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(jostleSignature));


        {
            byte[] vandalised = Arrays.clone(jostleSignature);
            vandalised[0] ^= 1;
            bcVerifier = Signature.getInstance(algoName, "BC");
            bcVerifier.initVerify(pubKeyBC);
            bcVerifier.update(msg);
            Assertions.assertFalse(bcVerifier.verify(vandalised));
        }

        // Jostle verifies BC
        Signature verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        verifierJostle.initVerify(keyPair.getPublic());
        verifierJostle.update(msg);
        Assertions.assertTrue(verifierJostle.verify(bcSignature));


        {
            byte[] vandalised = Arrays.clone(bcSignature);
            vandalised[0] ^= 1;
            verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
            verifierJostle.initVerify(keyPair.getPublic());
            verifierJostle.update(msg);
            Assertions.assertFalse(verifierJostle.verify(vandalised));
        }

    }

    private void crossProviderVerificationWithContext(String algoName, MLDSAParameterSpec specJostle,
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec specBC, byte[] ctx, SecureRandom sr) throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(specJostle);
        KeyPair keyPair = keyGen.generateKeyPair();


        byte[] publicKey = ((MLDSAPublicKey) keyPair.getPublic()).getPublicData();
        byte[] privateKey = ((MLDSAPrivateKey) keyPair.getPrivate()).getPrivateData();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        PrivateKey privKeyBC =
                factory.generatePrivate(new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(specBC, privateKey,
                        publicKey));
        PublicKey pubKeyBC = factory.generatePublic(new org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec(specBC,
                publicKey));


        byte[] msg = new byte[2049];
        sr.nextBytes(msg);

        Signature bcSigner = Signature.getInstance(algoName, "BC");
        bcSigner.initSign(privKeyBC);
        // ContextParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
        bcSigner.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(ctx));
        bcSigner.update(msg);
        byte[] bcSignature = bcSigner.sign();


        Signature signatureJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        signatureJostle.initSign(keyPair.getPrivate());
        signatureJostle.setParameter(new ContextParameterSpec(ctx));
        signatureJostle.update(msg);
        byte[] jostleSignature = signatureJostle.sign();


        // BC verifies jostle
        Signature bcVerifier = Signature.getInstance(algoName, "BC");
        bcVerifier.initVerify(pubKeyBC);
        bcVerifier.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(ctx));
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(jostleSignature));


        // Vandalise context and check for verification failure.
        byte[] vandalised = Arrays.clone(ctx);
        if (vandalised.length == 0)
        {
            vandalised = new byte[]{1};
        }
        vandalised[0] ^= 1;


        bcVerifier = Signature.getInstance(algoName, "BC");
        bcVerifier.initVerify(pubKeyBC);
        bcVerifier.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(vandalised));
        bcVerifier.update(msg);
        Assertions.assertFalse(bcVerifier.verify(jostleSignature));


        // Jostle verifies BC
        Signature verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        verifierJostle.initVerify(keyPair.getPublic());
        verifierJostle.setParameter(new ContextParameterSpec(ctx));
        verifierJostle.update(msg);
        Assertions.assertTrue(verifierJostle.verify(bcSignature));


        // Vandalise context and check for verification failure
        vandalised = Arrays.clone(ctx);
        if (vandalised.length == 0)
        {
            vandalised = new byte[]{1};
        }
        vandalised[0] ^= 1;
        verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        verifierJostle.initVerify(keyPair.getPublic());
        verifierJostle.setParameter(new ContextParameterSpec(vandalised));
        verifierJostle.update(msg);
        Assertions.assertFalse(verifierJostle.verify(bcSignature));
    }

    @Test
    public void testMLDSASignature() throws Exception
    {
        SecureRandom sr = seededRandom("testMLDSASignature");

        crossProviderVerification("ML-DSA", MLDSAParameterSpec.ml_dsa_44,
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44, sr);
        crossProviderVerification("ML-DSA", MLDSAParameterSpec.ml_dsa_65,
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65, sr);
        crossProviderVerification("ML-DSA", MLDSAParameterSpec.ml_dsa_87,
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87, sr);


        for (int ctxLen = 0; ctxLen < 256; ctxLen++)
        {

            byte[] ctx = new byte[ctxLen];
            sr.nextBytes(ctx);

            crossProviderVerificationWithContext("ML-DSA", MLDSAParameterSpec.ml_dsa_44,
                    org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44, ctx, sr);
            crossProviderVerificationWithContext("ML-DSA", MLDSAParameterSpec.ml_dsa_65,
                    org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65, ctx, sr);
            crossProviderVerificationWithContext("ML-DSA", MLDSAParameterSpec.ml_dsa_87,
                    org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87, ctx, sr);
        }
    }

    @Test
    public void testSeedOnlyKeyEncoding() throws Exception
    {
        SecureRandom sr = seededRandom("testSeedOnlyKeyEncoding");
        for (int i = 0; i < joSpec.length; i++)
        {
            MLDSAParameterSpec spec = joSpec[i];
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec bcSpec = jostleToBc.get(spec);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();

            MLDSAPrivateKey privKey = (MLDSAPrivateKey) keyPair.getPrivate();
            byte[] privateKeySeedOnly = privKey.getPrivateKey(true).getEncoded();



            //
            // Verify encoded key can be handled by BC and is usable
            //
            KeyFactory factory = KeyFactory.getInstance(bcSpec.getName(), "BC");
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKeySeedOnly));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

            byte[] msg = new byte[65];

            sr.nextBytes(msg);

            Signature signatureBC = Signature.getInstance(bcSpec.getName(), "BC");
            signatureBC.initSign(privKeyBC);
            signatureBC.update(msg);
            byte[] signature = signatureBC.sign();

            Signature verifierBC = Signature.getInstance(bcSpec.getName(), "BC");
            verifierBC.initVerify(pubKeyBC);
            verifierBC.update(msg);

            Assertions.assertTrue(verifierBC.verify(signature));
        }
    }

    @Test
    public void keyFactoryByNameTest() throws Exception
    {
        String[] names = new String[]{
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
        };


        for (int t = 0; t < names.length; t++)
        {
            String name = names[t];

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            {
                KeyFactory keyFactory = KeyFactory.getInstance(name, JostleProvider.PROVIDER_NAME);
                PublicKey pubK = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
                PrivateKey privK =
                        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

                Assertions.assertEquals(name, pubK.getAlgorithm());
                Assertions.assertEquals(name, privK.getAlgorithm());
            }

            //
            // Check it will actually fail
            //

            {
                String failingName = names[(t + 1) % names.length];

                try
                {
                    KeyFactory keyFactory = KeyFactory.getInstance(failingName, JostleProvider.PROVIDER_NAME);
                    keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

                    Assertions.fail();
                } catch (InvalidKeySpecException ikse)
                {
                    Assertions.assertEquals("expected " + failingName + " but got " + name, ikse.getMessage());
                }

            }

        }


    }

    @Test
    public void testEmptyMessageSignVerify() throws Exception
    {
        // Sign with no preceding update - valid usage that exercises the
        // SHAKE-256 finalisation with no message bytes accumulated. Cross-checks
        // against BC ensure the empty-input encoding is interop-compatible.
        for (MLDSAParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Roundtrip the keys through BC so we can sign/verify on the BC side.
            KeyFactory bcFactory = KeyFactory.getInstance("MLDSA", BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey privKeyBC =
                    bcFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));
            PublicKey pubKeyBC = bcFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));

            // Jostle sign empty.
            Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            signature.initSign(keyPair.getPrivate());
            byte[] jostleSig = signature.sign();
            Assertions.assertNotNull(jostleSig);
            Assertions.assertTrue(jostleSig.length > 0);

            // Jostle verifies its own empty-message signature.
            Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            verifier.initVerify(keyPair.getPublic());
            Assertions.assertTrue(verifier.verify(jostleSig));

            // BC verifies Jostle's empty-message signature.
            Signature bcVerifier = Signature.getInstance("MLDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcVerifier.initVerify(pubKeyBC);
            Assertions.assertTrue(bcVerifier.verify(jostleSig));

            // BC signs empty, Jostle verifies - confirms the reverse interop.
            Signature bcSigner = Signature.getInstance("MLDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcSigner.initSign(privKeyBC);
            byte[] bcSig = bcSigner.sign();

            verifier.initVerify(keyPair.getPublic());
            Assertions.assertTrue(verifier.verify(bcSig));

            // Sanity: a verifier fed a non-empty message must reject the
            // empty-message signature, so the previous accepts aren't trivial.
            verifier.initVerify(keyPair.getPublic());
            verifier.update((byte) 0x01);
            Assertions.assertFalse(verifier.verify(jostleSig));
        }
    }
}
