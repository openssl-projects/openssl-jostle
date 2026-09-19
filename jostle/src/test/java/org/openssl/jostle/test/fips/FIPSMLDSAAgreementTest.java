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

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
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
 * Cross-provider agreement for the FIPS provider's ML-DSA surface: JSLFIPS
 * against BouncyCastle, and JSLFIPS against JSL through encodings.
 * <p>
 * BouncyCastle is the load-bearing reference: JSLFIPS against JSL alone
 * compares two OpenSSL builds, so a defect shared by both is invisible.
 * {@code FIPSPQCTest} keeps the JSLFIPS-to-JSL crossing.
 * <p>
 * Module-gated on the MODULE's own answer, and the absence is CHECKED, not
 * skipped: a bare skip lets a registrar that dropped a served family pass.
 * <p>
 * Signature bytes are not comparable — Jostle signs hedged, BouncyCastle's JCE
 * deterministically, and Jostle exposes no deterministic ML-DSA. Byte equality
 * is asserted on the shared-seed key encodings and the external-mu digest.
 * <p>
 * <b>Falsification (2026-09-19).</b> RED: dropping the {@code ML-DSA-87} arm
 * from {@link #bcSignatureName} failed the completeness guard naming that
 * Signature and its OID alias. RED: replacing the BC verifier with a JSLFIPS
 * verifier failed the reference-provider assertion. GREEN: restored.
 */
public class FIPSMLDSAAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String[] GUARDED_TYPES = {"KeyFactory", "KeyPairGenerator", "Signature"};

    private static final String[] PARAM_SETS = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};

    private static final String DEFAULT_SET = "ML-DSA-65";

    /** NIST CSOR id-ml-dsa-44/65/87, as the SubjectPublicKeyInfo must carry them. */
    private static final Map<String, String> SPKI_OID = new LinkedHashMap<String, String>();

    static
    {
        SPKI_OID.put("ML-DSA-44", "2.16.840.1.101.3.4.3.17");
        SPKI_OID.put("ML-DSA-65", "2.16.840.1.101.3.4.3.18");
        SPKI_OID.put("ML-DSA-87", "2.16.840.1.101.3.4.3.19");
    }

    private static final int TRIALS = 10;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Map<String, KeyPair> KEY_PAIRS = new HashMap<String, KeyPair>();

    /** Class-level gate, so a test added later is gated too. */
    @BeforeAll
    static void before()
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

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /**
     * Does the loaded MODULE implement ML-DSA? 3.1.2 does not.
     * <p>
     * Asked of the module, never of the provider: the provider's registration
     * is the thing under test, so reading it here would compare a fact with
     * itself and a registrar that dropped a served family would pass.
     */
    private static boolean moduleServesMlDsa()
    {
        return FIPSTestUtil.moduleServesKeyMgmt("ML-DSA-65");
    }

    private static void assumeMlDsa()
    {
        Assumptions.assumeTrue(moduleServesMlDsa(),
                "the loaded FIPS module implements no ML-DSA (3.1.2)");
    }

    private static synchronized KeyPair keyPair(String paramSet) throws Exception
    {
        KeyPair kp = KEY_PAIRS.get(paramSet);
        if (kp == null)
        {
            kp = KeyPairGenerator.getInstance(paramSet, FIPS).generateKeyPair();
            KEY_PAIRS.put(paramSet, kp);
        }
        return kp;
    }

    /** A BouncyCastle Signature, with its provider asserted — see the class javadoc. */
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

    private static PublicKey bcPublic(PublicKey key) throws Exception
    {
        return FIPSTestUtil.crossPublic(key, "ML-DSA", BC);
    }

    private static PrivateKey bcPrivate(PrivateKey key) throws Exception
    {
        return FIPSTestUtil.crossPrivate(key, "ML-DSA", BC);
    }

    private static String primaryOf(String type, String alg)
    {
        Provider provider = Security.getProvider(FIPS);
        String primary = provider.getProperty("Alg.Alias." + type + "." + alg);
        return (primary == null ? alg : primary).toUpperCase(Locale.ROOT);
    }

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
     * BouncyCastle's JCE spelling for a registered JSLFIPS Signature name.
     * THROWS on an unknown name, so a newly registered variant fails the
     * completeness guard rather than going unexercised.
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
        Signature s = BC.equals(provider) ? bcSignature(alg) : Signature.getInstance(alg, provider);
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
        Signature s = BC.equals(provider) ? bcSignature(alg) : Signature.getInstance(alg, provider);
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

    // -----------------------------------------------------------------
    // Completeness guard
    // -----------------------------------------------------------------

    /**
     * Every ML-DSA service JSLFIPS registers is DRIVEN against BouncyCastle,
     * discovered by SPI class-name prefix, aliases included. On a module with
     * no ML-DSA the registration set must be EMPTY — checked, not skipped.
     */
    @Test
    public void everyRegisteredMlDsaServiceIsDriven() throws Exception
    {
        Provider provider = Security.getProvider(FIPS);

        if (!moduleServesMlDsa())
        {
            SortedSet<String> registered = ProviderSurfaceGuard.registeredSurface(
                    provider, CipherFamilies.MLDSA_PREFIX, GUARDED_TYPES);
            Assertions.assertTrue(registered.isEmpty(),
                    "the module implements no ML-DSA, yet JSLFIPS registers: " + registered);
            return;
        }

        final SecureRandom sr = seededRandom("everyRegisteredMlDsaServiceIsDriven");

        ProviderSurfaceGuard.assertEveryServiceDriven(provider, CipherFamilies.MLDSA_PREFIX,
                "ML-DSA (JSLFIPS)", GUARDED_TYPES,
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
                            driveSignature(type, alg, kp, msg);
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            PublicKey pub = KeyFactory.getInstance(alg, FIPS)
                                    .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
                            Assertions.assertTrue(
                                    Arrays.areEqual(kp.getPublic().getEncoded(), pub.getEncoded()),
                                    alg + ": re-encoded a public key differently");
                            PrivateKey priv = KeyFactory.getInstance(alg, FIPS)
                                    .generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
                            byte[] sig = sign(FIPS, set, priv, msg, null);
                            Assertions.assertTrue(verify(BC, set, bcPublic(pub), msg, sig, null),
                                    alg + ": BouncyCastle rejected a signature from the crossed key");
                        }
                        else if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, FIPS);
                            if (!primaryOf(type, alg).equals(set))
                            {
                                kpg.initialize(MLDSAParameterSpec.fromName(set));
                            }
                            KeyPair generated = kpg.generateKeyPair();
                            byte[] sig = sign(FIPS, set, generated.getPrivate(), msg, null);
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

    private static void driveSignature(String type, String alg, KeyPair kp, byte[] msg) throws Exception
    {
        String bcAlg = bcSignatureName(type, alg);
        String primary = primaryOf(type, alg);

        if ("ML-DSA-CALCULATE-MU".equals(primary))
        {
            byte[] mu = sign(FIPS, alg, kp.getPrivate(), msg, null);
            Signature bcCalc = bcSignature(bcAlg);
            bcCalc.initSign(bcPrivate(kp.getPrivate()));
            bcCalc.update(msg);
            Assertions.assertArrayEquals(bcCalc.sign(), mu, alg + ": mu differs from BouncyCastle's");
            return;
        }

        if ("ML-DSA-EXTERNAL-MU".equals(primary))
        {
            byte[] mu = sign(FIPS, "ML-DSA-CALCULATE-MU", kp.getPrivate(), msg, null);
            byte[] sig = sign(FIPS, alg, kp.getPrivate(), mu, null);
            Assertions.assertTrue(verify(BC, bcAlg, bcPublic(kp.getPublic()), mu, sig, null),
                    alg + ": BouncyCastle rejected an external-mu signature");
            return;
        }

        byte[] sig = sign(FIPS, alg, kp.getPrivate(), msg, null);
        Assertions.assertTrue(verify(BC, bcAlg, bcPublic(kp.getPublic()), msg, sig, null),
                alg + ": BouncyCastle rejected a JSLFIPS signature");
        byte[] bcSig = sign(BC, bcAlg, bcPrivate(kp.getPrivate()), msg, null);
        Assertions.assertTrue(verify(FIPS, alg, kp.getPublic(), msg, bcSig, null),
                alg + ": JSLFIPS rejected a BouncyCastle signature");
    }

    // -----------------------------------------------------------------
    // Signature agreement
    // -----------------------------------------------------------------

    /** Every parameter set, both directions, with tamper and wrong-key negatives. */
    @Test
    public void signaturesCrossVerifyWithBouncyCastleBothDirections() throws Exception
    {
        assumeMlDsa();
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

                byte[] fipsSig = sign(FIPS, set, kp.getPrivate(), msg, null);
                Assertions.assertTrue(verify(BC, set, bcPub, msg, fipsSig, null),
                        set + ": BouncyCastle rejected a JSLFIPS signature");

                byte[] bcSig = sign(BC, set, bcPriv, msg, null);
                Assertions.assertTrue(verify(FIPS, set, kp.getPublic(), msg, bcSig, null),
                        set + ": JSLFIPS rejected a BouncyCastle signature");

                byte[] tampered = Arrays.clone(msg);
                tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(verify(FIPS, set, kp.getPublic(), tampered, bcSig, null),
                        set + ": JSLFIPS accepted a signature over a tampered message");
                Assertions.assertFalse(verify(BC, set, bcPub, tampered, fipsSig, null),
                        set + ": BouncyCastle accepted a signature over a tampered message");

                byte[] mangled = Arrays.clone(fipsSig);
                mangled[sr.nextInt(mangled.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(verify(BC, set, bcPub, msg, mangled, null),
                        set + ": BouncyCastle accepted a tampered signature");
            }

            KeyPair other = KeyPairGenerator.getInstance(set, FIPS).generateKeyPair();
            byte[] msg = new byte[64];
            sr.nextBytes(msg);
            byte[] sig = sign(FIPS, set, kp.getPrivate(), msg, null);
            Assertions.assertFalse(verify(BC, set, bcPublic(other.getPublic()), msg, sig, null),
                    set + ": BouncyCastle accepted a signature under the wrong public key");
        }
    }

    /**
     * Encodings are the only sanctioned crossing: a key object belongs to the
     * provider INSTANCE that made it, and OpenSSL serves an operation in the
     * key's own provider whatever lib ctx drove the call.
     */
    @Test
    public void signaturesCrossVerifyWithTheBaseProviderThroughEncodings() throws Exception
    {
        assumeMlDsa();
        SecureRandom sr = seededRandom("signaturesCrossVerifyWithTheBaseProviderThroughEncodings");

        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            byte[] msg = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(msg);

            byte[] fipsSig = sign(FIPS, set, kp.getPrivate(), msg, null);
            PublicKey jslPub = FIPSTestUtil.crossPublic(kp.getPublic(), set, JSL);
            Assertions.assertTrue(verify(JSL, set, jslPub, msg, fipsSig, null),
                    set + ": JSL rejected a JSLFIPS signature");

            PrivateKey jslPriv = FIPSTestUtil.crossPrivate(kp.getPrivate(), set, JSL);
            byte[] jslSig = sign(JSL, set, jslPriv, msg, null);
            Assertions.assertTrue(verify(FIPS, set, kp.getPublic(), msg, jslSig, null),
                    set + ": JSLFIPS rejected a JSL signature");

            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(verify(FIPS, set, kp.getPublic(), tampered, jslSig, null),
                    set + ": JSLFIPS accepted a JSL signature over a tampered message");
        }
    }

    /**
     * The ML-DSA context string is load-bearing under the FIPS provider too: a
     * signature made under one context must not verify under another, and
     * BouncyCastle agrees about which is wrong.
     */
    @Test
    public void theContextStringIsLoadBearingOnBothSides() throws Exception
    {
        assumeMlDsa();
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

            byte[] sig = sign(FIPS, set, kp.getPrivate(), msg, ctxA);
            Assertions.assertTrue(verify(BC, set, bcPub, msg, sig, ctxA),
                    set + ": BouncyCastle rejected a signature under its own context");
            Assertions.assertFalse(verify(BC, set, bcPub, msg, sig, ctxB),
                    set + ": BouncyCastle accepted a signature under a DIFFERENT context");
            Assertions.assertFalse(verify(FIPS, set, kp.getPublic(), msg, sig, ctxB),
                    set + ": JSLFIPS accepted a signature under a DIFFERENT context");
        }
    }

    /** The mu digest is byte-equal, and an external-mu signature crosses both ways. */
    @Test
    public void externalMuAgreesWithBouncyCastle() throws Exception
    {
        assumeMlDsa();
        SecureRandom sr = seededRandom("externalMuAgreesWithBouncyCastle");

        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            PrivateKey bcPriv = bcPrivate(kp.getPrivate());

            byte[] msg = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(msg);

            byte[] mu = sign(FIPS, "ML-DSA-CALCULATE-MU", kp.getPrivate(), msg, null);
            Signature bcCalc = bcSignature("ML-DSA-CALCULATE-MU");
            bcCalc.initSign(bcPriv);
            bcCalc.update(msg);
            byte[] bcMu = bcCalc.sign();
            Assertions.assertArrayEquals(bcMu, mu, set + ": mu differs from BouncyCastle's");
            Assertions.assertEquals(64, mu.length, set + ": mu is not 64 bytes");

            byte[] fipsSig = sign(FIPS, "ML-DSA-EXTERNAL-MU", kp.getPrivate(), mu, null);
            Assertions.assertTrue(verify(BC, "ML-DSA-EXTERNAL-MU", bcPub, bcMu, fipsSig, null),
                    set + ": BouncyCastle rejected a JSLFIPS external-mu signature");

            byte[] bcSig = sign(BC, "ML-DSA-EXTERNAL-MU", bcPriv, bcMu, null);
            Assertions.assertTrue(verify(FIPS, "ML-DSA-EXTERNAL-MU", kp.getPublic(), mu, bcSig, null),
                    set + ": JSLFIPS rejected a BouncyCastle external-mu signature");

            byte[] wrongMu = Arrays.clone(mu);
            wrongMu[sr.nextInt(wrongMu.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(verify(BC, "ML-DSA-EXTERNAL-MU", bcPub, wrongMu, fipsSig, null),
                    set + ": BouncyCastle accepted an external-mu signature over the wrong mu");
        }
    }

    /**
     * The same message split several ways produces a signature BouncyCastle
     * verifies — a dimension the per-name completeness guard cannot see.
     */
    @Test
    public void chunkedUpdatesProduceSignaturesBouncyCastleVerifies() throws Exception
    {
        assumeMlDsa();
        SecureRandom sr = seededRandom("chunkedUpdatesProduceSignaturesBouncyCastleVerifies");

        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            byte[] msg = new byte[1 + sr.nextInt(600)];
            sr.nextBytes(msg);

            for (int step : new int[]{0, 1, 31, 32, 33, 64})
            {
                Signature s = Signature.getInstance(set, FIPS);
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
                Assertions.assertTrue(verify(BC, set, bcPub, msg, s.sign(), null),
                        set + ": BouncyCastle rejected a signature built from " + step + "-byte chunks");
            }
        }
    }

    // -----------------------------------------------------------------
    // Key encodings
    // -----------------------------------------------------------------

    /** A JSLFIPS keypair round-trips byte for byte through BouncyCastle and through JSL. */
    @Test
    public void keysRoundTripThroughBouncyCastleAndTheBaseProvider() throws Exception
    {
        assumeMlDsa();
        SecureRandom sr = seededRandom("keysRoundTripThroughBouncyCastleAndTheBaseProvider");

        for (String set : PARAM_SETS)
        {
            KeyPair kp = keyPair(set);
            for (String other : new String[]{BC, JSL})
            {
                Assertions.assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(),
                                FIPSTestUtil.crossPublic(kp.getPublic(), "ML-DSA", other).getEncoded()),
                        set + "/" + other + ": public key re-encoded differently");
                Assertions.assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(),
                                FIPSTestUtil.crossPrivate(kp.getPrivate(), "ML-DSA", other).getEncoded()),
                        set + "/" + other + ": private key re-encoded differently");
            }

            KeyPair bcPair = KeyPairGenerator.getInstance(set, BC).generateKeyPair();
            PublicKey viaFipsPub = KeyFactory.getInstance(set, FIPS)
                    .generatePublic(new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));
            PrivateKey viaFipsPriv = KeyFactory.getInstance(set, FIPS)
                    .generatePrivate(new PKCS8EncodedKeySpec(bcPair.getPrivate().getEncoded()));
            Assertions.assertTrue(Arrays.areEqual(bcPair.getPublic().getEncoded(),
                            viaFipsPub.getEncoded()),
                    set + ": JSLFIPS re-encoded a BouncyCastle public key differently");

            byte[] msg = new byte[64];
            sr.nextBytes(msg);
            byte[] sig = sign(FIPS, set, viaFipsPriv, msg, null);
            Signature bcCheck = bcSignature(set);
            bcCheck.initVerify(bcPair.getPublic());
            bcCheck.update(msg);
            Assertions.assertTrue(bcCheck.verify(sig),
                    set + ": a round-tripped BouncyCastle keypair no longer matches its own public key");
        }
    }

    /**
     * From ONE shared 32-byte seed, JSLFIPS and BouncyCastle derive
     * byte-identical keys — the strongest agreement available for a family
     * whose signatures cannot be byte-compared.
     */
    @Test
    public void sharedSeedYieldsByteEqualKeyEncodings() throws Exception
    {
        assumeMlDsa();
        SecureRandom sr = seededRandom("sharedSeedYieldsByteEqualKeyEncodings");

        org.bouncycastle.jcajce.spec.MLDSAParameterSpec[] bcSpecs = {
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44,
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65,
                org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87};

        for (int i = 0; i < PARAM_SETS.length; i++)
        {
            String set = PARAM_SETS[i];
            byte[] seed = new byte[32];
            sr.nextBytes(seed);

            MLDSAPrivateKey fipsPriv = (MLDSAPrivateKey) KeyFactory.getInstance(set, FIPS)
                    .generatePrivate(new MLDSAPrivateKeySpec(MLDSAParameterSpec.fromName(set), seed));
            org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey bcPriv =
                    (org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) bcKeyFactory(set)
                            .generatePrivate(new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(
                                    bcSpecs[i], seed));

            Assertions.assertArrayEquals(bcPriv.getPublicKey().getEncoded(),
                    fipsPriv.getPublicKey().getEncoded(),
                    set + ": one seed produced two different public keys");
            Assertions.assertArrayEquals(bcPriv.getPrivateKey(true).getEncoded(),
                    fipsPriv.getPrivateKey(true).getEncoded(),
                    set + ": one seed produced two different seed-form private keys");
            Assertions.assertArrayEquals(bcPriv.getPrivateData(), fipsPriv.getPrivateData(),
                    set + ": one seed expanded to two different private keys");

            // And the module's own expansion matches the base provider's.
            MLDSAPrivateKey jslPriv = (MLDSAPrivateKey) KeyFactory.getInstance(set, JSL)
                    .generatePrivate(new MLDSAPrivateKeySpec(MLDSAParameterSpec.fromName(set), seed));
            Assertions.assertArrayEquals(jslPriv.getPrivateData(), fipsPriv.getPrivateData(),
                    set + ": JSLFIPS and JSL expanded one seed differently");
        }
    }

    /**
     * The SubjectPublicKeyInfo carries the CSOR OID for the parameter set, with
     * absent parameters, and the key still resolves through the FIPS provider's
     * own OID alias.
     */
    @Test
    public void subjectPublicKeyInfoCarriesTheRegisteredOid() throws Exception
    {
        assumeMlDsa();

        for (Map.Entry<String, String> e : SPKI_OID.entrySet())
        {
            KeyPair kp = keyPair(e.getKey());
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
            Assertions.assertEquals(e.getValue(), spki.getAlgorithm().getAlgorithm().getId(),
                    e.getKey() + ": wrong SubjectPublicKeyInfo algorithm OID");
            Assertions.assertNull(spki.getAlgorithm().getParameters(),
                    e.getKey() + ": the ML-DSA AlgorithmIdentifier must carry absent parameters");

            byte[] msg = new byte[48];
            RANDOM.nextBytes(msg);
            byte[] sig = sign(FIPS, e.getValue(), kp.getPrivate(), msg, null);
            Assertions.assertTrue(verify(BC, e.getKey(), bcPublic(kp.getPublic()), msg, sig, null),
                    e.getKey() + ": a signature made under the OID alias did not verify at BouncyCastle");
        }
    }

    /**
     * The capability gate is all-or-nothing: the module's answer decides, and a
     * partial registration is a defect a single-service check misses.
     */
    @Test
    public void mlDsaIsServedAllOrNothing()
    {
        Provider provider = Security.getProvider(FIPS);
        SortedSet<String> surface = ProviderSurfaceGuard.registeredSurface(
                provider, CipherFamilies.MLDSA_PREFIX, GUARDED_TYPES);

        if (!moduleServesMlDsa())
        {
            Assertions.assertTrue(surface.isEmpty(),
                    "the module implements no ML-DSA, yet JSLFIPS registers: " + surface);
            return;
        }

        SortedSet<String> missing = new TreeSet<String>();
        for (String type : GUARDED_TYPES)
        {
            for (String set : PARAM_SETS)
            {
                if (!surface.contains(type + "." + set))
                {
                    missing.add(type + "." + set);
                }
            }
        }
        Assertions.assertTrue(missing.isEmpty(),
                "the module serves ML-DSA but JSLFIPS registers only part of it; missing: " + missing);
    }
}
