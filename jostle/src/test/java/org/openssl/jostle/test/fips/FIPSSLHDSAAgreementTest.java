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
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Cross-provider agreement for the FIPS provider's SLH-DSA surface: JSLFIPS
 * against BouncyCastle, and JSLFIPS against JSL through encodings.
 * <p>
 * BouncyCastle is the load-bearing reference: JSLFIPS against JSL alone
 * compares two OpenSSL builds, so a defect shared by both is invisible.
 * <p>
 * Module-gated on the MODULE's own answer, and the absence is CHECKED, not
 * skipped: a bare skip lets a registrar that dropped a served family pass.
 * <p>
 * The message-encoding variants have no BouncyCastle JCE name and are compared
 * against its lightweight signer through {@link RawSlhDsaSigner}; the
 * deterministic expectation is {@code opt_rand} = PK.seed, FIPS 205
 * Algorithm 19 line 2 (standards library FIPS-205.pdf, INDEX hash
 * 8ef34228276f3386d23cb0da8c14592b8cfb0db3358016bba64df7a004f8d13d).
 * <p>
 * <b>Falsification (2026-09-19).</b> RED: dropping the
 * {@code SLH-DSA-SHAKE-256S} arm from {@link #bcSignatureName} failed the
 * completeness guard naming that Signature and its OID alias. RED: replacing
 * the BC verifier with a JSLFIPS verifier failed the reference-provider
 * assertion. GREEN: restored.
 */
public class FIPSSLHDSAAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String[] GUARDED_TYPES = {"KeyFactory", "KeyPairGenerator", "Signature"};

    /** A fast set for names that pin none; the "S" variants sign in seconds. */
    private static final String DEFAULT_SET = "SLH-DSA-SHA2-128F";

    /** One SHA2 and one SHAKE, both fast, for the cells that need depth not breadth. */
    private static final String[] FAST_SETS = {"SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F"};

    /** NIST CSOR id-slh-dsa-*, RFC 9814, as the SubjectPublicKeyInfo must carry them. */
    private static final Map<String, String> SPKI_OID = new LinkedHashMap<String, String>();

    static
    {
        SPKI_OID.put("SLH-DSA-SHA2-128S", "2.16.840.1.101.3.4.3.20");
        SPKI_OID.put("SLH-DSA-SHA2-128F", "2.16.840.1.101.3.4.3.21");
        SPKI_OID.put("SLH-DSA-SHA2-192S", "2.16.840.1.101.3.4.3.22");
        SPKI_OID.put("SLH-DSA-SHA2-192F", "2.16.840.1.101.3.4.3.23");
        SPKI_OID.put("SLH-DSA-SHA2-256S", "2.16.840.1.101.3.4.3.24");
        SPKI_OID.put("SLH-DSA-SHA2-256F", "2.16.840.1.101.3.4.3.25");
        SPKI_OID.put("SLH-DSA-SHAKE-128S", "2.16.840.1.101.3.4.3.26");
        SPKI_OID.put("SLH-DSA-SHAKE-128F", "2.16.840.1.101.3.4.3.27");
        SPKI_OID.put("SLH-DSA-SHAKE-192S", "2.16.840.1.101.3.4.3.28");
        SPKI_OID.put("SLH-DSA-SHAKE-192F", "2.16.840.1.101.3.4.3.29");
        SPKI_OID.put("SLH-DSA-SHAKE-256S", "2.16.840.1.101.3.4.3.30");
        SPKI_OID.put("SLH-DSA-SHAKE-256F", "2.16.840.1.101.3.4.3.31");
    }

    /** Registered Signature names BouncyCastle does not expose through the JCE. */
    private static final SortedSet<String> NO_BC_JCE_NAME =
            Collections.unmodifiableSortedSet(new TreeSet<String>(java.util.Arrays.asList(
                    "SLH-DSA-NONE", "DET-SLH-DSA-PURE", "DET-SLH-DSA-NONE")));

    /** Low deliberately: the twelve sets include six "S" variants that sign in seconds. */
    private static final int TRIALS = 2;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Map<String, KeyPair> KEY_PAIRS = new HashMap<String, KeyPair>();

    /**
     * BouncyCastle's raw (no message-encoding) SLH-DSA, which 1.86 exposes only
     * as protected members. The only independent witness for
     * {@code SLH-DSA-NONE} and {@code DET-SLH-DSA-NONE}.
     */
    static final class RawSlhDsaSigner extends SLHDSASigner
    {
        /** {@code optRand} null means BC's own hedged draw; PK.seed means deterministic. */
        byte[] signRaw(byte[] message, byte[] optRand)
        {
            return internalGenerateSignature(message, optRand);
        }

        boolean verifyRaw(byte[] message, byte[] signature)
        {
            return internalVerifySignature(message, signature);
        }
    }

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
     * Does the loaded MODULE implement SLH-DSA? 3.1.2 does not.
     * <p>
     * Asked of the module, never of the provider: the provider's registration
     * is the thing under test, so reading it here would compare a fact with
     * itself and a registrar that dropped a served family would pass. The name
     * is the one {@code ProvFIPSSLHDSA} gates on.
     */
    private static boolean moduleServesSlhDsa()
    {
        return FIPSTestUtil.moduleServesKeyMgmt("SLH-DSA-SHA2-128S");
    }

    private static void assumeSlhDsa()
    {
        Assumptions.assumeTrue(moduleServesSlhDsa(),
                "the loaded FIPS module implements no SLH-DSA (3.1.2)");
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

    private static PublicKey bcPublic(PublicKey key) throws Exception
    {
        return FIPSTestUtil.crossPublic(key, "SLH-DSA", BC);
    }

    private static PrivateKey bcPrivate(PrivateKey key) throws Exception
    {
        return FIPSTestUtil.crossPrivate(key, "SLH-DSA", BC);
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
        return SPKI_OID.containsKey(primary) ? primary : DEFAULT_SET;
    }

    /**
     * BouncyCastle's JCE spelling for a registered JSLFIPS Signature name, or
     * null where the lightweight raw signer is the reference. THROWS on an
     * unknown name, so a newly registered variant fails the completeness guard.
     */
    private static String bcSignatureName(String type, String alg)
    {
        String primary = primaryOf(type, alg);
        if (SPKI_OID.containsKey(primary))
        {
            return primary;
        }
        if ("SLHDSA".equals(primary) || "SLH-DSA-PURE".equals(primary))
        {
            return "SLH-DSA";
        }
        if (NO_BC_JCE_NAME.contains(primary))
        {
            return null;
        }
        throw new IllegalStateException("no BouncyCastle reference defined for Signature." + alg
                + " (primary " + primary + ") — teach bcSignatureName rather than leaving it unexercised");
    }

    private static byte[] sign(String provider, String alg, PrivateKey key, byte[] msg) throws Exception
    {
        Signature s = BC.equals(provider) ? bcSignature(alg) : Signature.getInstance(alg, provider);
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    private static boolean verify(String provider, String alg, PublicKey key, byte[] msg, byte[] sig)
            throws Exception
    {
        Signature s = BC.equals(provider) ? bcSignature(alg) : Signature.getInstance(alg, provider);
        s.initVerify(key);
        s.update(msg);
        return s.verify(sig);
    }

    private static SLHDSAPrivateKeyParameters lightweightPrivate(PrivateKey key) throws Exception
    {
        return (SLHDSAPrivateKeyParameters) PrivateKeyFactory.createKey(key.getEncoded());
    }

    private static AsymmetricKeyParameter lightweightPublic(PublicKey key) throws Exception
    {
        return PublicKeyFactory.createKey(key.getEncoded());
    }

    // -----------------------------------------------------------------
    // Completeness guard
    // -----------------------------------------------------------------

    /**
     * Every SLH-DSA service JSLFIPS registers is DRIVEN against BouncyCastle,
     * discovered by SPI class-name prefix, aliases included. On a module with
     * no SLH-DSA the registration set must be EMPTY — checked, not skipped.
     */
    @Test
    public void everyRegisteredSlhDsaServiceIsDriven() throws Exception
    {
        Provider provider = Security.getProvider(FIPS);

        if (!moduleServesSlhDsa())
        {
            SortedSet<String> registered = ProviderSurfaceGuard.registeredSurface(
                    provider, CipherFamilies.SLHDSA_PREFIX, GUARDED_TYPES);
            Assertions.assertTrue(registered.isEmpty(),
                    "the module implements no SLH-DSA, yet JSLFIPS registers: " + registered);
            return;
        }

        final SecureRandom sr = seededRandom("everyRegisteredSlhDsaServiceIsDriven");

        ProviderSurfaceGuard.assertEveryServiceDriven(provider, CipherFamilies.SLHDSA_PREFIX,
                "SLH-DSA (JSLFIPS)", GUARDED_TYPES,
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
                            byte[] sig = sign(FIPS, set, priv, msg);
                            Assertions.assertTrue(verify(BC, set, bcPublic(pub), msg, sig),
                                    alg + ": BouncyCastle rejected a signature from the crossed key");
                        }
                        else if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, FIPS);
                            if (!SPKI_OID.containsKey(primaryOf(type, alg)))
                            {
                                kpg.initialize(SLHDSAParameterSpec.fromName(set));
                            }
                            KeyPair generated = kpg.generateKeyPair();
                            byte[] sig = sign(FIPS, set, generated.getPrivate(), msg);
                            Assertions.assertTrue(
                                    verify(BC, set, bcPublic(generated.getPublic()), msg, sig),
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
        if (bcAlg != null)
        {
            byte[] sig = sign(FIPS, alg, kp.getPrivate(), msg);
            Assertions.assertTrue(verify(BC, bcAlg, bcPublic(kp.getPublic()), msg, sig),
                    alg + ": BouncyCastle rejected a JSLFIPS signature");
            byte[] bcSig = sign(BC, bcAlg, bcPrivate(kp.getPrivate()), msg);
            Assertions.assertTrue(verify(FIPS, alg, kp.getPublic(), msg, bcSig),
                    alg + ": JSLFIPS rejected a BouncyCastle signature");
            return;
        }

        byte[] sig = sign(FIPS, alg, kp.getPrivate(), msg);
        if (primaryOf(type, alg).endsWith("-NONE"))
        {
            RawSlhDsaSigner raw = new RawSlhDsaSigner();
            raw.init(false, lightweightPublic(kp.getPublic()));
            Assertions.assertTrue(raw.verifyRaw(msg, sig),
                    alg + ": BouncyCastle's raw verifier rejected a JSLFIPS signature");
            return;
        }
        Assertions.assertArrayEquals(sign(BC, "SLH-DSA", bcPrivate(kp.getPrivate()), msg), sig,
                alg + ": the deterministic signature differs from BouncyCastle's");
    }

    // -----------------------------------------------------------------
    // Signature agreement
    // -----------------------------------------------------------------

    /** Every one of the twelve parameter sets, both directions, with negatives. */
    @Test
    public void signaturesCrossVerifyWithBouncyCastleBothDirections() throws Exception
    {
        assumeSlhDsa();
        SecureRandom sr = seededRandom("signaturesCrossVerifyWithBouncyCastleBothDirections");

        for (String set : SPKI_OID.keySet())
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            PrivateKey bcPriv = bcPrivate(kp.getPrivate());

            byte[] msg = new byte[1 + sr.nextInt(1024)];
            sr.nextBytes(msg);

            byte[] fipsSig = sign(FIPS, set, kp.getPrivate(), msg);
            Assertions.assertTrue(verify(BC, set, bcPub, msg, fipsSig),
                    set + ": BouncyCastle rejected a JSLFIPS signature");

            byte[] bcSig = sign(BC, set, bcPriv, msg);
            Assertions.assertTrue(verify(FIPS, set, kp.getPublic(), msg, bcSig),
                    set + ": JSLFIPS rejected a BouncyCastle signature");

            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(verify(FIPS, set, kp.getPublic(), tampered, bcSig),
                    set + ": JSLFIPS accepted a signature over a tampered message");
            Assertions.assertFalse(verify(BC, set, bcPub, tampered, fipsSig),
                    set + ": BouncyCastle accepted a signature over a tampered message");

            byte[] mangled = Arrays.clone(fipsSig);
            mangled[sr.nextInt(mangled.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(verify(BC, set, bcPub, msg, mangled),
                    set + ": BouncyCastle accepted a tampered signature");
        }

        for (String set : FAST_SETS)
        {
            KeyPair kp = keyPair(set);
            KeyPair other = KeyPairGenerator.getInstance(set, FIPS).generateKeyPair();
            byte[] msg = new byte[64];
            sr.nextBytes(msg);
            byte[] sig = sign(FIPS, set, kp.getPrivate(), msg);
            Assertions.assertFalse(verify(BC, set, bcPublic(other.getPublic()), msg, sig),
                    set + ": BouncyCastle accepted a signature under the wrong public key");
        }
    }

    /**
     * Encodings are the only sanctioned crossing: a key object belongs to the
     * provider INSTANCE that made it.
     */
    @Test
    public void signaturesCrossVerifyWithTheBaseProviderThroughEncodings() throws Exception
    {
        assumeSlhDsa();
        SecureRandom sr = seededRandom("signaturesCrossVerifyWithTheBaseProviderThroughEncodings");

        for (String set : FAST_SETS)
        {
            KeyPair kp = keyPair(set);
            byte[] msg = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(msg);

            byte[] fipsSig = sign(FIPS, set, kp.getPrivate(), msg);
            PublicKey jslPub = FIPSTestUtil.crossPublic(kp.getPublic(), set, JSL);
            Assertions.assertTrue(verify(JSL, set, jslPub, msg, fipsSig),
                    set + ": JSL rejected a JSLFIPS signature");

            PrivateKey jslPriv = FIPSTestUtil.crossPrivate(kp.getPrivate(), set, JSL);
            byte[] jslSig = sign(JSL, set, jslPriv, msg);
            Assertions.assertTrue(verify(FIPS, set, kp.getPublic(), msg, jslSig),
                    set + ": JSLFIPS rejected a JSL signature");

            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(verify(FIPS, set, kp.getPublic(), tampered, jslSig),
                    set + ": JSLFIPS accepted a JSL signature over a tampered message");
        }
    }

    /**
     * {@code DET-SLH-DSA-PURE} is byte-equal to BouncyCastle's JCE signer,
     * which is deterministic, and the hedged sibling is not — so the two
     * registrations are proven distinct rather than assumed so. Both
     * directions, per the agreement rule.
     */
    @Test
    public void theDeterministicVariantIsByteEqualToBouncyCastle() throws Exception
    {
        assumeSlhDsa();
        SecureRandom sr = seededRandom("theDeterministicVariantIsByteEqualToBouncyCastle");

        for (String set : SPKI_OID.keySet())
        {
            KeyPair kp = keyPair(set);
            PrivateKey bcPriv = bcPrivate(kp.getPrivate());
            PublicKey bcPub = bcPublic(kp.getPublic());
            byte[] msg = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(msg);

            byte[] det = sign(FIPS, "DET-SLH-DSA-PURE", kp.getPrivate(), msg);
            Assertions.assertArrayEquals(sign(BC, "SLH-DSA", bcPriv, msg), det,
                    set + ": the deterministic signature differs from BouncyCastle's");
            Assertions.assertArrayEquals(det, sign(FIPS, "DET-SLH-DSA-PURE", kp.getPrivate(), msg),
                    set + ": DET-SLH-DSA-PURE is not deterministic");
            Assertions.assertTrue(verify(BC, set, bcPub, msg, det),
                    set + ": BouncyCastle rejected the deterministic signature");
            Assertions.assertFalse(Arrays.areEqual(det, sign(FIPS, "SLH-DSA-PURE", kp.getPrivate(), msg)),
                    set + ": SLH-DSA-PURE produced the deterministic signature — "
                            + "the hedged and deterministic registrations are not distinct");

            // The other direction: BouncyCastle signs, both pure names verify.
            byte[] bcSig = sign(BC, "SLH-DSA", bcPriv, msg);
            Assertions.assertTrue(verify(FIPS, "DET-SLH-DSA-PURE", kp.getPublic(), msg, bcSig),
                    set + ": DET-SLH-DSA-PURE rejected a BouncyCastle signature");
            Assertions.assertTrue(verify(FIPS, "SLH-DSA-PURE", kp.getPublic(), msg, bcSig),
                    set + ": SLH-DSA-PURE rejected a BouncyCastle signature");
            byte[] tamperedMsg = Arrays.clone(msg);
            tamperedMsg[sr.nextInt(tamperedMsg.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(verify(FIPS, "SLH-DSA-PURE", kp.getPublic(), tamperedMsg, bcSig),
                    set + ": SLH-DSA-PURE accepted a BouncyCastle signature over a tampered message");
        }
    }

    /**
     * The two {@code -NONE} names sign with no message encoding, compared
     * against BouncyCastle's raw signer in BOTH directions. A no-encoding
     * signature must NOT satisfy BC's JCE verifier, which applies the pure
     * encoding.
     */
    @Test
    public void theNoEncodingVariantsAgreeWithBouncyCastlesRawSigner() throws Exception
    {
        assumeSlhDsa();
        SecureRandom sr = seededRandom("theNoEncodingVariantsAgreeWithBouncyCastlesRawSigner");

        for (String set : FAST_SETS)
        {
            KeyPair kp = keyPair(set);
            SLHDSAPrivateKeyParameters bcPriv = lightweightPrivate(kp.getPrivate());
            AsymmetricKeyParameter bcPub = lightweightPublic(kp.getPublic());

            for (int t = 0; t < TRIALS; t++)
            {
                byte[] msg = new byte[1 + sr.nextInt(512)];
                sr.nextBytes(msg);

                byte[] hedged = sign(FIPS, "SLH-DSA-NONE", kp.getPrivate(), msg);
                RawSlhDsaSigner rawVerify = new RawSlhDsaSigner();
                rawVerify.init(false, bcPub);
                Assertions.assertTrue(rawVerify.verifyRaw(msg, hedged),
                        set + ": BouncyCastle's raw verifier rejected SLH-DSA-NONE");
                Assertions.assertFalse(
                        Arrays.areEqual(hedged, sign(FIPS, "SLH-DSA-NONE", kp.getPrivate(), msg)),
                        set + ": SLH-DSA-NONE is deterministic — it should be hedged");

                byte[] det = sign(FIPS, "DET-SLH-DSA-NONE", kp.getPrivate(), msg);
                RawSlhDsaSigner rawSign = new RawSlhDsaSigner();
                rawSign.init(true, bcPriv);
                Assertions.assertArrayEquals(rawSign.signRaw(msg, bcPriv.getPublicSeed()), det,
                        set + ": DET-SLH-DSA-NONE differs from BouncyCastle's raw deterministic form");

                Assertions.assertFalse(verify(BC, set, bcPublic(kp.getPublic()), msg, det),
                        set + ": BouncyCastle's pure verifier accepted a no-encoding signature — "
                                + "the message encoding is being ignored on one side");

                // The other direction. Verification does not consult the
                // randomiser, so BC's HEDGED raw signature verifies under both.
                // optRand is REQUIRED here: BC's raw signer dereferences it,
                // and FIPS 205 Algorithm 19 wants n bytes for the hedged form.
                byte[] optRand = new byte[bcPriv.getPublicSeed().length];
                sr.nextBytes(optRand);
                RawSlhDsaSigner rawHedged = new RawSlhDsaSigner();
                rawHedged.init(true, bcPriv);
                byte[] bcRaw = rawHedged.signRaw(msg, optRand);
                Assertions.assertTrue(verify(FIPS, "SLH-DSA-NONE", kp.getPublic(), msg, bcRaw),
                        set + ": SLH-DSA-NONE rejected a BouncyCastle raw signature");
                Assertions.assertTrue(verify(FIPS, "DET-SLH-DSA-NONE", kp.getPublic(), msg, bcRaw),
                        set + ": DET-SLH-DSA-NONE rejected a BouncyCastle raw signature");

                byte[] tampered = Arrays.clone(msg);
                tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(verify(FIPS, "SLH-DSA-NONE", kp.getPublic(), tampered, bcRaw),
                        set + ": SLH-DSA-NONE accepted a signature over a tampered message");
            }
        }
    }

    /**
     * The same message split several ways produces a signature BouncyCastle
     * verifies — a dimension the per-name completeness guard cannot see.
     */
    @Test
    public void chunkedUpdatesProduceSignaturesBouncyCastleVerifies() throws Exception
    {
        assumeSlhDsa();
        SecureRandom sr = seededRandom("chunkedUpdatesProduceSignaturesBouncyCastleVerifies");

        for (String set : FAST_SETS)
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
                Assertions.assertTrue(verify(BC, set, bcPub, msg, s.sign()),
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
        assumeSlhDsa();
        SecureRandom sr = seededRandom("keysRoundTripThroughBouncyCastleAndTheBaseProvider");

        for (String set : SPKI_OID.keySet())
        {
            KeyPair kp = keyPair(set);
            for (String other : new String[]{BC, JSL})
            {
                Assertions.assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(),
                                FIPSTestUtil.crossPublic(kp.getPublic(), "SLH-DSA", other).getEncoded()),
                        set + "/" + other + ": public key re-encoded differently");
                Assertions.assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(),
                                FIPSTestUtil.crossPrivate(kp.getPrivate(), "SLH-DSA", other).getEncoded()),
                        set + "/" + other + ": private key re-encoded differently");
            }
        }

        for (String set : FAST_SETS)
        {
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
            byte[] sig = sign(FIPS, set, viaFipsPriv, msg);
            Signature bcCheck = bcSignature(set);
            bcCheck.initVerify(bcPair.getPublic());
            bcCheck.update(msg);
            Assertions.assertTrue(bcCheck.verify(sig),
                    set + ": a round-tripped BouncyCastle keypair no longer matches its own public key");
        }
    }

    /** The SubjectPublicKeyInfo carries the CSOR OID, with absent parameters. */
    @Test
    public void subjectPublicKeyInfoCarriesTheRegisteredOid() throws Exception
    {
        assumeSlhDsa();
        SecureRandom sr = seededRandom("subjectPublicKeyInfoCarriesTheRegisteredOid");

        for (Map.Entry<String, String> e : SPKI_OID.entrySet())
        {
            KeyPair kp = keyPair(e.getKey());
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
            Assertions.assertEquals(e.getValue(), spki.getAlgorithm().getAlgorithm().getId(),
                    e.getKey() + ": wrong SubjectPublicKeyInfo algorithm OID");
            Assertions.assertNull(spki.getAlgorithm().getParameters(),
                    e.getKey() + ": the SLH-DSA AlgorithmIdentifier must carry absent parameters");
        }

        for (String set : FAST_SETS)
        {
            KeyPair kp = keyPair(set);
            byte[] msg = new byte[48];
            sr.nextBytes(msg);
            byte[] sig = sign(FIPS, SPKI_OID.get(set), kp.getPrivate(), msg);
            Assertions.assertTrue(verify(BC, set, bcPublic(kp.getPublic()), msg, sig),
                    set + ": a signature made under the OID alias did not verify at BouncyCastle");
        }
    }

    /**
     * The capability gate is all-or-nothing: the module's answer decides, and a
     * partial registration is a defect a single-service check misses.
     */
    @Test
    public void slhDsaIsServedAllOrNothing()
    {
        Provider provider = Security.getProvider(FIPS);
        SortedSet<String> surface = ProviderSurfaceGuard.registeredSurface(
                provider, CipherFamilies.SLHDSA_PREFIX, GUARDED_TYPES);

        if (!moduleServesSlhDsa())
        {
            Assertions.assertTrue(surface.isEmpty(),
                    "the module implements no SLH-DSA, yet JSLFIPS registers: " + surface);
            return;
        }

        SortedSet<String> missing = new TreeSet<String>();
        for (String type : GUARDED_TYPES)
        {
            for (String set : SPKI_OID.keySet())
            {
                if (!surface.contains(type + "." + set))
                {
                    missing.add(type + "." + set);
                }
            }
        }
        Assertions.assertTrue(missing.isEmpty(),
                "the module serves SLH-DSA but JSLFIPS registers only part of it; missing: " + missing);
    }
}
