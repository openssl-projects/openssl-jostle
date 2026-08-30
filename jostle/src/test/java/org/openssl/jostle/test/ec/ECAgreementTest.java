/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.ec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.EcCurves;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Cross-provider agreement for the WHOLE base-provider ({@code JSL}) EC
 * surface, against BouncyCastle.
 * <p>
 * Non-FIPS counterpart of {@link
 * org.openssl.jostle.test.fips.FIPSECAgreementTest}, which cannot substitute:
 * that one runs only with {@code TEST_FIPS_LIB} set, so without this class
 * {@code ECDHWITHSHA1KDF} had no JCE-level comparison against an independent
 * implementation on the base provider at all.
 * <p>
 * <b>What "agrees" means differs by type.</b>
 * <ol>
 * <li><b>Signature</b> — ECDSA's nonce is random, so signatures cannot be
 * byte-compared. Agreement is CROSS-VERIFICATION, both directions, for every
 * registered name.</li>
 * <li><b>KeyAgreement</b> — the shared secret and the X9.63-derived KEK are
 * deterministic functions of the two keys (and the UKM), so agreement IS
 * byte-equality.</li>
 * <li><b>KeyFactory</b> — byte-equality of the re-encoded key, both halves and
 * both directions.</li>
 * <li><b>AlgorithmParameters</b> — byte-equality of the named-curve encoding,
 * and the peer must read it back.</li>
 * </ol>
 * <b>Breadth over registered NAMES, not over curves.</b> Three representative
 * curves are used; curve breadth is {@link ECCurveTableTest}'s job, and the
 * chunking, state-machine and boundary coverage stays in {@link ECDSATest},
 * {@link ECDHTest} and {@link ECTest}.
 * <p>
 * Key material crosses providers as encodings decoded through each provider's
 * own KeyFactory.
 * <p>
 * Inputs come from a per-test SHA1PRNG whose seed is logged.
 */
public class ECAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** The five JCA types {@code ProvEC} registers under. */
    private static final String[] GUARDED_TYPES = {
            "AlgorithmParameters", "KeyAgreement", "KeyFactory", "KeyPairGenerator", "Signature"
    };

    /**
     * Curves used by the per-curve tests that are NOT the signature sweep —
     * key round-tripping, plain ECDH and the parameters codec. Three is enough
     * there because those paths do not vary with the curve beyond field size;
     * the signature sweep below is exhaustive.
     */
    private static final String[] CURVES = {"P-256", "P-384", "P-521"};

    /**
     * Every curve the build serves, for the signature sweep. Exhaustive rather
     * than representative because it is affordable: measured 2412
     * cross-verifications in 1.1 s over the 67 curves BouncyCastle also
     * accepts. The 15 it does not are driven JSL-only, and named in
     * {@link EcCurves#NOT_IN_BOUNCYCASTLE} rather than silently intersected
     * away.
     */
    private static final String[] SWEEP_CURVES = EcCurves.BUILTIN;

    /**
     * AES key-wrap OIDs used as the KDF's target algorithm, giving 16 / 24 /
     * 32-byte KEKs — so a KDF that ignored the requested length cannot pass.
     */
    private static final String[] WRAP_OIDS = {
            "2.16.840.1.101.3.4.1.5",   // id-aes128-wrap
            "2.16.840.1.101.3.4.1.25",  // id-aes192-wrap
            "2.16.840.1.101.3.4.1.45"   // id-aes256-wrap
    };

    private static final int TRIALS = 3;

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

    /** Every primary of one type that {@code ProvEC} registers, sorted. */
    private static List<String> registered(String type)
    {
        Provider provider = Security.getProvider(JSL);
        Assertions.assertNotNull(provider, "JSL provider is not registered");

        List<String> names = new ArrayList<String>();
        for (Provider.Service s : provider.getServices())
        {
            String cn = s.getClassName();
            if (type.equals(s.getType()) && cn != null && cn.startsWith(CipherFamilies.EC_PREFIX))
            {
                names.add(s.getAlgorithm());
            }
        }
        Assertions.assertFalse(names.isEmpty(), "JSL registered no EC " + type + " services");
        Collections.sort(names);
        return names;
    }

    private static KeyPair generate(String curve) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static PublicKey toBc(PublicKey key) throws Exception
    {
        return KeyFactory.getInstance("EC", BC).generatePublic(new X509EncodedKeySpec(key.getEncoded()));
    }

    private static PrivateKey toBc(PrivateKey key) throws Exception
    {
        return KeyFactory.getInstance("EC", BC).generatePrivate(new PKCS8EncodedKeySpec(key.getEncoded()));
    }

    private static boolean isPreHashed(String alg)
    {
        return "NONEWITHECDSA".equalsIgnoreCase(alg);
    }

    /**
     * The order's bit length for a named curve, cached — the sweep asks per
     * curve per algorithm and generating a keypair to find out would dominate
     * its runtime.
     */
    private static final java.util.Map<String, Integer> ORDER_BITS =
            new java.util.concurrent.ConcurrentHashMap<String, Integer>();

    private static int orderBits(String curve) throws Exception
    {
        Integer cached = ORDER_BITS.get(curve);
        if (cached != null)
        {
            return cached.intValue();
        }
        int bits = ((java.security.interfaces.ECPrivateKey) generate(curve).getPrivate())
                .getParams().getOrder().bitLength();
        ORDER_BITS.put(curve, Integer.valueOf(bits));
        return bits;
    }

    /**
     * The digest fed to {@code NONEwithECDSA}, chosen against the CURVE'S
     * ORDER rather than fixed.
     * <p>
     * ECDSA uses the leftmost {@code n} bits of the digest, so a digest longer
     * than the order is truncated. 58 of the 82 curves this class sweeps have
     * an order below 256 bits, so a fixed SHA-256 would be exercising
     * truncation on most of them and agreement on almost none — and if the two
     * implementations truncated differently the test would report it as a
     * signature mismatch with no clue why. Picking the largest standard digest
     * that FITS keeps the comparison about the signature.
     * <p>
     * Below 160 bits no standard digest fits; those curves get SHA-1 and
     * therefore do exercise the truncation path deliberately, which is the
     * remaining case worth having.
     */
    private static String preHashDigest(String curve) throws Exception
    {
        int bits = orderBits(curve);
        if (bits >= 512)
        {
            return "SHA-512";
        }
        if (bits >= 384)
        {
            return "SHA-384";
        }
        if (bits >= 256)
        {
            return "SHA-256";
        }
        if (bits >= 224)
        {
            return "SHA-224";
        }
        return "SHA-1";
    }

    private static byte[] signedBytes(String alg, byte[] message, String curve) throws Exception
    {
        if (isPreHashed(alg))
        {
            return MessageDigest.getInstance(preHashDigest(curve)).digest(message);
        }
        return message;
    }

    private static byte[] sign(String alg, String provider, PrivateKey key, byte[] message, String curve)
            throws Exception
    {
        Signature s = Signature.getInstance(alg, provider);
        s.initSign(key);
        s.update(signedBytes(alg, message, curve));
        return s.sign();
    }

    private static boolean verify(String alg, String provider, PublicKey key, byte[] message,
                                  byte[] sig, String curve) throws Exception
    {
        Signature v = Signature.getInstance(alg, provider);
        v.initVerify(key);
        v.update(signedBytes(alg, message, curve));
        return v.verify(sig);
    }

    /**
     * One X9.63 KDF derivation. {@code ukm} may be null, which is the
     * no-user-keying-material case; each provider takes its own spec class.
     */
    private static byte[] deriveKdf(String provider, String transform, PrivateKey priv,
                                    PublicKey peerPub, byte[] ukm, String wrapOid) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance(transform, provider);
        if (ukm == null)
        {
            ka.init(priv);
        }
        else if (BC.equals(provider))
        {
            ka.init(priv, new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(ukm));
        }
        else
        {
            ka.init(priv, new org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec(ukm));
        }
        ka.doPhase(peerPub, true);
        return ka.generateSecret(wrapOid).getEncoded();
    }

    /** The SPI class {@code ProvEC} registers the X9.63-KDF agreements under. */
    private static final String KDF_AGREEMENT_SPI =
            "org.openssl.jostle.jcajce.provider.ec.ECWithKDFKeyAgreementSpi";

    /**
     * Whether a registered KeyAgreement name is a KDF variant, decided from the
     * registrar's CLASS name rather than the algorithm's spelling.
     * <p>
     * Spelling does not work: the five KDF agreements carry OID aliases such as
     * {@code 1.3.132.1.11.1}, which do not end in "KDF". A suffix test sent all
     * ten alias spellings down the plain-ECDH branch, where {@code
     * generateSecret()} with no algorithm is rejected — the guard caught it.
     */
    private static boolean isKdfAgreement(String alg)
    {
        String cn = ProviderSurfaceGuard.registeredClassNames(Security.getProvider(JSL),
                CipherFamilies.EC_PREFIX, GUARDED_TYPES)
                .get("KeyAgreement." + alg.toUpperCase(java.util.Locale.ROOT));
        Assertions.assertNotNull(cn, "no registered class for KeyAgreement." + alg);
        return KDF_AGREEMENT_SPI.equals(cn);
    }

    // -----------------------------------------------------------------
    // Completeness guards
    // -----------------------------------------------------------------

    /**
     * Every EC service JSL registers is DRIVEN, discovered by SPI class-name
     * prefix rather than listed, so a registration added later fails until
     * someone teaches this an operation. Aliases are included, which is what
     * covers the OID spellings.
     */
    @Test
    public void everyRegisteredEcServiceIsDriven() throws Exception
    {
        final SecureRandom sr = seededRandom("everyRegisteredEcServiceIsDriven");
        final KeyPair alice = generate("P-256");
        final KeyPair bob = generate("P-256");

        ProviderSurfaceGuard.assertEveryServiceDriven(Security.getProvider(JSL),
                CipherFamilies.EC_PREFIX, "EC (JSL)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        if ("Signature".equals(type))
                        {
                            byte[] msg = new byte[32];
                            sr.nextBytes(msg);
                            byte[] sig = sign(alg, JSL, alice.getPrivate(), msg, "P-256");
                            Assertions.assertTrue(verify(alg, JSL, alice.getPublic(), msg, sig, "P-256"),
                                    alg + ": did not verify its own signature");
                        }
                        else if ("KeyAgreement".equals(type))
                        {
                            if (isKdfAgreement(alg))
                            {
                                byte[] kek = deriveKdf(JSL, alg, alice.getPrivate(), bob.getPublic(),
                                        null, WRAP_OIDS[0]);
                                Assertions.assertEquals(16, kek.length,
                                        alg + ": derived a KEK of the wrong length");
                            }
                            else
                            {
                                KeyAgreement ka = KeyAgreement.getInstance(alg, JSL);
                                ka.init(alice.getPrivate());
                                ka.doPhase(bob.getPublic(), true);
                                Assertions.assertTrue(ka.generateSecret().length > 0,
                                        alg + ": derived an empty shared secret");
                            }
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            PublicKey pub = KeyFactory.getInstance(alg, JSL)
                                    .generatePublic(new X509EncodedKeySpec(alice.getPublic().getEncoded()));
                            Assertions.assertTrue(
                                    Arrays.areEqual(alice.getPublic().getEncoded(), pub.getEncoded()), alg);
                        }
                        else if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, JSL);
                            kpg.initialize(new ECGenParameterSpec("P-256"));
                            byte[] msg = new byte[32];
                            sr.nextBytes(msg);
                            KeyPair kp = kpg.generateKeyPair();
                            byte[] sig = sign("SHA256withECDSA", JSL, kp.getPrivate(), msg, "P-256");
                            Assertions.assertTrue(
                                    verify("SHA256withECDSA", JSL, kp.getPublic(), msg, sig, "P-256"),
                                    alg + ": generated a keypair that cannot sign");
                        }
                        else if ("AlgorithmParameters".equals(type))
                        {
                            AlgorithmParameters ap = AlgorithmParameters.getInstance(alg, JSL);
                            ap.init(new ECGenParameterSpec("P-256"));
                            Assertions.assertNotNull(ap.getEncoded(), alg);
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
     * The removal direction, at type granularity: each of the five JCA types
     * {@code ProvEC} registers under must still be present. A per-name list
     * would drift; this catches a family dropped wholesale.
     */
    @Test
    public void everyGuardedTypeIsStillRegistered()
    {
        SortedSet<String> surface = ProviderSurfaceGuard.registeredSurface(
                Security.getProvider(JSL), CipherFamilies.EC_PREFIX, GUARDED_TYPES);

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
                "JSL no longer registers any EC service of these types: " + missing);
    }

    // -----------------------------------------------------------------
    // Signature — cross-verification, both directions
    // -----------------------------------------------------------------

    /**
     * For every registered ECDSA name, over EVERY curve the build serves: JSL
     * signs and BC verifies, and BC signs and JSL verifies. Both directions,
     * because one alone passes against a verifier that ignores the digest. A
     * one-byte change to the message must fail verification on the peer.
     * <p>
     * The 15 curves BouncyCastle does not accept
     * ({@link EcCurves#NOT_IN_BOUNCYCASTLE}) are still driven, JSL-signing and
     * JSL-verifying, so they are not silently skipped — and the counters below
     * fail if either group turns out empty, which is what would happen if the
     * BC-absent set went stale in either direction.
     */
    @Test
    public void everyRegisteredSignatureCrossVerifiesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("everyRegisteredSignatureCrossVerifiesWithBouncyCastle");
        List<String> algs = registered("Signature");

        int crossChecked = 0;
        int jslOnlyChecked = 0;

        for (String curve : SWEEP_CURVES)
        {
            KeyPair pair;
            try
            {
                pair = generate(curve);
            }
            catch (Exception ex)
            {
                // A curve the build does not serve is passed over here, but the
                // floors below are FAIL-CLOSED, not a safety net: a build
                // without binary fields serves ~34 prime curves, which is under
                // the 500-check floor, so it would fail. That is deliberate —
                // the supported builds (3.5.8, 3.1.2) serve all 82, and a build
                // that does not is a configuration this sweep cannot vouch for.
                continue;
            }

            if (EcCurves.NO_ECDSA_SIGNING.contains(curve))
            {
                // Asserted in its own test rather than skipped silently.
                continue;
            }

            boolean bcKnowsCurve = !EcCurves.NOT_IN_BOUNCYCASTLE.contains(curve);
            PublicKey peerPub = null;
            PrivateKey peerPriv = null;
            if (bcKnowsCurve)
            {
                peerPub = toBc(pair.getPublic());
                peerPriv = toBc(pair.getPrivate());
            }

            for (String alg : algs)
            {
                byte[] message = new byte[1 + sr.nextInt(512)];
                sr.nextBytes(message);
                String tag = alg + " / " + curve;

                byte[] jslSig = sign(alg, JSL, pair.getPrivate(), message, curve);

                if (!bcKnowsCurve)
                {
                    Assertions.assertTrue(verify(alg, JSL, pair.getPublic(), message, jslSig, curve),
                            tag + ": JSL did not verify its own signature");
                    jslOnlyChecked++;
                    continue;
                }

                Assertions.assertTrue(verify(alg, BC, peerPub, message, jslSig, curve),
                        tag + ": BC rejected a JSL signature");

                byte[] bcSig = sign(alg, BC, peerPriv, message, curve);
                Assertions.assertTrue(verify(alg, JSL, pair.getPublic(), message, bcSig, curve),
                        tag + ": JSL rejected a BC signature");

                byte[] tampered = message.clone();
                tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
                Assertions.assertFalse(verify(alg, BC, peerPub, tampered, jslSig, curve),
                        tag + ": BC accepted a JSL signature over a tampered message");
                Assertions.assertFalse(verify(alg, JSL, pair.getPublic(), tampered, bcSig, curve),
                        tag + ": JSL accepted a BC signature over a tampered message");
                crossChecked++;
            }
        }

        // Non-vacuity, per group. Measured 67 BC-comparable curves and 15
        // JSL-only, times 10 registered names; the floors sit well below.
        Assertions.assertTrue(crossChecked >= 500,
                "only " + crossChecked + " cross-provider signature checks ran — the sweep has "
                        + "gone vacuous, or the build serves almost no curves");
        Assertions.assertTrue(jslOnlyChecked >= 100,
                "only " + jslOnlyChecked + " JSL-only signature checks ran — EcCurves"
                        + ".NOT_IN_BOUNCYCASTLE may have gone stale");
    }

    // -----------------------------------------------------------------
    // KeyAgreement — byte-equality of the secret and of the derived KEK
    // -----------------------------------------------------------------

    /**
     * Plain ECDH: the raw shared secret is a deterministic function of the two
     * keys, so it must be byte-identical across providers, on every curve. A
     * different peer must produce a different secret.
     */
    @Test
    public void plainEcdhSharedSecretAgreesWithBouncyCastle() throws Exception
    {
        seededRandom("plainEcdhSharedSecretAgreesWithBouncyCastle");

        for (String curve : CURVES)
        {
            KeyPair alice = generate(curve);
            KeyPair bob = generate(curve);
            KeyPair mallory = generate(curve);

            KeyAgreement jslKa = KeyAgreement.getInstance("ECDH", JSL);
            jslKa.init(alice.getPrivate());
            jslKa.doPhase(bob.getPublic(), true);
            byte[] jslSecret = jslKa.generateSecret();

            KeyAgreement bcKa = KeyAgreement.getInstance("ECDH", BC);
            bcKa.init(toBc(alice.getPrivate()));
            bcKa.doPhase(toBc(bob.getPublic()), true);
            Assertions.assertArrayEquals(bcKa.generateSecret(), jslSecret,
                    curve + ": ECDH shared secret differs from BC");

            KeyAgreement other = KeyAgreement.getInstance("ECDH", JSL);
            other.init(alice.getPrivate());
            other.doPhase(mallory.getPublic(), true);
            Assertions.assertFalse(Arrays.areEqual(jslSecret, other.generateSecret()),
                    curve + ": a different peer produced the same shared secret");
        }
    }

    /**
     * For every registered {@code ECDHwithSHAnnnKDF} name, the derived KEK must
     * be byte-identical to BouncyCastle's, across all three wrap lengths and
     * both the no-UKM and random-UKM cases. A different UKM must derive a
     * different KEK, so a KDF that ignored it cannot pass.
     */
    @Test
    public void everyRegisteredEcdhKdfAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("everyRegisteredEcdhKdfAgreesWithBouncyCastle");

        for (String alg : registered("KeyAgreement"))
        {
            if (!isKdfAgreement(alg))
            {
                continue;
            }

            for (int trial = 0; trial < TRIALS; trial++)
            {
                KeyPair alice = generate("P-256");
                KeyPair bob = generate("P-256");
                PrivateKey alicePeer = toBc(alice.getPrivate());
                PublicKey bobPeer = toBc(bob.getPublic());

                byte[] ukm = null;
                if (trial % 2 == 1)
                {
                    ukm = new byte[8 + sr.nextInt(40)];
                    sr.nextBytes(ukm);
                }

                for (String wrapOid : WRAP_OIDS)
                {
                    String tag = alg + " wrap=" + wrapOid
                            + " ukm=" + (ukm == null ? "none" : Integer.toString(ukm.length));

                    byte[] jslKek = deriveKdf(JSL, alg, alice.getPrivate(), bob.getPublic(), ukm, wrapOid);
                    byte[] bcKek = deriveKdf(BC, alg, alicePeer, bobPeer, ukm, wrapOid);
                    Assertions.assertArrayEquals(bcKek, jslKek, tag + ": derived KEK differs from BC");

                    byte[] otherUkm = new byte[16];
                    sr.nextBytes(otherUkm);
                    byte[] otherKek = deriveKdf(JSL, alg, alice.getPrivate(), bob.getPublic(),
                            otherUkm, wrapOid);
                    Assertions.assertFalse(Arrays.areEqual(jslKek, otherKek),
                            tag + ": a different UKM derived the same KEK");
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // KeyFactory and AlgorithmParameters — byte-equality
    // -----------------------------------------------------------------

    /**
     * A keypair generated by either provider must re-encode identically
     * through the other, on both halves, and still operate afterwards.
     */
    @Test
    public void keysRoundTripThroughBothKeyFactories() throws Exception
    {
        SecureRandom sr = seededRandom("keysRoundTripThroughBothKeyFactories");

        KeyFactory jslKf = KeyFactory.getInstance("EC", JSL);

        for (String curve : CURVES)
        {
            KeyPair jslPair = generate(curve);

            // The PUBLIC half must be byte-identical — SubjectPublicKeyInfo has
            // no optional fields the two encoders can disagree about.
            Assertions.assertTrue(Arrays.areEqual(jslPair.getPublic().getEncoded(),
                            toBc(jslPair.getPublic()).getEncoded()),
                    curve + ": BC re-encoded a JSL public key differently");

            // The PRIVATE half legitimately differs; see
            // ecPrivateKeyEncodingsDifferOnlyByTheRedundantCurveParameters.
            // What must hold here is that the key material survives the
            // crossing, which is asserted by operating with it below.
            Assertions.assertEquals(privateValue(jslPair.getPrivate()),
                    privateValue(toBc(jslPair.getPrivate())),
                    curve + ": BC decoded a different private value from a JSL key");

            KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", BC);
            bcKpg.initialize(new ECGenParameterSpec(curve));
            KeyPair bcPair = bcKpg.generateKeyPair();

            PublicKey viaJslPub = jslKf.generatePublic(
                    new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));
            PrivateKey viaJslPriv = jslKf.generatePrivate(
                    new PKCS8EncodedKeySpec(bcPair.getPrivate().getEncoded()));
            Assertions.assertTrue(Arrays.areEqual(bcPair.getPublic().getEncoded(),
                            viaJslPub.getEncoded()),
                    curve + ": JSL re-encoded a BC public key differently");
            Assertions.assertEquals(privateValue(bcPair.getPrivate()), privateValue(viaJslPriv),
                    curve + ": JSL decoded a different private value from a BC key");

            byte[] msg = new byte[64];
            sr.nextBytes(msg);
            byte[] sig = sign("SHA256withECDSA", JSL, viaJslPriv, msg, curve);
            Assertions.assertTrue(verify("SHA256withECDSA", JSL, viaJslPub, msg, sig, curve),
                    curve + ": a round-tripped BC keypair no longer operates under JSL");
        }
    }

    /**
     * The named-curve {@code AlgorithmParameters} encoding must be identical
     * to BC's, and each provider must read the other's back to the same curve.
     */
    @Test
    public void algorithmParametersAgreeWithBouncyCastle() throws Exception
    {
        for (String curve : CURVES)
        {
            AlgorithmParameters jslAp = AlgorithmParameters.getInstance("EC", JSL);
            jslAp.init(new ECGenParameterSpec(curve));
            AlgorithmParameters bcAp = AlgorithmParameters.getInstance("EC", BC);
            bcAp.init(new ECGenParameterSpec(curve));
            Assertions.assertArrayEquals(bcAp.getEncoded(), jslAp.getEncoded(),
                    curve + ": JSL and BC encode the named curve differently");

            AlgorithmParameters bcReread = AlgorithmParameters.getInstance("EC", BC);
            bcReread.init(jslAp.getEncoded());
            Assertions.assertArrayEquals(jslAp.getEncoded(), bcReread.getEncoded(),
                    curve + ": BC did not read a JSL encoding back unchanged");

            AlgorithmParameters jslReread = AlgorithmParameters.getInstance("EC", JSL);
            jslReread.init(bcAp.getEncoded());
            Assertions.assertArrayEquals(bcAp.getEncoded(), jslReread.getEncoded(),
                    curve + ": JSL did not read a BC encoding back unchanged");
        }
    }

    /** The scalar {@code d}, read through the JCE interface rather than the encoding. */
    private static java.math.BigInteger privateValue(PrivateKey key)
    {
        return ((java.security.interfaces.ECPrivateKey) key).getS();
    }

    /**
     * JSL and BouncyCastle encode an EC PRIVATE key differently, and the
     * difference is exactly one optional field. Pinned rather than tolerated,
     * so a future change to either side's encoder is reported here instead of
     * surfacing as an interop failure somewhere else.
     * <p>
     * RFC 5915's {@code ECPrivateKey} carries an OPTIONAL {@code [0]
     * parameters} naming the curve. Inside a PKCS#8 {@code PrivateKeyInfo} that
     * curve is already named in the outer AlgorithmIdentifier, so the field is
     * redundant: BC emits it anyway, OpenSSL (and therefore JSL) omits it. Both
     * are well-formed DER and each side decodes the other, which is what makes
     * this a difference rather than a defect — but it does mean private-key
     * agreement for EC is the key material, not the bytes.
     * <p>
     * Measured on P-256: JSL 138 bytes, BC 150, differing by the 12-byte
     * {@code a00a06082a8648ce3d030107} that names prime256v1 a second time.
     */
    @Test
    public void ecPrivateKeyEncodingsDifferOnlyByTheRedundantCurveParameters() throws Exception
    {
        for (String curve : CURVES)
        {
            KeyPair pair = generate(curve);
            byte[] jslEnc = pair.getPrivate().getEncoded();
            byte[] bcEnc = toBc(pair.getPrivate()).getEncoded();

            Assertions.assertFalse(Arrays.areEqual(jslEnc, bcEnc),
                    curve + ": the encoders now agree — if BC or OpenSSL changed, this pin is stale "
                            + "and keysRoundTripThroughBothKeyFactories should assert bytes again");

            // Same key material on both sides, read through the JCE interface.
            Assertions.assertEquals(privateValue(pair.getPrivate()),
                    privateValue(toBc(pair.getPrivate())),
                    curve + ": the two encodings decode to different private values");

            // The difference is the inner [0] parameters field, and nothing else:
            // BC carries it, JSL does not, and stripping it makes the two equal.
            byte[] inner = innerEcPrivateKey(jslEnc);
            byte[] bcInner = innerEcPrivateKey(bcEnc);
            Assertions.assertFalse(hasContextTag(inner, 0),
                    curve + ": JSL now emits the redundant [0] parameters");
            Assertions.assertTrue(hasContextTag(bcInner, 0),
                    curve + ": BC no longer emits the [0] parameters this pin describes");
            Assertions.assertTrue(hasContextTag(inner, 1) && hasContextTag(bcInner, 1),
                    curve + ": both sides must still carry the [1] publicKey");
        }
    }

    /** The {@code privateKey} OCTET STRING's content — an RFC 5915 ECPrivateKey. */
    private static byte[] innerEcPrivateKey(byte[] pkcs8) throws Exception
    {
        org.bouncycastle.asn1.ASN1Sequence seq =
                org.bouncycastle.asn1.ASN1Sequence.getInstance(pkcs8);
        return org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
    }

    /** Whether the ECPrivateKey SEQUENCE carries the given context-specific tag. */
    private static boolean hasContextTag(byte[] ecPrivateKey, int tagNo) throws Exception
    {
        org.bouncycastle.asn1.ASN1Sequence seq =
                org.bouncycastle.asn1.ASN1Sequence.getInstance(ecPrivateKey);
        for (int i = 0; i < seq.size(); i++)
        {
            org.bouncycastle.asn1.ASN1Encodable o = seq.getObjectAt(i);
            if (o instanceof org.bouncycastle.asn1.ASN1TaggedObject
                    && ((org.bouncycastle.asn1.ASN1TaggedObject) o).getTagNo() == tagNo)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * The two Oakley EC2N groups do ECDH but refuse ECDSA signing, on every
     * registered name including the raw one. Both halves are asserted: a
     * silent skip would hide either OpenSSL starting to sign on them or ECDH
     * breaking there.
     * <p>
     * These are RFC 2409 key-agreement groups. Measured: signing fails for all
     * ten registered names on these two and succeeds for all ten on every
     * other curve the build serves — including 112-bit orders — so the cause
     * is the group, not a small order.
     */
    @Test
    public void oakleyCurvesDoEcdhButRefuseEcdsaSigning() throws Exception
    {
        SecureRandom sr = seededRandom("oakleyCurvesDoEcdhButRefuseEcdsaSigning");
        List<String> algs = registered("Signature");
        Assertions.assertFalse(EcCurves.NO_ECDSA_SIGNING.isEmpty(), "nothing to assert");

        for (String curve : EcCurves.NO_ECDSA_SIGNING)
        {
            KeyPair alice = generate(curve);
            KeyPair bob = generate(curve);

            // ECDH works, and is what these groups exist for.
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", JSL);
            ka.init(alice.getPrivate());
            ka.doPhase(bob.getPublic(), true);
            byte[] secret = ka.generateSecret();
            Assertions.assertTrue(secret.length > 0, curve + ": ECDH produced an empty secret");

            KeyAgreement other = KeyAgreement.getInstance("ECDH", JSL);
            other.init(alice.getPrivate());
            other.doPhase(generate(curve).getPublic(), true);
            Assertions.assertFalse(Arrays.areEqual(secret, other.generateSecret()),
                    curve + ": a different peer produced the same shared secret");

            // Signing is refused, on every registered name.
            byte[] message = new byte[64];
            sr.nextBytes(message);
            for (String alg : algs)
            {
                Assertions.assertThrows(OpenSSLException.class,
                        () -> sign(alg, JSL, alice.getPrivate(), message, curve),
                        curve + " / " + alg + ": expected OpenSSL to refuse ECDSA signing on an "
                                + "Oakley key-agreement group; if it now signs, drop this curve from "
                                + "EcCurves.NO_ECDSA_SIGNING so the sweep covers it");
            }
        }
    }
}
