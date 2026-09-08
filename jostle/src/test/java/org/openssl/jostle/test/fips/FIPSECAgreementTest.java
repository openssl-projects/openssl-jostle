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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cross-provider agreement for the FIPS provider's EC surface (ECDSA
 * signatures and ECDH key agreement).
 * <p>
 * This is the EC analogue of {@code FIPSAESAgreementTest}: every operation is
 * exercised against BOTH the non-FIPS Jostle provider (JSL) AND BouncyCastle
 * (BC), in the same JVM, and in <b>both directions</b> for each reference.
 * <p>
 * <b>Key-isolation caveat.</b> A Jostle key belongs to the provider INSTANCE
 * that created it, and since MT-14 each provider's operational SPIs reject the
 * other Jostle provider's key object - PUBLIC as well as PRIVATE - with
 * {@link java.security.InvalidKeyException}. To make all three providers
 * operate on <i>identical</i> key material we therefore generate a keypair
 * once, take its X.509 (public) and PKCS#8 (private) encodings, and decode
 * BOTH halves through EACH provider's own {@code KeyFactory} - the sanctioned
 * route, and the only one.
 * <p>
 * ECDSA is randomised, so signatures are not byte-comparable; instead every
 * signature produced by one provider is cross-verified through the other two,
 * both directions, plus a tampered-message differentiator. ECDH shared secrets
 * ARE deterministic and must be byte-identical across the three providers; a
 * different peer key is the differentiator. A SHA-2 digest
 * ({@code SHA256withECDSA}) is used throughout. ({@code NoneWithECDSA} is served
 * by JSLFIPS in both directions and is covered by
 * {@code FIPSECTest.noneWithECDSA_servedBothDirectionsOverSuppliedDigest}.)
 * <p>
 * Inputs (message content and length) are drawn from a per-test SHA1PRNG whose
 * seed is logged, so a flaky run is reproducible (per CLAUDE.md). Keypairs come
 * from each provider's own strength-appropriate keygen RNG.
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSECAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String[] CURVES = {"secp256r1", "secp384r1", "secp521r1"};
    private static final String SIG_ALG = "SHA256withECDSA";
    private static final int TRIALS = 4;

    // Registered ECDHwithSHAnnnKDF KeyAgreement variants (ECDH shared secret run
    // through an X9.63 KDF to derive a wrapping KEK). All five PRFs are served:
    // the module performs X963KDF with a SHA-1 PRF under fips=yes. Cert #4985
    // Table 8 lists that usage as non-approved, which is the operator's
    // compliance determination rather than a capability we withhold.
    private static final String[] ECDH_KDF_NAMES = {
            "ECDHWITHSHA1KDF", "ECDHWITHSHA224KDF", "ECDHWITHSHA256KDF", "ECDHWITHSHA384KDF", "ECDHWITHSHA512KDF"
    };

    // AES key-wrap OIDs used as the KDF's target (KEK) algorithm, giving 16/24/
    // 32-byte KEKs. 3DES-wrap is intentionally excluded — Triple-DES is
    // non-approved in the FIPS module.
    private static final String[] WRAP_OIDS = {
            "2.16.840.1.101.3.4.1.5",   // id-aes128-wrap -> 16-byte KEK
            "2.16.840.1.101.3.4.1.25",  // id-aes192-wrap -> 24-byte KEK
            "2.16.840.1.101.3.4.1.45"   // id-aes256-wrap -> 32-byte KEK
    };

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        ensureProviders();
    }

    private static void ensureProviders()
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

    /**
     * A public/private key pair as decoded through a single provider's
     * KeyFactory - so it is operable by that provider (private keys are
     * provider-bound; see the class Javadoc).
     */
    private static final class Keys
    {
        final PublicKey pub;
        final PrivateKey priv;

        Keys(PublicKey pub, PrivateKey priv)
        {
            this.pub = pub;
            this.priv = priv;
        }
    }

    /** Generate an EC keypair on the given curve through JSLFIPS. */
    private static KeyPair generate(String provider, String curve) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    /** Decode both halves of an encoded keypair through {@code provider}'s KeyFactory. */
    private static Keys importInto(String provider, byte[] x509Pub, byte[] pkcs8Priv) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("EC", provider);
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(x509Pub));
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Priv));
        return new Keys(pub, priv);
    }

    /**
     * Generate one keypair and materialise it, from identical encoded bytes,
     * as an operable {@link Keys} inside each of the three providers.
     */
    private static Map<String, Keys> shareAcrossProviders(String curve) throws Exception
    {
        KeyPair kp = generate(FIPS, curve);
        byte[] x509 = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        Map<String, Keys> shared = new LinkedHashMap<>();
        shared.put(FIPS, importInto(FIPS, x509, pkcs8));
        shared.put(JSL, importInto(JSL, x509, pkcs8));
        shared.put(BC, importInto(BC, x509, pkcs8));
        return shared;
    }

    private static byte[] sign(String provider, PrivateKey key, byte[] message) throws Exception
    {
        Signature s = Signature.getInstance(SIG_ALG, provider);
        s.initSign(key);
        s.update(message);
        return s.sign();
    }

    private static boolean verify(String provider, PublicKey key, byte[] message, byte[] sig) throws Exception
    {
        Signature s = Signature.getInstance(SIG_ALG, provider);
        s.initVerify(key);
        s.update(message);
        return s.verify(sig);
    }

    private static byte[] agree(String provider, PrivateKey priv, PublicKey peerPub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", provider);
        ka.init(priv);
        ka.doPhase(peerPub, true);
        return ka.generateSecret();
    }

    /**
     * Derive a wrapping KEK via an ECDHwithSHAnnnKDF transformation inside
     * {@code provider}: ECDH over (priv, peerPub) then the X9.63 KDF, targeting
     * the {@code wrapOid} key length, with optional user keying material. BC
     * uses its own {@code UserKeyingMaterialSpec}; the Jostle providers use
     * theirs.
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

    /**
     * ECDSA is randomised, so signatures cannot be byte-compared: instead each
     * provider's signature is cross-verified through the other two, both
     * directions. A tampered message must fail JSLFIPS verification.
     */
    @Test
    public void ecdsaAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("ecdsaAgrees");

        for (String curve : CURVES)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                Map<String, Keys> keys = shareAcrossProviders(curve);
                byte[] message = new byte[1 + sr.nextInt(512)];
                sr.nextBytes(message);
                String tag = "ECDSA " + curve + " trial=" + trial;

                // JSLFIPS sign -> JSL and BC verify.
                byte[] sigFips = sign(FIPS, keys.get(FIPS).priv, message);
                Assertions.assertTrue(verify(JSL, keys.get(JSL).pub, message, sigFips),
                        tag + ": JSLFIPS sign -> JSL verify");
                Assertions.assertTrue(verify(BC, keys.get(BC).pub, message, sigFips),
                        tag + ": JSLFIPS sign -> BC verify");

                // JSL sign -> JSLFIPS verify.
                byte[] sigJsl = sign(JSL, keys.get(JSL).priv, message);
                Assertions.assertTrue(verify(FIPS, keys.get(FIPS).pub, message, sigJsl),
                        tag + ": JSL sign -> JSLFIPS verify");

                // BC sign -> JSLFIPS verify.
                byte[] sigBc = sign(BC, keys.get(BC).priv, message);
                Assertions.assertTrue(verify(FIPS, keys.get(FIPS).pub, message, sigBc),
                        tag + ": BC sign -> JSLFIPS verify");

                // Differentiator: a flipped message byte must not verify.
                byte[] tampered = Arrays.clone(message);
                tampered[sr.nextInt(tampered.length)] ^= 0x01;
                Assertions.assertFalse(verify(FIPS, keys.get(FIPS).pub, tampered, sigFips),
                        tag + ": tampered message must not verify");
            }
        }
    }

    /**
     * ECDH shared secrets are deterministic: all three providers, keyed with
     * identical imported material, must derive byte-identical secrets. A
     * different peer key is the differentiator.
     */
    @Test
    public void ecdhAgrees() throws Exception
    {
        for (String curve : CURVES)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                Map<String, Keys> alice = shareAcrossProviders(curve);
                Map<String, Keys> bob = shareAcrossProviders(curve);
                String tag = "ECDH " + curve + " trial=" + trial;

                byte[] secretFips = agree(FIPS, alice.get(FIPS).priv, bob.get(FIPS).pub);
                byte[] secretJsl = agree(JSL, alice.get(JSL).priv, bob.get(JSL).pub);
                byte[] secretBc = agree(BC, alice.get(BC).priv, bob.get(BC).pub);

                Assertions.assertArrayEquals(secretFips, secretJsl,
                        tag + ": JSLFIPS vs JSL shared secret");
                Assertions.assertArrayEquals(secretFips, secretBc,
                        tag + ": JSLFIPS vs BC shared secret");

                // Differentiator: a different peer public key yields a
                // different secret.
                Map<String, Keys> carol = shareAcrossProviders(curve);
                byte[] secretCarol = agree(FIPS, alice.get(FIPS).priv, carol.get(FIPS).pub);
                Assertions.assertFalse(Arrays.areEqual(secretFips, secretCarol),
                        tag + ": different peer produced an identical secret");
            }
        }
    }

    /**
     * The registered ECDHwithSHAnnnKDF KeyAgreement variants (ECDH secret fed
     * through an X9.63 KDF to derive a wrapping KEK) must derive a byte-identical
     * KEK across JSLFIPS, JSL, and BC — for every registered digest, every
     * AES-wrap target length, and both the no-UKM and random-UKM cases. A
     * different UKM is the differentiator.
     */
    @Test
    public void ecdhKdfAgrees() throws Exception
    {
        SecureRandom sr = seededRandom("ecdhKdfAgrees");

        for (String name : ECDH_KDF_NAMES)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                Map<String, Keys> alice = shareAcrossProviders("secp256r1");
                Map<String, Keys> bob = shareAcrossProviders("secp256r1");

                byte[] ukm = null;
                if (trial % 2 == 1)
                {
                    ukm = new byte[8 + sr.nextInt(40)];
                    sr.nextBytes(ukm);
                }

                for (String wrapOid : WRAP_OIDS)
                {
                    String tag = name + " wrap=" + wrapOid
                            + " ukm=" + (ukm == null ? "none" : Integer.toString(ukm.length))
                            + " trial=" + trial;

                    byte[] kekFips = deriveKdf(FIPS, name, alice.get(FIPS).priv, bob.get(FIPS).pub, ukm, wrapOid);
                    byte[] kekJsl = deriveKdf(JSL, name, alice.get(JSL).priv, bob.get(JSL).pub, ukm, wrapOid);
                    byte[] kekBc = deriveKdf(BC, name, alice.get(BC).priv, bob.get(BC).pub, ukm, wrapOid);

                    Assertions.assertArrayEquals(kekFips, kekJsl, tag + ": KEK JSLFIPS vs JSL");
                    Assertions.assertArrayEquals(kekFips, kekBc, tag + ": KEK JSLFIPS vs BC");

                    // Differentiator: a different UKM must change the derived KEK.
                    byte[] otherUkm = new byte[16];
                    sr.nextBytes(otherUkm);
                    byte[] kekOther = deriveKdf(FIPS, name, alice.get(FIPS).priv, bob.get(FIPS).pub, otherUkm, wrapOid);
                    Assertions.assertFalse(Arrays.areEqual(kekFips, kekOther),
                            tag + ": distinct UKM produced an identical KEK");
                }
            }
        }
    }

    /**
     * Key encodings round-trip through BouncyCastle's KeyFactory in BOTH
     * directions, for BOTH halves: JSLFIPS-generated keys decode through BC and
     * operate, and BC-generated keys decode through JSLFIPS and operate.
     */
    @Test
    public void keysRoundTripThroughBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("keysRoundTripThroughBouncyCastle");

        for (String curve : CURVES)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                String tag = curve + " trial=" + trial;
                byte[] message = new byte[1 + sr.nextInt(256)];
                sr.nextBytes(message);

                // Direction 1: JSLFIPS-generated keys -> BC KeyFactory.
                KeyPair fipsKp = generate(FIPS, curve);
                KeyFactory bcKf = KeyFactory.getInstance("EC", BC);
                PublicKey bcPub = bcKf.generatePublic(
                        new X509EncodedKeySpec(fipsKp.getPublic().getEncoded()));
                PrivateKey bcPriv = bcKf.generatePrivate(
                        new PKCS8EncodedKeySpec(fipsKp.getPrivate().getEncoded()));

                byte[] sig1 = sign(FIPS, fipsKp.getPrivate(), message);
                Assertions.assertTrue(verify(BC, bcPub, message, sig1),
                        tag + ": JSLFIPS sign -> BC-decoded public verify");
                byte[] sig2 = sign(BC, bcPriv, message);
                Assertions.assertTrue(verify(FIPS, fipsKp.getPublic(), message, sig2),
                        tag + ": BC-decoded private sign -> JSLFIPS verify");

                // Direction 2: BC-generated keys -> JSLFIPS KeyFactory.
                KeyPair bcKp = generate(BC, curve);
                KeyFactory fipsKf = KeyFactory.getInstance("EC", FIPS);
                PublicKey fipsPub = fipsKf.generatePublic(
                        new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));
                PrivateKey fipsPriv = fipsKf.generatePrivate(
                        new PKCS8EncodedKeySpec(bcKp.getPrivate().getEncoded()));

                byte[] sig3 = sign(FIPS, fipsPriv, message);
                Assertions.assertTrue(verify(BC, bcKp.getPublic(), message, sig3),
                        tag + ": JSLFIPS-decoded private sign -> BC verify");
                byte[] sig4 = sign(BC, bcKp.getPrivate(), message);
                Assertions.assertTrue(verify(FIPS, fipsPub, message, sig4),
                        tag + ": BC sign -> JSLFIPS-decoded public verify");
            }
        }
    }

    /**
     * The ONLY registered ECDSA name whose signing refusal is a legitimate
     * deployment rather than a regression. {@code signature-digest-check} is a
     * {@code fipsinstall} setting — off at defaults, on under {@code -pedantic}
     * — so SHA-1 signing may or may not be available on a supported module.
     * <p>
     * Every other registered digest is approved (the SHA-2 family and the SHA-3
     * family, which the module's {@code digest_to_nid} table lists; NONE takes
     * a caller-supplied digest), so a refusal on any of them fails hard. A
     * uniform tolerance would let a module that regressed into refusing
     * {@code SHA256withECDSA} pass this test as "contract".
     */
    private static final java.util.Set<String> SHA1_ECDSA =
            java.util.Collections.singleton("SHA1WITHECDSA");

    /** The five JCA types {@code ProvFIPSEC} registers under. */
    private static final String[] GUARDED_TYPES = {
            "AlgorithmParameters", "KeyAgreement", "KeyFactory", "KeyPairGenerator", "Signature"
    };

    /** Every EC primary of one type JSLFIPS registers, sorted. */
    private static java.util.List<String> registeredFips(String type)
    {
        java.security.Provider provider = FIPSTestUtil.assumeFipsProvider();
        java.util.List<String> names = new java.util.ArrayList<String>();
        for (java.security.Provider.Service svc : provider.getServices())
        {
            String cn = svc.getClassName();
            if (type.equals(svc.getType()) && cn != null && cn.startsWith(CipherFamilies.EC_PREFIX))
            {
                names.add(svc.getAlgorithm());
            }
        }
        Assertions.assertFalse(names.isEmpty(), "JSLFIPS registered no EC " + type + " services");
        java.util.Collections.sort(names);
        return names;
    }

    private static byte[] signWith(String alg, String provider, PrivateKey key, byte[] message)
            throws Exception
    {
        Signature s = Signature.getInstance(alg, provider);
        s.initSign(key);
        s.update(message);
        return s.sign();
    }

    private static boolean verifyWith(String alg, String provider, PublicKey key, byte[] message,
                                      byte[] sig) throws Exception
    {
        Signature v = Signature.getInstance(alg, provider);
        v.initVerify(key);
        v.update(message);
        return v.verify(sig);
    }

    /**
     * EVERY registered ECDSA name cross-verified with BC, not just the one
     * {@link #ecdsaAgrees()} drives. Both directions where the module signs.
     * <p>
     * The both-branches tolerance is scoped to {@code SHA1withECDSA} alone
     * ({@link #SHA1_ECDSA}); every other name must actually sign, so a module
     * that regressed into refusing an approved digest fails here rather than
     * passing as "contract". Verification is legacy-approved and must work on
     * every name either way.
     * <p>
     * {@code NoneWithECDSA} takes a caller-supplied digest, sized here to the
     * 256-bit order of the test curve.
     */
    @Test
    public void everyRegisteredEcdsaNameCrossVerifiesWithBc() throws Exception
    {
        SecureRandom sr = seededRandom("everyRegisteredEcdsaNameCrossVerifiesWithBc");
        Map<String, Keys> keys = shareAcrossProviders("secp256r1");

        for (String alg : registeredFips("Signature"))
        {
            byte[] message = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(message);
            byte[] input = "NONEWITHECDSA".equalsIgnoreCase(alg)
                    ? java.security.MessageDigest.getInstance("SHA-256").digest(message)
                    : message;

            byte[] tampered = input.clone();
            tampered[sr.nextInt(tampered.length)] ^= 0x01;

            // BC signs, JSLFIPS verifies — available on every module.
            byte[] sigBc = signWith(alg, BC, keys.get(BC).priv, input);
            Assertions.assertTrue(verifyWith(alg, FIPS, keys.get(FIPS).pub, input, sigBc),
                    alg + ": BC sign -> JSLFIPS verify");
            Assertions.assertFalse(verifyWith(alg, FIPS, keys.get(FIPS).pub, tampered, sigBc),
                    alg + ": tampered message must not verify");

            if (!SHA1_ECDSA.contains(alg.toUpperCase(java.util.Locale.ROOT)))
            {
                // An APPROVED digest. A refusal here is a regression, not a
                // configuration — no tolerance, so it fails hard.
                byte[] sigFips = signWith(alg, FIPS, keys.get(FIPS).priv, input);
                Assertions.assertTrue(verifyWith(alg, BC, keys.get(BC).pub, input, sigFips),
                        alg + ": the module signed, so BC must verify the result");
                continue;
            }

            // SHA-1 alone is a contract rather than one answer: whether signing
            // is refused is the signature-digest-check fipsinstall setting, off
            // at defaults and on under -pedantic. Both are legitimate.
            try
            {
                byte[] sigFips = signWith(alg, FIPS, keys.get(FIPS).priv, input);
                Assertions.assertTrue(verifyWith(alg, BC, keys.get(BC).pub, input, sigFips),
                        alg + ": the module signed, so BC must verify the result");
            }
            catch (java.security.InvalidKeyException ex)
            {
                // MT-76: the module's refusal now reaches callers as the
                // JCE-canonical InvalidKeyException with the OpenSSLException
                // preserved as the cause; the message text is unchanged.
                Assertions.assertTrue(ex.getCause() instanceof OpenSSLException,
                        "the OpenSSLException must be preserved as the cause, got: " + ex.getCause());
                // The module's wording differs between the two supported
                // versions, so both are accepted — 3.1.2 says "digest not
                // allowed", 3.5.x says "invalid digest". Pinning only the
                // first passes on 3.1.2 and on any 3.5.x config where this
                // branch is unreachable, and fails exactly where the gate
                // fires. FIPSSha1SignatureGateTest is the source of this pair.
                String m = String.valueOf(ex.getMessage());
                Assertions.assertTrue(m.contains("digest not allowed") || m.contains("invalid digest"),
                        alg + ": expected a module digest rejection, got: " + m);
            }
        }
    }

    /**
     * The named-curve {@code AlgorithmParameters} encoding must be identical to
     * BC's, and each side must read the other's back.
     */
    @Test
    public void algorithmParametersAgreeWithBc() throws Exception
    {
        for (String curve : CURVES)
        {
            java.security.AlgorithmParameters fipsAp =
                    java.security.AlgorithmParameters.getInstance("EC", FIPS);
            fipsAp.init(new java.security.spec.ECGenParameterSpec(curve));
            java.security.AlgorithmParameters bcAp =
                    java.security.AlgorithmParameters.getInstance("EC", BC);
            bcAp.init(new java.security.spec.ECGenParameterSpec(curve));
            Assertions.assertArrayEquals(bcAp.getEncoded(), fipsAp.getEncoded(),
                    curve + ": JSLFIPS and BC encode the named curve differently");

            java.security.AlgorithmParameters reread =
                    java.security.AlgorithmParameters.getInstance("EC", FIPS);
            reread.init(bcAp.getEncoded());
            Assertions.assertArrayEquals(bcAp.getEncoded(), reread.getEncoded(),
                    curve + ": JSLFIPS did not read a BC encoding back unchanged");
        }
    }

    /**
     * Completeness guard, both directions, over the EC PRIMARIES JSLFIPS
     * registers. {@code getServices()} omits aliases, so the OID spellings are
     * {@code FIPSOidSpellingParityTest}'s job, not this one.
     * <p>
     * Compared against what is ACTUALLY registered rather than a fixed list,
     * since a gated family is legitimately absent on one module.
     */
    @Test
    public void everyRegisteredEcServiceIsCovered()
    {
        java.security.Provider provider = FIPSTestUtil.assumeFipsProvider();

        java.util.SortedSet<String> covered = new java.util.TreeSet<String>();
        for (String alg : registeredFips("Signature"))
        {
            // Every one is driven by everyRegisteredEcdsaNameCrossVerifiesWithBc.
            covered.add("Signature." + alg.toUpperCase(java.util.Locale.ROOT));
        }
        covered.add("KeyAgreement.ECDH");
        for (String alg : ECDH_KDF_NAMES)
        {
            covered.add("KeyAgreement." + alg.toUpperCase(java.util.Locale.ROOT));
        }
        covered.add("KeyFactory.EC");
        covered.add("KeyPairGenerator.EC");
        covered.add("AlgorithmParameters.EC");

        java.util.SortedSet<String> registered = new java.util.TreeSet<String>();
        for (java.security.Provider.Service svc : provider.getServices())
        {
            String cn = svc.getClassName();
            if (cn != null && cn.startsWith(CipherFamilies.EC_PREFIX))
            {
                registered.add(svc.getType() + "." + svc.getAlgorithm().toUpperCase(java.util.Locale.ROOT));
            }
        }
        Assertions.assertFalse(registered.isEmpty(), "JSLFIPS registered no EC services");

        java.util.SortedSet<String> uncovered = new java.util.TreeSet<String>(registered);
        uncovered.removeAll(covered);
        Assertions.assertTrue(uncovered.isEmpty(),
                "JSLFIPS registers EC services with no agreement coverage in this class: "
                        + uncovered + "\nAdd them to a coverage group.");

        java.util.SortedSet<String> stale = new java.util.TreeSet<String>(covered);
        stale.removeAll(registered);
        Assertions.assertTrue(stale.isEmpty(),
                "this class names EC services JSLFIPS does not register: " + stale);
    }
}
