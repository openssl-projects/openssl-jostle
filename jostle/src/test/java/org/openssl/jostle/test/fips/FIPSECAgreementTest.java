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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
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
 * <b>Key-isolation caveat.</b> JSLFIPS and JSL PRIVATE keys are bound to the
 * interface library that created them - each provider's operational SPIs
 * reject the other Jostle provider's private key object with
 * {@link java.security.InvalidKeyException}. PUBLIC keys carry no secret and
 * cross freely. To make all three providers operate on <i>identical</i> key
 * material we therefore generate a keypair once, take its X.509 (public) and
 * PKCS#8 (private) encodings, and decode BOTH halves through EACH provider's
 * own {@code KeyFactory} - the sanctioned route for sharing a private key.
 * <p>
 * ECDSA is randomised, so signatures are not byte-comparable; instead every
 * signature produced by one provider is cross-verified through the other two,
 * both directions, plus a tampered-message differentiator. ECDH shared secrets
 * ARE deterministic and must be byte-identical across the three providers; a
 * different peer key is the differentiator. {@code NoneWithECDSA} is
 * deliberately absent from JSLFIPS (a non-approved service), so a SHA-2 digest
 * ({@code SHA256withECDSA}) is used throughout.
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
    // through an X9.63 KDF to derive a wrapping KEK). SHA-1 as a KDF PRF is
    // approved even though SHA-1 signature generation is not (see
    // FIPSSha1SignatureGateTest).
    private static final String[] ECDH_KDF_NAMES = {
            "ECDHWITHSHA1KDF", "ECDHWITHSHA256KDF", "ECDHWITHSHA384KDF", "ECDHWITHSHA512KDF"
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
        ensureProviders();
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
        ensureProviders();

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
        ensureProviders();
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
        ensureProviders();
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
}
