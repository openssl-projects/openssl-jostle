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
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Cross-provider agreement for the FIPS provider's DH (Diffie-Hellman)
 * key-agreement surface. The FIPS analogue of {@code dh/DHKeyAgreementTest},
 * comparing JSLFIPS against BOTH the non-FIPS provider (JSL) AND BouncyCastle
 * (BC) in the same JVM.
 * <p>
 * The domain group is fixed at RFC 7919 <b>ffdhe2048</b> (a FIPS-approved
 * safe-prime group, per SP 800-56A): the KeyPairGenerator's
 * {@code initialize(2048)} maps to that named group, so keygen is instant and
 * no ad-hoc (slow, possibly non-approved) prime search is performed.
 * <p>
 * Because JSLFIPS and JSL PRIVATE keys are isolated to the interface library
 * that created them (a KeyAgreement rejects the other Jostle provider's
 * private key), the same keypair is run across providers by encoding
 * (PKCS#8 / X.509) and decoding through EACH provider's own KeyFactory before
 * use — the {@link #agreeIn} helper does exactly this, uniformly for JSLFIPS,
 * JSL, and BC. With the same private on each side and the peer's public
 * supplied, all three providers must derive byte-identical shared secrets
 * (DH secrets are padded to the prime length, so byte-identity is a strong
 * differentiator a wrong-but-self-consistent implementation cannot satisfy).
 * <p>
 * Inputs are fresh random keypairs per trial from a per-test SHA1PRNG whose
 * seed is logged, so a flaky run is reproducible (per CLAUDE.md). Gated on
 * {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSDHAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final int TRIALS = 10;

    // ffdhe2048: 2048-bit prime -> 256-byte padded shared secret.
    private static final int P_BITS = 2048;
    private static final int SECRET_LEN = P_BITS / 8;

    // AES key-wrap OIDs used as the RFC 2631 (X9.42) KDF's target (KEK)
    // algorithm, giving 16/24/32-byte KEKs. 3DES-wrap is intentionally
    // excluded — Triple-DES is non-approved in the FIPS module.
    private static final String[] WRAP_OIDS = {
            "2.16.840.1.101.3.4.1.5",   // id-aes128-wrap -> 16-byte KEK
            "2.16.840.1.101.3.4.1.25",  // id-aes192-wrap -> 24-byte KEK
            "2.16.840.1.101.3.4.1.45"   // id-aes256-wrap -> 32-byte KEK
    };

    // The Jostle providers register the RFC 2631 DH-KDF under the name
    // "DHWITHRFC2631KDF" (and the ESDH OID alias); BouncyCastle registers it
    // only under the id-alg-ESDH OID.
    private static final String ESDH_OID = "1.2.840.113549.1.9.16.3.5"; // id-alg-ESDH

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
     * A fresh ffdhe2048 keypair from the FIPS provider. {@code initialize(2048)}
     * selects the RFC 7919 named group, so every keypair shares the same fixed
     * domain parameters and generation is instant.
     */
    private static KeyPair fipsKeyPair(SecureRandom sr) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", FIPS);
        kpg.initialize(P_BITS, sr);
        return kpg.generateKeyPair();
    }

    /** The fixed ffdhe2048 (p, g), obtained from a FIPS seed keypair. */
    private static DHParameterSpec ffdhe2048Spec(SecureRandom sr) throws Exception
    {
        DHParameterSpec params = ((DHPublicKey) fipsKeyPair(sr).getPublic()).getParams();
        Assertions.assertEquals(P_BITS, params.getP().bitLength(),
                "expected ffdhe2048 (2048-bit prime)");
        return params;
    }

    /**
     * Derive the DH shared secret inside {@code provider}, importing BOTH the
     * private and the peer public key through that provider's own KeyFactory
     * first. This is the sanctioned route across the JSLFIPS/JSL private-key
     * isolation boundary (and the only route into BC), and keeps the call
     * uniform for all three providers.
     */
    private static byte[] agreeIn(String provider, PrivateKey priv, PublicKey pub) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("DH", provider);
        PrivateKey localPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
        PublicKey localPub = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));

        KeyAgreement ka = KeyAgreement.getInstance("DH", provider);
        ka.init(localPriv);
        ka.doPhase(localPub, true);
        return ka.generateSecret();
    }

    /**
     * Derive a wrapping KEK via the registered DHWITHRFC2631KDF transformation
     * inside {@code provider}: DH over (priv, peer) then the RFC 2631 (X9.42)
     * KDF, targeting the {@code wrapOid} key length, with optional user keying
     * material. Both keys are imported through the provider's own KeyFactory
     * first (the sanctioned route across the private-key isolation boundary).
     * BC uses its own {@code UserKeyingMaterialSpec}; the Jostle providers use
     * theirs.
     */
    private static byte[] deriveKdf(String provider, PrivateKey priv, PublicKey pub,
                                    byte[] ukm, String wrapOid) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("DH", provider);
        PrivateKey localPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
        PublicKey localPub = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));

        // BC serves the RFC 2631 DH-KDF only by the ESDH OID; the Jostle
        // providers serve it by name (and by the OID alias) — use the name on
        // the Jostle side to also exercise the name registration.
        String transform = BC.equals(provider) ? ESDH_OID : "DHWITHRFC2631KDF";
        KeyAgreement ka = KeyAgreement.getInstance(transform, provider);
        if (ukm == null)
        {
            ka.init(localPriv);
        }
        else if (BC.equals(provider))
        {
            ka.init(localPriv, new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(ukm));
        }
        else
        {
            ka.init(localPriv, new org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec(ukm));
        }
        ka.doPhase(localPub, true);
        return ka.generateSecret(wrapOid).getEncoded();
    }


    // -----------------------------------------------------------------
    // Cross-provider shared-secret agreement + DH symmetry
    // -----------------------------------------------------------------

    /**
     * Two parties, each with an ffdhe2048 keypair. Every party's secret is
     * computed in JSLFIPS, JSL, and BC (the party's private imported into the
     * provider under test, the peer's public supplied) and asserted
     * byte-identical across all three providers. Standard DH is symmetric, so
     * partyA(privA, pubB) must equal partyB(privB, pubA); that too is asserted
     * and pinned across providers.
     */
    @Test
    public void sharedSecretAgreesAcrossProviders() throws Exception
    {
        SecureRandom sr = seededRandom("sharedSecretAgreesAcrossProviders");

        for (int trial = 0; trial < TRIALS; trial++)
        {
            KeyPair alice = fipsKeyPair(sr);
            KeyPair bob = fipsKeyPair(sr);

            // Both parties drew from the fixed ffdhe2048 group.
            DHParameterSpec pa = ((DHPublicKey) alice.getPublic()).getParams();
            DHParameterSpec pb = ((DHPublicKey) bob.getPublic()).getParams();
            Assertions.assertEquals(pa.getP(), pb.getP(),
                    "trial " + trial + ": parties must share the ffdhe2048 prime");
            Assertions.assertEquals(pa.getG(), pb.getG(),
                    "trial " + trial + ": parties must share the ffdhe2048 generator");
            Assertions.assertEquals(P_BITS, pa.getP().bitLength(),
                    "trial " + trial + ": group must be ffdhe2048");

            // Party A's secret (privA + pubB), computed in each provider.
            byte[] fipsA = agreeIn(FIPS, alice.getPrivate(), bob.getPublic());
            byte[] jslA = agreeIn(JSL, alice.getPrivate(), bob.getPublic());
            byte[] bcA = agreeIn(BC, alice.getPrivate(), bob.getPublic());
            Assertions.assertArrayEquals(fipsA, jslA,
                    "trial " + trial + ": partyA secret JSLFIPS vs JSL");
            Assertions.assertArrayEquals(fipsA, bcA,
                    "trial " + trial + ": partyA secret JSLFIPS vs BC");

            // Party B's secret (privB + pubA), computed in each provider.
            byte[] fipsB = agreeIn(FIPS, bob.getPrivate(), alice.getPublic());
            byte[] jslB = agreeIn(JSL, bob.getPrivate(), alice.getPublic());
            byte[] bcB = agreeIn(BC, bob.getPrivate(), alice.getPublic());
            Assertions.assertArrayEquals(fipsB, jslB,
                    "trial " + trial + ": partyB secret JSLFIPS vs JSL");
            Assertions.assertArrayEquals(fipsB, bcB,
                    "trial " + trial + ": partyB secret JSLFIPS vs BC");

            // DH symmetry: both parties arrive at the same secret.
            Assertions.assertArrayEquals(fipsA, fipsB,
                    "trial " + trial + ": partyA and partyB must derive the same secret");

            // Padded to the prime length, leading zero or not.
            Assertions.assertEquals(SECRET_LEN, fipsA.length,
                    "trial " + trial + ": secret must be padded to the prime length");
        }
    }


    // -----------------------------------------------------------------
    // Differentiator: the secret must depend on the peer
    // -----------------------------------------------------------------

    /**
     * A different peer public key must yield a different shared secret — proof
     * the agreement actually consumes the peer key rather than returning a
     * fixed or key-independent buffer. The divergence must also hold, and
     * agree, across all three providers.
     */
    @Test
    public void differentPeerYieldsDifferentSecret() throws Exception
    {
        SecureRandom sr = seededRandom("differentPeerYieldsDifferentSecret");

        for (int trial = 0; trial < TRIALS; trial++)
        {
            KeyPair alice = fipsKeyPair(sr);
            KeyPair bob = fipsKeyPair(sr);
            KeyPair carol = fipsKeyPair(sr);

            byte[] ab = agreeIn(FIPS, alice.getPrivate(), bob.getPublic());
            byte[] ac = agreeIn(FIPS, alice.getPrivate(), carol.getPublic());
            Assertions.assertFalse(Arrays.areEqual(ab, ac),
                    "trial " + trial + ": different peer public keys must yield different secrets");

            // The alice+bob secret is the same one JSL and BC compute.
            Assertions.assertArrayEquals(ab, agreeIn(JSL, alice.getPrivate(), bob.getPublic()),
                    "trial " + trial + ": alice+bob JSLFIPS vs JSL");
            Assertions.assertArrayEquals(ab, agreeIn(BC, alice.getPrivate(), bob.getPublic()),
                    "trial " + trial + ": alice+bob JSLFIPS vs BC");
        }
    }


    // -----------------------------------------------------------------
    // DHwithRFC2631KDF (X9.42 KDF) cross-provider KEK agreement
    // -----------------------------------------------------------------

    /**
     * The registered DHWITHRFC2631KDF KeyAgreement variant (DH secret fed
     * through the RFC 2631 / X9.42 KDF to derive a wrapping KEK) must derive a
     * byte-identical KEK across JSLFIPS, JSL, and BC — for every AES-wrap target
     * length and both the no-UKM and random-UKM cases. A different UKM is the
     * differentiator.
     */
    @Test
    public void rfc2631KdfAgreesAcrossProviders() throws Exception
    {
        SecureRandom sr = seededRandom("rfc2631KdfAgreesAcrossProviders");

        for (int trial = 0; trial < TRIALS; trial++)
        {
            KeyPair alice = fipsKeyPair(sr);
            KeyPair bob = fipsKeyPair(sr);

            byte[] ukm = null;
            if (trial % 2 == 1)
            {
                ukm = new byte[8 + sr.nextInt(40)];
                sr.nextBytes(ukm);
            }

            for (String wrapOid : WRAP_OIDS)
            {
                String tag = "DHWITHRFC2631KDF wrap=" + wrapOid
                        + " ukm=" + (ukm == null ? "none" : Integer.toString(ukm.length))
                        + " trial=" + trial;

                byte[] kekFips = deriveKdf(FIPS, alice.getPrivate(), bob.getPublic(), ukm, wrapOid);
                byte[] kekJsl = deriveKdf(JSL, alice.getPrivate(), bob.getPublic(), ukm, wrapOid);
                byte[] kekBc = deriveKdf(BC, alice.getPrivate(), bob.getPublic(), ukm, wrapOid);

                Assertions.assertArrayEquals(kekFips, kekJsl, tag + ": KEK JSLFIPS vs JSL");
                Assertions.assertArrayEquals(kekFips, kekBc, tag + ": KEK JSLFIPS vs BC");

                // Differentiator: a different UKM must change the derived KEK.
                byte[] otherUkm = new byte[16];
                sr.nextBytes(otherUkm);
                byte[] kekOther = deriveKdf(FIPS, alice.getPrivate(), bob.getPublic(), otherUkm, wrapOid);
                Assertions.assertFalse(Arrays.areEqual(kekFips, kekOther),
                        tag + ": distinct UKM produced an identical KEK");
            }
        }
    }


    // -----------------------------------------------------------------
    // Key-encoding round-trip through BC's KeyFactory (both directions)
    // -----------------------------------------------------------------

    /**
     * Every DH key JSLFIPS emits must decode through BC's KeyFactory, and every
     * DH key BC emits (on the same ffdhe2048 group) must decode through
     * JSLFIPS's KeyFactory — for BOTH the public and the private half. Proven
     * functionally: the decoded keys must derive the same shared secret the
     * origin provider derives. Both directions of the agreement (privA+pubB and
     * privB+pubA) are exercised, so each of the four key objects round-trips.
     */
    @Test
    public void keyEncodingRoundTripsThroughBC() throws Exception
    {
        SecureRandom sr = seededRandom("keyEncodingRoundTripsThroughBC");
        DHParameterSpec params = ffdhe2048Spec(sr);

        // Direction 1: JSLFIPS generates; BC decodes both halves (via agreeIn)
        // and must reproduce the JSLFIPS secret in both agreement directions.
        KeyPair alice = fipsKeyPair(sr);
        KeyPair bob = fipsKeyPair(sr);

        byte[] fipsFwd = agreeIn(FIPS, alice.getPrivate(), bob.getPublic());
        byte[] bcFwd = agreeIn(BC, alice.getPrivate(), bob.getPublic());
        Assertions.assertArrayEquals(fipsFwd, bcFwd,
                "BC must decode JSLFIPS alice.private + bob.public and derive the same secret");

        byte[] fipsRev = agreeIn(FIPS, bob.getPrivate(), alice.getPublic());
        byte[] bcRev = agreeIn(BC, bob.getPrivate(), alice.getPublic());
        Assertions.assertArrayEquals(fipsRev, bcRev,
                "BC must decode JSLFIPS bob.private + alice.public and derive the same secret");

        // Direction 2: BC generates on the SAME ffdhe2048 group; JSLFIPS decodes
        // both halves (via agreeIn) and must reproduce the BC secret.
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("DH", BC);
        bcKpg.initialize(new DHParameterSpec(params.getP(), params.getG()), sr);
        KeyPair bcAlice = bcKpg.generateKeyPair();
        KeyPair bcBob = bcKpg.generateKeyPair();

        byte[] bc2Fwd = agreeIn(BC, bcAlice.getPrivate(), bcBob.getPublic());
        byte[] fips2Fwd = agreeIn(FIPS, bcAlice.getPrivate(), bcBob.getPublic());
        Assertions.assertArrayEquals(bc2Fwd, fips2Fwd,
                "JSLFIPS must decode BC alice.private + bob.public and derive the same secret");

        byte[] bc2Rev = agreeIn(BC, bcBob.getPrivate(), bcAlice.getPublic());
        byte[] fips2Rev = agreeIn(FIPS, bcBob.getPrivate(), bcAlice.getPublic());
        Assertions.assertArrayEquals(bc2Rev, fips2Rev,
                "JSLFIPS must decode BC bob.private + alice.public and derive the same secret");
    }
}
