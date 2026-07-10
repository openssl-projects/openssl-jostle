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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Cross-provider agreement for the FIPS provider's DSA signature surface.
 * <p>
 * This is the DSA analogue of {@code FIPSAESAgreementTest} and the DSA
 * portion of {@code FIPSDSADHTest}, exercising every SHA-2 DSA transformation
 * three ways in the same JVM:
 * <ol>
 *   <li>JSLFIPS vs the non-FIPS Jostle provider (JSL), and</li>
 *   <li>JSLFIPS vs BouncyCastle (BC),</li>
 * </ol>
 * and in <b>both directions</b> for each reference: JSLFIPS signs and the
 * reference verifies, AND the reference signs and JSLFIPS verifies. DSA
 * signatures are randomised (a fresh per-signature nonce {@code k}), so the
 * signature bytes cannot be compared for equality the way a deterministic
 * cipher's ciphertext can; cross-verification against an independent
 * implementation is the equivalent differentiator — a stubbed or
 * wrong-but-self-consistent signer/verifier cannot satisfy an external
 * reference. Each trial also proves the negative path: a signature over a
 * message with one byte flipped must fail verification.
 * <p>
 * <b>FIPS domain parameters.</b> The 3.1.2 FIPS module requires FIPS 186-4
 * domain parameters (L=2048, N=256); the legacy 1024/160 pairing is rejected
 * by the module. Domain-parameter generation is a multi-second prime search,
 * so a single 2048/256 keypair is generated once (via JSLFIPS) and reused
 * across every trial and test.
 * <p>
 * <b>Key isolation.</b> JSLFIPS and JSL <em>private</em> keys are bound to the
 * interface library / {@code OSSL_LIB_CTX} that created them and are rejected
 * by the other Jostle provider's operational SPIs; <em>public</em> keys cross
 * freely. To drive the SAME key material through all three providers the
 * shared keypair is encoded once (X.509 public, PKCS#8 private) and decoded
 * through each provider's own {@code KeyFactory} — the sanctioned cross route
 * (see {@code FIPSKeyIsolationTest}). That decode is itself an encoding
 * round-trip, exercised explicitly for BC in both directions.
 * <p>
 * Inputs (message content and length) are drawn from a per-test SHA1PRNG whose
 * seed is logged, so a flaky run is reproducible (per CLAUDE.md).
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSDSAAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** SHA-2 DSA transformations registered by both Jostle providers and BC. */
    private static final String[] SHA2_DSA = {
            "SHA224withDSA", "SHA256withDSA", "SHA384withDSA", "SHA512withDSA"
    };

    /**
     * SHA-3 DSA transformations registered by {@code ProvFIPSDSA} and BC.
     * Kept in a separate array from {@link #SHA2_DSA} so that a module which
     * did NOT approve a SHA3-withDSA digest can be handled distinctly (see
     * {@link #sha3DsaSignaturesAgreeWithBc()}). The 3.1.2 FIPS module DOES
     * approve these: its {@code dsa_setup_md} gates on
     * {@code ossl_digest_get_approved_nid}, whose table
     * ({@code providers/common/digest_to_nid.c}) lists SHA3-224/256/384/512
     * (FIPS 202) alongside the SHA-2 family.
     */
    private static final String[] SHA3_DSA = {
            "SHA3-224withDSA", "SHA3-256withDSA", "SHA3-384withDSA", "SHA3-512withDSA"
    };

    private static final int TRIALS = 8;

    private static final SecureRandom RANDOM = new SecureRandom();

    // Shared 2048/256 keypair, generated once (via JSLFIPS) and encoded. The
    // domain-parameter search is expensive; every test reuses these bytes.
    private static volatile byte[] pubEnc;
    private static volatile byte[] privEnc;

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
     * Generate the shared 2048/256 (FIPS 186-4) DSA keypair once via JSLFIPS
     * and cache its X.509 / PKCS#8 encodings. Callers must have run
     * {@link #ensureProviders()} first so the FIPS provider is registered.
     */
    private static synchronized void ensureSharedKeyPair() throws Exception
    {
        if (pubEnc != null)
        {
            return;
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", FIPS);
        kpg.initialize(2048); // FIPS 186-4: L=2048 forces a 256-bit q (N=256).
        KeyPair kp = kpg.generateKeyPair();
        pubEnc = kp.getPublic().getEncoded();
        privEnc = kp.getPrivate().getEncoded();
    }

    private static final class ProviderKeys
    {
        final PublicKey pub;
        final PrivateKey priv;

        ProviderKeys(PublicKey pub, PrivateKey priv)
        {
            this.pub = pub;
            this.priv = priv;
        }
    }

    /** Decode the shared keypair through {@code provider}'s own KeyFactory. */
    private static ProviderKeys keysFor(String provider) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("DSA", provider);
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(pubEnc));
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privEnc));
        return new ProviderKeys(pub, priv);
    }

    private static byte[] randomMessage(SecureRandom sr)
    {
        // At least one byte so the tamper differentiator always has a byte to
        // flip; length varied per trial to exercise the digest's buffering.
        byte[] msg = new byte[1 + sr.nextInt(512)];
        sr.nextBytes(msg);
        return msg;
    }

    private static byte[] sign(String sigAlg, String provider, PrivateKey key, byte[] msg) throws Exception
    {
        Signature s = Signature.getInstance(sigAlg, provider);
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    private static boolean verify(String sigAlg, String provider, PublicKey key, byte[] msg, byte[] sig)
            throws Exception
    {
        Signature s = Signature.getInstance(sigAlg, provider);
        s.initVerify(key);
        s.update(msg);
        return s.verify(sig);
    }

    /**
     * For one signature transformation and one reference provider: JSLFIPS
     * signs and the reference verifies, the reference signs and JSLFIPS
     * verifies, and both signatures fail against a tampered message.
     */
    private void crossVerify(String sigAlg, String ref, SecureRandom sr) throws Exception
    {
        ProviderKeys fips = keysFor(FIPS);
        ProviderKeys refKeys = keysFor(ref);

        for (int trial = 0; trial < TRIALS; trial++)
        {
            byte[] msg = randomMessage(sr);
            String tag = sigAlg + " ref=" + ref + " trial=" + trial + " len=" + msg.length;

            // DSA is randomised: cross-verify rather than compare bytes.
            byte[] sigFips = sign(sigAlg, FIPS, fips.priv, msg);
            Assertions.assertTrue(verify(sigAlg, ref, refKeys.pub, msg, sigFips),
                    tag + ": JSLFIPS sign -> " + ref + " verify");

            byte[] sigRef = sign(sigAlg, ref, refKeys.priv, msg);
            Assertions.assertTrue(verify(sigAlg, FIPS, fips.pub, msg, sigRef),
                    tag + ": " + ref + " sign -> JSLFIPS verify");

            // Negative path: one flipped message byte must break verification
            // on both the JSLFIPS and the reference verifier.
            byte[] tampered = msg.clone();
            tampered[sr.nextInt(tampered.length)] ^= 0x01;
            Assertions.assertFalse(verify(sigAlg, FIPS, fips.pub, tampered, sigFips),
                    tag + ": tampered message must not verify (JSLFIPS)");
            Assertions.assertFalse(verify(sigAlg, ref, refKeys.pub, tampered, sigRef),
                    tag + ": tampered message must not verify (" + ref + ")");
        }
    }

    @Test
    public void dsaSignaturesAgreeWithJslAndBc() throws Exception
    {
        ensureProviders();
        ensureSharedKeyPair();
        SecureRandom sr = seededRandom("dsaSignaturesAgreeWithJslAndBc");

        for (String ref : new String[]{JSL, BC})
        {
            for (String sigAlg : SHA2_DSA)
            {
                crossVerify(sigAlg, ref, sr);
            }
        }
    }

    /**
     * SHA3-224/256/384/512withDSA are registered by {@code ProvFIPSDSA} but are
     * excluded from {@link #SHA2_DSA}, so the primary agreement test never
     * exercises them. This locks each SHA-3 DSA transformation against BC in
     * both directions (JSLFIPS signs / BC verifies and BC signs / JSLFIPS
     * verifies), with a tampered-message differentiator per trial.
     * <p>
     * If a future FIPS module ever declined a SHA3-withDSA digest for signing,
     * the module surfaces an {@link OpenSSLException} ("digest not allowed") the
     * same way it gates SHA-1 signing (see {@code FIPSSha1SignatureGateTest}).
     * That refusal is locked distinctly rather than being allowed to fail the
     * round-trip opaquely — either the digest is approved and cross-verifies, or
     * it is refused with the module's "digest not allowed" error.
     */
    @Test
    public void sha3DsaSignaturesAgreeWithBc() throws Exception
    {
        ensureProviders();
        ensureSharedKeyPair();
        SecureRandom sr = seededRandom("sha3DsaSignaturesAgreeWithBc");

        for (String sigAlg : SHA3_DSA)
        {
            try
            {
                crossVerify(sigAlg, BC, sr);
            }
            catch (OpenSSLException ex)
            {
                // Distinct lock: a module that does not approve this SHA-3
                // digest for DSA signing must refuse it explicitly, not
                // silently produce a wrong signature.
                Assertions.assertTrue(String.valueOf(ex.getMessage()).contains("digest not allowed"),
                        sigAlg + ": expected a module 'digest not allowed' refusal, got: " + ex.getMessage());
            }
        }
    }

    /**
     * The shared DSA key round-trips through BouncyCastle's KeyFactory in both
     * directions and stays operational: JSLFIPS-encoded keys decode in BC and
     * interoperate, and BC's re-encoded key objects decode back into JSLFIPS.
     */
    @Test
    public void keyEncodingRoundTripsThroughBC() throws Exception
    {
        ensureProviders();
        ensureSharedKeyPair();
        SecureRandom sr = seededRandom("keyEncodingRoundTripsThroughBC");
        byte[] msg = randomMessage(sr);

        KeyFactory fipsKf = KeyFactory.getInstance("DSA", FIPS);
        KeyFactory bcKf = KeyFactory.getInstance("DSA", BC);

        PublicKey fipsPub = fipsKf.generatePublic(new X509EncodedKeySpec(pubEnc));
        PrivateKey fipsPriv = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(privEnc));

        // Direction 1: JSLFIPS-encoded key -> BC KeyFactory -> interoperates.
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(pubEnc));
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(privEnc));

        byte[] sigFips = sign("SHA256withDSA", FIPS, fipsPriv, msg);
        Assertions.assertTrue(verify("SHA256withDSA", BC, bcPub, msg, sigFips),
                "JSLFIPS-encoded public key, decoded by BC, verifies a JSLFIPS signature");

        byte[] sigBc = sign("SHA256withDSA", BC, bcPriv, msg);
        Assertions.assertTrue(verify("SHA256withDSA", FIPS, fipsPub, msg, sigBc),
                "BC signature over the JSLFIPS-encoded private key verifies in JSLFIPS");

        // Direction 2: BC's key objects re-encoded -> JSLFIPS KeyFactory.
        PublicKey fipsPubFromBc = fipsKf.generatePublic(new X509EncodedKeySpec(bcPub.getEncoded()));
        PrivateKey fipsPrivFromBc = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(bcPriv.getEncoded()));

        byte[] sig2 = sign("SHA256withDSA", FIPS, fipsPrivFromBc, msg);
        Assertions.assertTrue(verify("SHA256withDSA", BC, bcPub, msg, sig2),
                "BC-encoded private key, decoded by JSLFIPS, produces a BC-verifiable signature");
        Assertions.assertTrue(verify("SHA256withDSA", FIPS, fipsPubFromBc, msg, sig2),
                "BC-encoded public key, decoded by JSLFIPS, verifies the signature");

        // Negative path on the round-tripped keys.
        byte[] tampered = msg.clone();
        tampered[sr.nextInt(tampered.length)] ^= 0x01;
        Assertions.assertFalse(verify("SHA256withDSA", BC, bcPub, tampered, sig2),
                "tampered message must not verify against the round-tripped key");
    }
}
