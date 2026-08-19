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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cross-provider agreement for the FIPS provider's RSA surface.
 * <p>
 * The RSA analogue of {@code FIPSAESAgreementTest}: every approved RSA
 * transformation is exercised in the same JVM against BOTH the non-FIPS
 * provider (JSL) AND BouncyCastle (BC), in BOTH directions (JSLFIPS produces,
 * the reference consumes, and vice versa).
 * <p>
 * <b>Key isolation.</b> JSLFIPS and JSL PRIVATE keys are bound to the
 * interface library that created them; an operational SPI rejects a private
 * key minted by the other Jostle provider with {@code InvalidKeyException}
 * (see {@code FIPSKeyIsolationTest}). Public keys cross freely. To run the
 * SAME key material through all three providers, this test generates one
 * 2048-bit keypair in the module, encodes both halves (X.509 / PKCS#8), and
 * decodes them into EACH provider's {@code KeyFactory} — the sanctioned route.
 * <p>
 * <b>Determinism vs randomisation.</b>
 * <ul>
 *   <li>PKCS#1 v1.5 signatures are deterministic: JSLFIPS, JSL and BC must
 *       emit byte-identical signatures for the same imported key + message,
 *       and each provider must verify the others'.</li>
 *   <li>PSS signatures, OAEP encryption and PKCS#1 v1.5 encryption are
 *       randomised: cross-verify / cross-decrypt both directions, and prove
 *       the randomisation (two outputs of the same input differ).</li>
 * </ul>
 * Explicit {@link PSSParameterSpec} / {@link OAEPParameterSpec} are pinned on
 * every call — Jostle's default OAEP/PSS digest is SHA-256 while BC's is
 * SHA-1, so cross-provider agreement requires the spec.
 * <p>
 * RSA generation is 2048-bit (the FIPS module floor). Inputs (message content
 * and length) come from a per-test SHA1PRNG whose seed is logged, so a flaky
 * run is reproducible; keys are freshly generated per trial from the module.
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSRSAAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    // Every provider the same key material is decoded into.
    private static final String[] PROVIDERS = {FIPS, JSL, BC};
    // References JSLFIPS is compared against, both directions.
    private static final String[] REFERENCES = {JSL, BC};

    private static final int KEY_SIZE_BITS = 2048;

    // Number of independent keypairs per @Test.
    private static final int TRIALS = 5;

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

    // ----- parameter-spec factories (fresh instance per use) ----------------

    private static PSSParameterSpec pssSpec()
    {
        // SHA-256 / MGF1-SHA-256 / 32-byte salt / trailer 1 — pinned so all
        // three providers agree (BC's PSS default digest is SHA-1).
        return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    }

    private static OAEPParameterSpec oaepSpec()
    {
        // SHA-256 for OAEP hash and MGF1 hash, empty label — pinned so all
        // three providers agree (BC's OAEP default digest is SHA-1).
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    /**
     * OAEP is registered on the bare {@code "RSA"} transformation in both
     * Jostle providers; BC exposes it under the explicit padding name.
     */
    private static String oaepXform(String provider)
    {
        if (BC.equals(provider))
        {
            return "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        }
        return "RSA";
    }

    // ----- key material shared across providers -----------------------------

    /**
     * Public/private key objects, per provider, all decoded from the SAME
     * module-generated keypair.
     */
    private static final class SharedKeys
    {
        final Map<String, PublicKey> pub = new LinkedHashMap<>();
        final Map<String, PrivateKey> priv = new LinkedHashMap<>();
    }

    private static KeyPair generateFipsKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", FIPS);
        kpg.initialize(KEY_SIZE_BITS);
        return kpg.generateKeyPair();
    }

    /**
     * Generate one 2048-bit keypair in the module and decode both halves into
     * every provider's KeyFactory. This is the ONLY sanctioned way to operate
     * the same private key across JSLFIPS and JSL (private keys are otherwise
     * isolated); public keys would cross without re-decoding, but decoding
     * uniformly keeps the matrix symmetric.
     */
    private static SharedKeys freshSharedKeys() throws Exception
    {
        KeyPair kp = generateFipsKeyPair();
        byte[] pubEnc = kp.getPublic().getEncoded();
        byte[] privEnc = kp.getPrivate().getEncoded();

        SharedKeys keys = new SharedKeys();
        for (String provider : PROVIDERS)
        {
            KeyFactory kf = KeyFactory.getInstance("RSA", provider);
            keys.pub.put(provider, kf.generatePublic(new X509EncodedKeySpec(pubEnc)));
            keys.priv.put(provider, kf.generatePrivate(new PKCS8EncodedKeySpec(privEnc)));
        }
        return keys;
    }

    // ----- operation helpers ------------------------------------------------

    private static byte[] rsaSign(String provider, String alg, PrivateKey priv,
                                  AlgorithmParameterSpec spec, byte[] msg) throws Exception
    {
        Signature s = Signature.getInstance(alg, provider);
        if (spec != null)
        {
            s.setParameter(spec);
        }
        s.initSign(priv);
        s.update(msg);
        return s.sign();
    }

    private static boolean rsaVerify(String provider, String alg, PublicKey pub,
                                     AlgorithmParameterSpec spec, byte[] msg, byte[] sig) throws Exception
    {
        Signature s = Signature.getInstance(alg, provider);
        if (spec != null)
        {
            s.setParameter(spec);
        }
        s.initVerify(pub);
        s.update(msg);
        return s.verify(sig);
    }

    private static byte[] rsaEncrypt(String provider, String xform, PublicKey pub,
                                     AlgorithmParameterSpec spec, byte[] msg) throws Exception
    {
        Cipher c = Cipher.getInstance(xform, provider);
        if (spec != null)
        {
            c.init(Cipher.ENCRYPT_MODE, pub, spec);
        }
        else
        {
            c.init(Cipher.ENCRYPT_MODE, pub);
        }
        return c.doFinal(msg);
    }

    private static byte[] rsaDecrypt(String provider, String xform, PrivateKey priv,
                                     AlgorithmParameterSpec spec, byte[] ct) throws Exception
    {
        Cipher c = Cipher.getInstance(xform, provider);
        if (spec != null)
        {
            c.init(Cipher.DECRYPT_MODE, priv, spec);
        }
        else
        {
            c.init(Cipher.DECRYPT_MODE, priv);
        }
        return c.doFinal(ct);
    }

    // ----- tests ------------------------------------------------------------

    /**
     * PKCS#1 v1.5 signatures are deterministic: for the same imported private
     * key + message, JSLFIPS, JSL and BC must produce byte-identical
     * signatures, and every provider must verify every other provider's
     * signature. A tampered message must fail to verify.
     */
    @Test
    public void pkcs1SignaturesAreDeterministicAndAgree() throws Exception
    {
        SecureRandom sr = seededRandom("pkcs1SignaturesAreDeterministicAndAgree");

        String[] digests = {"SHA256withRSA", "SHA512withRSA"};

        for (int trial = 0; trial < TRIALS; trial++)
        {
            SharedKeys keys = freshSharedKeys();
            byte[] msg = new byte[1 + sr.nextInt(1024)];
            sr.nextBytes(msg);

            for (String alg : digests)
            {
                String tag = alg + " trial=" + trial;

                // Each provider signs the same key + message.
                Map<String, byte[]> sigs = new LinkedHashMap<>();
                for (String provider : PROVIDERS)
                {
                    sigs.put(provider, rsaSign(provider, alg, keys.priv.get(provider), null, msg));
                }

                // Deterministic: all three signatures are byte-identical.
                for (String provider : PROVIDERS)
                {
                    Assertions.assertArrayEquals(sigs.get(FIPS), sigs.get(provider),
                            tag + ": " + provider + " signature must equal JSLFIPS (PKCS#1 v1.5 is deterministic)");
                }

                // Full cross-verify: every provider verifies every signature.
                for (String signer : PROVIDERS)
                {
                    for (String verifier : PROVIDERS)
                    {
                        Assertions.assertTrue(
                                rsaVerify(verifier, alg, keys.pub.get(verifier), null, msg, sigs.get(signer)),
                                tag + ": " + signer + " sign -> " + verifier + " verify");
                    }
                }

                // Negative: a single flipped message byte must not verify.
                byte[] tampered = Arrays.clone(msg);
                tampered[sr.nextInt(tampered.length)] ^= 0x01;
                Assertions.assertFalse(
                        rsaVerify(FIPS, alg, keys.pub.get(FIPS), null, tampered, sigs.get(FIPS)),
                        tag + ": tampered message must not verify");
            }
        }
    }

    /**
     * PSS signatures are randomised: cross-verify both directions against each
     * reference with an explicit PSSParameterSpec, prove the salt randomises
     * (two signatures of the same message differ), and prove a tampered
     * message fails.
     */
    @Test
    public void pssSignaturesCrossVerify() throws Exception
    {
        SecureRandom sr = seededRandom("pssSignaturesCrossVerify");

        final String alg = "RSASSA-PSS";

        for (int trial = 0; trial < TRIALS; trial++)
        {
            SharedKeys keys = freshSharedKeys();
            byte[] msg = new byte[1 + sr.nextInt(1024)];
            sr.nextBytes(msg);

            for (String ref : REFERENCES)
            {
                String tag = "PSS trial=" + trial + " ref=" + ref;

                // JSLFIPS sign -> reference verify.
                byte[] fipsSig = rsaSign(FIPS, alg, keys.priv.get(FIPS), pssSpec(), msg);
                Assertions.assertTrue(rsaVerify(ref, alg, keys.pub.get(ref), pssSpec(), msg, fipsSig),
                        tag + ": JSLFIPS sign -> " + ref + " verify");

                // Reference sign -> JSLFIPS verify.
                byte[] refSig = rsaSign(ref, alg, keys.priv.get(ref), pssSpec(), msg);
                Assertions.assertTrue(rsaVerify(FIPS, alg, keys.pub.get(FIPS), pssSpec(), msg, refSig),
                        tag + ": " + ref + " sign -> JSLFIPS verify");
            }

            // Randomisation: two JSLFIPS signatures of the same message differ.
            byte[] a = rsaSign(FIPS, alg, keys.priv.get(FIPS), pssSpec(), msg);
            byte[] b = rsaSign(FIPS, alg, keys.priv.get(FIPS), pssSpec(), msg);
            Assertions.assertFalse(Arrays.areEqual(a, b),
                    "PSS trial=" + trial + ": salt must randomise (two signatures identical)");

            // Negative: tampered message must not verify.
            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= 0x01;
            Assertions.assertFalse(rsaVerify(FIPS, alg, keys.pub.get(FIPS), pssSpec(), tampered, a),
                    "PSS trial=" + trial + ": tampered message must not verify");
        }
    }

    /**
     * OAEP encryption is randomised: cross-decrypt both directions against
     * each reference with an explicit OAEPParameterSpec, prove randomisation
     * (two ciphertexts of the same plaintext differ), and prove a tampered
     * ciphertext is rejected with BadPaddingException.
     */
    @Test
    public void oaepEncryptionCrossDecrypts() throws Exception
    {
        SecureRandom sr = seededRandom("oaepEncryptionCrossDecrypts");

        for (int trial = 0; trial < TRIALS; trial++)
        {
            SharedKeys keys = freshSharedKeys();
            // OAEP-SHA256 max plaintext for a 2048-bit key = 256 - 2*32 - 2 = 190.
            byte[] msg = new byte[1 + sr.nextInt(180)];
            sr.nextBytes(msg);

            for (String ref : REFERENCES)
            {
                String tag = "OAEP trial=" + trial + " ref=" + ref;

                // JSLFIPS encrypt -> reference decrypt.
                byte[] ctFips = rsaEncrypt(FIPS, oaepXform(FIPS), keys.pub.get(FIPS), oaepSpec(), msg);
                Assertions.assertArrayEquals(msg,
                        rsaDecrypt(ref, oaepXform(ref), keys.priv.get(ref), oaepSpec(), ctFips),
                        tag + ": JSLFIPS encrypt -> " + ref + " decrypt");

                // Reference encrypt -> JSLFIPS decrypt.
                byte[] ctRef = rsaEncrypt(ref, oaepXform(ref), keys.pub.get(ref), oaepSpec(), msg);
                Assertions.assertArrayEquals(msg,
                        rsaDecrypt(FIPS, oaepXform(FIPS), keys.priv.get(FIPS), oaepSpec(), ctRef),
                        tag + ": " + ref + " encrypt -> JSLFIPS decrypt");
            }

            // Randomisation: two JSLFIPS ciphertexts of the same plaintext differ.
            byte[] c1 = rsaEncrypt(FIPS, "RSA", keys.pub.get(FIPS), oaepSpec(), msg);
            byte[] c2 = rsaEncrypt(FIPS, "RSA", keys.pub.get(FIPS), oaepSpec(), msg);
            Assertions.assertFalse(Arrays.areEqual(c1, c2),
                    "OAEP trial=" + trial + ": seed must randomise (two ciphertexts identical)");

            // Negative: a tampered ciphertext must be rejected. OAEP is
            // IND-CCA2 by construction, so any decode failure maps to
            // BadPaddingException at the JCE surface.
            byte[] tampered = Arrays.clone(c1);
            tampered[tampered.length / 2] ^= 0x01;
            Assertions.assertThrows(BadPaddingException.class,
                    () -> rsaDecrypt(FIPS, "RSA", keys.priv.get(FIPS), oaepSpec(), tampered),
                    "OAEP trial=" + trial + ": tampered ciphertext must be rejected");
        }
    }

    /**
     * Key-encoding round-trip between JSLFIPS and BC, both halves and both
     * directions: a key generated by one provider, encoded and decoded through
     * the other's KeyFactory, signs and verifies correctly. This proves the
     * X.509 / PKCS#8 encodings interoperate (correct OID and parameters) — not
     * just that internal Jostle round-trips work.
     */
    @Test
    public void keyEncodingRoundTripsBetweenFipsAndBc() throws Exception
    {
        SecureRandom sr = seededRandom("keyEncodingRoundTripsBetweenFipsAndBc");

        byte[] msg = new byte[1 + sr.nextInt(512)];
        sr.nextBytes(msg);

        // --- Direction 1: JSLFIPS-generated key operated through BC ---------
        KeyPair fipsKp = generateFipsKeyPair();
        KeyFactory bcKf = KeyFactory.getInstance("RSA", BC);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(fipsKp.getPublic().getEncoded()));
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(fipsKp.getPrivate().getEncoded()));

        // BC-decoded private half signs; both the BC-decoded public half and
        // the original JSLFIPS public half verify.
        byte[] sig1 = rsaSign(BC, "SHA256withRSA", bcPriv, null, msg);
        Assertions.assertTrue(rsaVerify(BC, "SHA256withRSA", bcPub, null, msg, sig1),
                "BC-decoded public half verifies BC-decoded private half's signature");
        Assertions.assertTrue(rsaVerify(FIPS, "SHA256withRSA", fipsKp.getPublic(), null, msg, sig1),
                "original JSLFIPS public half verifies the BC-decoded private half's signature");

        // --- Direction 2: BC-generated key operated through JSLFIPS ---------
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BC);
        bcKpg.initialize(KEY_SIZE_BITS);
        KeyPair bcKp = bcKpg.generateKeyPair();
        KeyFactory fipsKf = KeyFactory.getInstance("RSA", FIPS);
        PublicKey fipsPub = fipsKf.generatePublic(new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));
        PrivateKey fipsPriv = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(bcKp.getPrivate().getEncoded()));

        byte[] sig2 = rsaSign(FIPS, "SHA256withRSA", fipsPriv, null, msg);
        Assertions.assertTrue(rsaVerify(FIPS, "SHA256withRSA", fipsPub, null, msg, sig2),
                "JSLFIPS-decoded public half verifies JSLFIPS-decoded private half's signature");
        Assertions.assertTrue(rsaVerify(BC, "SHA256withRSA", bcKp.getPublic(), null, msg, sig2),
                "original BC public half verifies the JSLFIPS-decoded private half's signature");
    }
}
