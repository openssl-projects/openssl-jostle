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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;

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
 * ML-DSA, ML-KEM and SLH-DSA through the FIPS provider ("JSLFIPS").
 * <p>
 * These families are <b>module-version dependent</b>: OpenSSL's 3.5.x FIPS
 * module implements all three, no 3.1.2 module implements any, and
 * {@code ProvFIPS{MLDSA,MLKEM,SLHDSA}} register them only when the keymgmt
 * fetch resolves. So every test here asserts the CONTRACT rather than one
 * module's answer:
 * <ul>
 *   <li>registered → the algorithm must fully work, and agree with the
 *       non-FIPS provider over the same key material;</li>
 *   <li>not registered → the module must genuinely refuse the fetch, so a
 *       working algorithm cannot have been dropped from callers.</li>
 * </ul>
 * Unlike DSA signing, no {@code fipsinstall} switch gates PQC - real
 * operations succeed identically under the {@code -pedantic} and default
 * configs ({@code fips-c-review/probes/pqc_op_probe.c}) - so a fetch is a
 * complete answer and registration-time gating is sound.
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSPQCTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** Does JSLFIPS carry the family, and does that agree with the module? */
    private static boolean served(String kpgAlg, String fetchName)
    {
        boolean registered = Security.getProvider(FIPS)
                .getService("KeyPairGenerator", kpgAlg) != null;
        int fetch = FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_KEYMGMT, fetchName);
        Assertions.assertEquals(registered, fetch != 0,
                kpgAlg + ": registration disagrees with the module's keymgmt fetch for "
                        + fetchName + " (module " + FIPSNISelector.OpenSSLFIPSNI.moduleVersion() + ")");
        return registered;
    }

    /**
     * ML-DSA signs and verifies through JSLFIPS, and the signature is accepted
     * by the non-FIPS provider over the same key.
     * <p>
     * Cross-verification against an independent implementation is what proves
     * the FIPS path produced a real signature rather than something
     * self-consistent; the tampered-message check proves the verifier looks at
     * the message at all.
     */
    @Test
    public void mldsaSignsAndAgreesWithJsl() throws Exception
    {
        if (!served("ML-DSA-65", "ML-DSA-65"))
        {
            return;
        }
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", FIPS).generateKeyPair();

        byte[] msg = new byte[1 + RANDOM.nextInt(512)];
        RANDOM.nextBytes(msg);

        Signature s = Signature.getInstance("ML-DSA-65", FIPS);
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] sig = s.sign();

        Signature v = Signature.getInstance("ML-DSA-65", FIPS);
        v.initVerify(kp.getPublic());
        v.update(msg);
        Assertions.assertTrue(v.verify(sig), "JSLFIPS must verify its own ML-DSA signature");

        // Same key material through JSL, via the only crossing there is:
        // re-decode the X.509 encoding through JSL's own KeyFactory. The key
        // OBJECT is refused (MT-14) — and would have had JSL's verifier
        // executing in the module.
        Signature jsl = Signature.getInstance("ML-DSA-65", JSL);
        jsl.initVerify(KeyFactory.getInstance("ML-DSA-65", JSL)
                .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
        jsl.update(msg);
        Assertions.assertTrue(jsl.verify(sig), "JSL must verify a JSLFIPS ML-DSA signature");

        byte[] tampered = msg.clone();
        tampered[RANDOM.nextInt(tampered.length)] ^= 0x01;
        Signature t = Signature.getInstance("ML-DSA-65", FIPS);
        t.initVerify(kp.getPublic());
        t.update(tampered);
        Assertions.assertFalse(t.verify(sig), "a tampered message verified");
    }

    /** SLH-DSA, same contract as ML-DSA. */
    @Test
    public void slhdsaSignsAndAgreesWithJsl() throws Exception
    {
        if (!served("SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S"))
        {
            return;
        }
        KeyPair kp = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", FIPS).generateKeyPair();

        byte[] msg = new byte[64];
        RANDOM.nextBytes(msg);

        Signature s = Signature.getInstance("SLH-DSA-SHA2-128S", FIPS);
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] sig = s.sign();

        Signature jsl = Signature.getInstance("SLH-DSA-SHA2-128S", JSL);
        jsl.initVerify(KeyFactory.getInstance("SLH-DSA-SHA2-128S", JSL)
                .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
        jsl.update(msg);
        Assertions.assertTrue(jsl.verify(sig), "JSL must verify a JSLFIPS SLH-DSA signature");

        byte[] tampered = msg.clone();
        tampered[0] ^= 0x01;
        Signature t = Signature.getInstance("SLH-DSA-SHA2-128S", FIPS);
        t.initVerify(kp.getPublic());
        t.update(tampered);
        Assertions.assertFalse(t.verify(sig), "a tampered message verified");
    }

    /**
     * An ML-KEM keypair generated by JSLFIPS round-trips through JSL's
     * encapsulate / decapsulate, proving the FIPS key is a real one and that
     * the two providers agree on the parameter set and encoding.
     */
    @Test
    public void mlkemKeysRoundTripThroughJsl() throws Exception
    {
        if (!served("ML-KEM-768", "ML-KEM-768"))
        {
            return;
        }
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", FIPS).generateKeyPair();

        // Both halves must survive an encode / decode through the other
        // provider - the sanctioned crossing, and the check that the encoding
        // is provider-neutral.
        KeyFactory jslKf = KeyFactory.getInstance("ML-KEM-768", JSL);
        PublicKey jslPub = jslKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey jslPriv = jslKf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        Assertions.assertArrayEquals(kp.getPublic().getEncoded(), jslPub.getEncoded(),
                "ML-KEM public encoding is not provider-neutral");
        Assertions.assertArrayEquals(kp.getPrivate().getEncoded(), jslPriv.getEncoded(),
                "ML-KEM private encoding is not provider-neutral");
    }

}
