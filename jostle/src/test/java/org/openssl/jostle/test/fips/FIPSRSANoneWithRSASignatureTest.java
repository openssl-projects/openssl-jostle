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

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

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
 * Behaviour lock for {@code NoneWithRSA} through the FIPS provider ("JSLFIPS").
 * <p>
 * Capability, not approval: the module performs raw PKCS#1 v1.5 signing
 * (measured directly against the OpenSSL FIPS provider: {@code
 * EVP_PKEY_sign_init} + {@code EVP_PKEY_CTX_set_rsa_padding(RSA_PKCS1_PADDING)}
 * with no digest set, then {@code EVP_PKEY_sign}, succeeds and round-trips on
 * both 3.1.2 and 3.5.8), so JSLFIPS serves it — approval is the operator's
 * determination, not this provider's to simulate by feeding a digest name
 * ("NONE") the module was never going to fetch. {@code ProvFIPSRSA} registers
 * {@code NoneWithRSA} through {@code RSASignatureSpi.None} exactly as
 * {@code ProvRSA} does: the raw path, {@code PADDING_PKCS1_NONE}, no digest
 * fetch.
 * <p>
 * (This test used to pin a deliberately-manufactured refusal — registering
 * through the digest-name path with the impossible name "NONE" — as if it
 * were a module limitation. It was not: the module was never asked to do
 * the thing it was said to refuse.)
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSRSANoneWithRSASignatureTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

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

    private static byte[] randomTbs(SecureRandom sr)
    {
        // Well under k - 11 (= 245 for a 2048-bit modulus).
        byte[] tbs = new byte[1 + sr.nextInt(200)];
        sr.nextBytes(tbs);
        return tbs;
    }

    /** JSLFIPS resolves and actually signs/verifies — registration is usable, on both modules. */
    @Test
    public void noneWithRsaSignsAndVerifiesOnTheLoadedModule() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", FIPS).generateKeyPair();
        byte[] tbs = randomTbs(RANDOM);

        Signature signer = Signature.getInstance("NoneWithRSA", FIPS);
        signer.initSign(kp.getPrivate());
        signer.update(tbs);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("NoneWithRSA", FIPS);
        verifier.initVerify(kp.getPublic());
        verifier.update(tbs);
        Assertions.assertTrue(verifier.verify(sig),
                "NoneWithRSA must sign and verify under JSLFIPS (" + FIPSTestUtil.moduleDescription() + ")");
    }

    /**
     * Byte-identical to JSL and to BouncyCastle on the same key and input —
     * PKCS#1 v1.5 signing is deterministic, so this is a direct check that
     * JSLFIPS runs the SAME raw path, not merely "a" working path.
     */
    @Test
    public void noneWithRsaMatchesJslAndBouncyCastleByteForByte() throws Exception
    {
        KeyPair fipsKp = KeyPairGenerator.getInstance("RSA", FIPS).generateKeyPair();
        KeyFactory jslKf = KeyFactory.getInstance("RSA", JSL);
        PrivateKey jslPriv = jslKf.generatePrivate(new PKCS8EncodedKeySpec(fipsKp.getPrivate().getEncoded()));
        PublicKey jslPub = jslKf.generatePublic(new X509EncodedKeySpec(fipsKp.getPublic().getEncoded()));
        KeyFactory bcKf = KeyFactory.getInstance("RSA", BC);
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(fipsKp.getPrivate().getEncoded()));
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(fipsKp.getPublic().getEncoded()));

        byte[] tbs = randomTbs(RANDOM);

        Signature fipsSigner = Signature.getInstance("NoneWithRSA", FIPS);
        fipsSigner.initSign(fipsKp.getPrivate());
        fipsSigner.update(tbs);
        byte[] fipsSig = fipsSigner.sign();

        Signature jslSigner = Signature.getInstance("NoneWithRSA", JSL);
        jslSigner.initSign(jslPriv);
        jslSigner.update(tbs);
        byte[] jslSig = jslSigner.sign();

        Signature bcSigner = Signature.getInstance("NoneWithRSA", BC);
        bcSigner.initSign(bcPriv);
        bcSigner.update(tbs);
        byte[] bcSig = bcSigner.sign();

        Assertions.assertArrayEquals(jslSig, fipsSig,
                "JSLFIPS and JSL must produce byte-identical deterministic NoneWithRSA signatures");
        Assertions.assertArrayEquals(bcSig, fipsSig,
                "JSLFIPS and BouncyCastle must produce byte-identical deterministic NoneWithRSA signatures");

        // And each verifies under JSLFIPS.
        Signature fipsVerifyJsl = Signature.getInstance("NoneWithRSA", FIPS);
        fipsVerifyJsl.initVerify(fipsKp.getPublic());
        fipsVerifyJsl.update(tbs);
        Assertions.assertTrue(fipsVerifyJsl.verify(jslSig), "JSLFIPS rejected a JSL NoneWithRSA signature");

        Signature fipsVerifyBc = Signature.getInstance("NoneWithRSA", FIPS);
        fipsVerifyBc.initVerify(fipsKp.getPublic());
        fipsVerifyBc.update(tbs);
        Assertions.assertTrue(fipsVerifyBc.verify(bcSig), "JSLFIPS rejected a BC NoneWithRSA signature");
    }

    /** Tampering the signed bytes must break verification — proves this isn't a stub. */
    @Test
    public void noneWithRsaTamperedInputFailsVerification() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("RSA", FIPS).generateKeyPair();
        byte[] tbs = randomTbs(RANDOM);

        Signature signer = Signature.getInstance("NoneWithRSA", FIPS);
        signer.initSign(kp.getPrivate());
        signer.update(tbs);
        byte[] sig = signer.sign();

        byte[] tampered = Arrays.clone(tbs);
        tampered[RANDOM.nextInt(tampered.length)] ^= 0x01;

        Signature verifier = Signature.getInstance("NoneWithRSA", FIPS);
        verifier.initVerify(kp.getPublic());
        verifier.update(tampered);
        Assertions.assertFalse(verifier.verify(sig), "JSLFIPS verified a tampered NoneWithRSA message");
    }
}
