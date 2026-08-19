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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * Behaviour lock for {@code NoneWithRSA} through the FIPS provider ("JSLFIPS").
 * <p>
 * {@code ProvFIPSRSA} registers {@code NoneWithRSA} by constructing the base
 * {@code RSASignatureSpi} with digest name {@code "NONE"} (the PKCS#1 v1.5
 * <em>digest</em> path, not the raw {@code RSASignatureSpi.None} path the
 * non-FIPS provider uses) — so {@code Signature.getInstance("NoneWithRSA",
 * "JSLFIPS")} <b>resolves</b>, but the FIPS module <b>refuses to service it</b>:
 * {@code EVP_DigestSign/VerifyInit} tries to fetch a digest named {@code NONE},
 * which does not exist in the FIPS {@code OSSL_LIB_CTX}, and fails at
 * <em>init</em> with an unsupported-algorithm error. The SPI's
 * {@code engineInitSign} / {@code engineInitVerify} translate that native
 * {@link OpenSSLException} into the JCE-canonical, fallback-eligible
 * {@link InvalidKeyException} (the original {@code OpenSSLException} is preserved
 * as the cause). This mirrors the SHA-1 signature-generation gate (see
 * {@code FIPSSha1SignatureGateTest}, whose rejection fires at {@code sign()}
 * rather than init and therefore stays an {@code OpenSSLException}): the service
 * is present but the module is the authority that rejects the non-approved
 * operation.
 * <p>
 * This test <b>pins that current behaviour</b> so a future change is caught
 * loudly and deliberately: if {@code NoneWithRSA} is ever dropped from JSLFIPS
 * (resolution would then throw {@code NoSuchAlgorithmException}) or ever becomes
 * functional (the {@code assertThrows} would fail), this test goes red and the
 * change is reviewed against the security policy rather than shipping silently.
 * <p>
 * (The non-FIPS provider serves a fully-functional {@code NoneWithRSA}; that
 * round-trip / BouncyCastle-agreement coverage lives in
 * {@code RSANoneWithRSASignatureTest}.) Gated on {@code TEST_FIPS_LIB}; skipped
 * when unset.
 */
public class FIPSRSANoneWithRSASignatureTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static KeyPair generateFipsKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", FIPS);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static byte[] randomTbs()
    {
        // Well under k - 11 (= 245 for a 2048-bit modulus): a size the raw
        // engine would accept if the module serviced NONE at all.
        byte[] tbs = new byte[32];
        RANDOM.nextBytes(tbs);
        return tbs;
    }

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    /**
     * {@code NoneWithRSA} resolves through JSLFIPS (registered) but the module
     * refuses to initialise a raw signature: {@code initSign} fails with an
     * {@link OpenSSLException} whose message reports the unsupported {@code NONE}
     * algorithm fetch in the FIPS lib ctx.
     */
    @Test
    public void noneWithRsaResolvesButModuleRefusesSign() throws Exception
    {
        KeyPair kp = generateFipsKeyPair();

        // Registered: resolution succeeds.
        Signature signer = Signature.getInstance("NoneWithRSA", FIPS);
        Assertions.assertNotNull(signer, "NoneWithRSA must remain registered in JSLFIPS");

        byte[] tbs = randomTbs();
        // The refusal fires at initSign (digest "NONE" is unfetchable); the SPI
        // translates the native OpenSSLException to the JCE-canonical,
        // fallback-eligible InvalidKeyException, preserving the OpenSSLException
        // as the cause.
        InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class, () ->
        {
            signer.initSign(kp.getPrivate());
            signer.update(tbs);
            signer.sign();
        }, "the FIPS module must refuse the NoneWithRSA signing path at init");
        Assertions.assertTrue(ex.getCause() instanceof OpenSSLException,
                "InvalidKeyException must carry the underlying OpenSSLException as its cause");
        String msg = String.valueOf(ex.getMessage());
        Assertions.assertTrue(msg.startsWith("OpenSSL Error:") && msg.contains("unsupported"),
                "expected an unsupported-algorithm module rejection, got: " + msg);
    }

    /**
     * The verify direction is refused the same way: {@code initVerify} on a
     * {@code NoneWithRSA} instance fails with an unsupported-algorithm
     * {@link OpenSSLException} (the raw path fetches {@code NONE} for both
     * directions).
     */
    @Test
    public void noneWithRsaResolvesButModuleRefusesVerify() throws Exception
    {
        KeyPair kp = generateFipsKeyPair();

        Signature verifier = Signature.getInstance("NoneWithRSA", FIPS);
        byte[] tbs = randomTbs();
        // Refusal fires at initVerify and is translated to InvalidKeyException,
        // exactly as the signing direction (digest "NONE" is unfetchable).
        InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class, () ->
        {
            verifier.initVerify(kp.getPublic());
            verifier.update(tbs);
            verifier.verify(new byte[256]);
        }, "the FIPS module must refuse the NoneWithRSA verify path at init");
        Assertions.assertTrue(ex.getCause() instanceof OpenSSLException,
                "InvalidKeyException must carry the underlying OpenSSLException as its cause");
        String msg = String.valueOf(ex.getMessage());
        Assertions.assertTrue(msg.startsWith("OpenSSL Error:") && msg.contains("unsupported"),
                "expected an unsupported-algorithm module rejection, got: " + msg);
    }
}
