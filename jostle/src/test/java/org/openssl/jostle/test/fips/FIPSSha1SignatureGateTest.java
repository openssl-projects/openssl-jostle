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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

/**
 * Hard guard for the SHA-1 signature boundary of the FIPS module.
 * <p>
 * Per the OpenSSL FIPS Provider 3.1.2 Security Policy (CMVP cert #4985, §2.7d /
 * SHA-1 Usage), SHA-1 as a signature hash is approved only for VERIFICATION
 * (legacy) — signature GENERATION with SHA-1 is not approved. The 3.1.2 module
 * enforces this itself: its RSA/ECDSA {@code setup_md} rejects SHA-1 for signing
 * ("digest not allowed"). JSLFIPS therefore leaves the {@code SHA1with*}
 * Signature services registered (unlike PKCS#1 v1.5 encryption, which the module
 * does NOT gate and which is dropped at the provider) and relies on the module
 * to gate the sign direction — exactly as it relies on the module to gate
 * non-approved curves (see {@code FIPSECTest}).
 * <p>
 * This test pins that reliance: if a future module or configuration ever allowed
 * SHA-1 signing (or disallowed legacy SHA-1 verification), it fails loudly rather
 * than silently drifting into a non-approved capability. Gated on
 * {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSSha1SignatureGateTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

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
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * A {@code SHA1with*} signature-generation attempt through JSLFIPS must be
     * rejected by the module with an "OpenSSL Error: ... digest not allowed".
     * <p>
     * The module refuses SHA-1 signing at init ({@code setup_md}); how that
     * surfaces at the JCE boundary depends on the SPI: the RSA Signature SPI
     * translates the init-time refusal into the JCE-canonical, fallback-eligible
     * {@link java.security.InvalidKeyException} (preserving the
     * {@link OpenSSLException} as the cause), whereas the EC/DSA SPIs surface the
     * raw {@link OpenSSLException}. This helper accepts either shape and requires
     * the underlying module "digest not allowed" message in both.
     */
    private static void assertSha1SignRejected(KeyPair kp, String sigAlg)
    {
        byte[] msg = new byte[32];
        RANDOM.nextBytes(msg);
        Exception ex = Assertions.assertThrows(Exception.class, () ->
        {
            Signature s = Signature.getInstance(sigAlg, FIPS);
            s.initSign(kp.getPrivate());
            s.update(msg);
            s.sign();
        }, sigAlg + ": the FIPS module must reject SHA-1 signature generation");

        // Unwrap the RSA InvalidKeyException down to its OpenSSLException cause;
        // EC/DSA already are an OpenSSLException.
        Throwable openssl = (ex instanceof OpenSSLException) ? ex : ex.getCause();
        Assertions.assertTrue(openssl instanceof OpenSSLException,
                sigAlg + ": expected an OpenSSLException (possibly wrapped in InvalidKeyException), got: " + ex);
        // The module's wording for this refusal changed between the two
        // supported versions, so both are pinned rather than either being
        // matched loosely:
        //   3.1.2 : "... securitycheck: digest not allowed"
        //   3.5.7 : "... ossl_fips_ind_digest_sign_check: invalid digest"
        // Both name the digest as the cause, which is what distinguishes this
        // from a key or provider problem — the SHA-256 control above rules
        // those out.
        String m = String.valueOf(openssl.getMessage());
        Assertions.assertTrue(m.contains("digest not allowed") || m.contains("invalid digest"),
                sigAlg + ": expected a module digest rejection, got: " + m);
    }

    @Test
    public void sha1SignatureGenerationRejected() throws Exception
    {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", FIPS);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        // Control: SHA-256 signing works (proves the key/provider are sound, so
        // the SHA-1 rejections below are specifically about the digest).
        byte[] msg = new byte[64];
        RANDOM.nextBytes(msg);
        Signature control = Signature.getInstance("SHA256withRSA", FIPS);
        control.initSign(rsa.getPrivate());
        control.update(msg);
        Assertions.assertTrue(control.sign().length > 0, "SHA-256 RSA signing must work");

        assertSha1SignRejected(rsa, "SHA1withRSA");
        assertSha1SignRejected(rsa, "SHA1withRSAandMGF1");

        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", FIPS);
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ec = ecKpg.generateKeyPair();

        Signature ecControl = Signature.getInstance("SHA256withECDSA", FIPS);
        ecControl.initSign(ec.getPrivate());
        ecControl.update(msg);
        Assertions.assertTrue(ecControl.sign().length > 0, "SHA-256 ECDSA signing must work");

        assertSha1SignRejected(ec, "SHA1withECDSA");
    }

    /**
     * SHA-1 DSA signature GENERATION is refused.
     * <p>
     * Only meaningful where the module signs with DSA at all. OpenSSL's 3.5.x
     * FIPS module refuses DSA signing outright, which subsumes the SHA-1 gate
     * — asserted explicitly rather than skipped, so a module that quietly
     * started signing SHA-1 DSA could not pass by looking verify-only. The
     * keypair comes from {@link FIPSTestUtil#dsaKeyPair} because 3.5.x also
     * refuses every DSA generation path.
     */
    @Test
    public void sha1DsaSignatureGenerationRejected() throws Exception
    {
        KeyPair dsa = FIPSTestUtil.dsaKeyPair(FIPS);

        if (!FIPSTestUtil.fipsDsaCanSign())
        {
            // The broader gate must cover SHA-1 too: no DSA digest may sign.
            java.security.InvalidKeyException e = Assertions.assertThrows(
                    java.security.InvalidKeyException.class,
                    () -> Signature.getInstance("SHA1withDSA", FIPS).initSign(dsa.getPrivate()),
                    "a verify-only module must refuse SHA1withDSA signing too");
            Assertions.assertEquals(FIPSTestUtil.DSA_SIGN_REFUSED_MESSAGE, e.getMessage());
            return;
        }

        // Control: SHA-256 signing works (proves the key/provider are sound, so
        // the SHA-1 rejection below is specifically about the digest).
        byte[] msg = new byte[64];
        RANDOM.nextBytes(msg);
        Signature control = Signature.getInstance("SHA256withDSA", FIPS);
        control.initSign(dsa.getPrivate());
        control.update(msg);
        Assertions.assertTrue(control.sign().length > 0, "SHA-256 DSA signing must work");

        assertSha1SignRejected(dsa, "SHA1withDSA");
    }

    @Test
    public void sha1VerificationRemainsAllowed() throws Exception
    {
        byte[] msg = new byte[64];
        RANDOM.nextBytes(msg);

        // A SHA-1 signature produced elsewhere (BouncyCastle) must still verify
        // through JSLFIPS: SHA-1 SigVer is approved for legacy use. The public
        // key crosses provider boundaries freely.
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", BC);
        bcKpg.initialize(2048);
        KeyPair kp = bcKpg.generateKeyPair();

        Signature bcSigner = Signature.getInstance("SHA1withRSA", BC);
        bcSigner.initSign(kp.getPrivate());
        bcSigner.update(msg);
        byte[] sig = bcSigner.sign();

        Signature fipsVerifier = Signature.getInstance("SHA1withRSA", FIPS);
        fipsVerifier.initVerify(kp.getPublic());
        fipsVerifier.update(msg);
        Assertions.assertTrue(fipsVerifier.verify(sig),
                "the FIPS module must allow legacy SHA-1 signature verification");
    }
}
