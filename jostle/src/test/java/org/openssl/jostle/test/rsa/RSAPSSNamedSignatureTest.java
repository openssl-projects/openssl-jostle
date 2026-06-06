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

package org.openssl.jostle.test.rsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Tests for the per-digest RSASSA-PSS convenience Signature names registered by
 * {@code ProvRSA} — {@code <digest>WITHRSAANDMGF1} and the
 * {@code <digest>WITHRSASSA-PSS} aliases — backed by the new
 * {@code RSAPSSSignatureSpi(String digest)} constructor.
 *
 * <p>Each name must carry its own digest default (with MGF1 over the same hash
 * and salt = digest length), because BC's PKIX/CMS layer drives these names
 * <em>without</em> calling {@code setParameter} for default parameters. The
 * java-spi guide flags name-based digest defaults as exactly where a
 * registration bug silently collapses to the wrong digest, so these tests:
 * <ol>
 *   <li>cross-check each name's implicit default against an explicit
 *       {@link PSSParameterSpec} verified by BouncyCastle (both directions),</li>
 *   <li>confirm the {@code WITHRSASSA-PSS} alias resolves and round-trips,</li>
 *   <li>prove an explicit {@code setParameter} overrides the name's default,</li>
 *   <li>exercise the negative path (tampered message must not verify).</li>
 * </ol>
 */
public class RSAPSSNamedSignatureTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static KeyPair sharedKeyPair;

    /** {jslAlgName, jcaDigestName, saltLen (= digest output length)}. */
    private static final String[][] CASES = {
            {"SHA1WITHRSAANDMGF1", "SHA-1", "20"},
            {"SHA224WITHRSAANDMGF1", "SHA-224", "28"},
            {"SHA256WITHRSAANDMGF1", "SHA-256", "32"},
            {"SHA384WITHRSAANDMGF1", "SHA-384", "48"},
            {"SHA512WITHRSAANDMGF1", "SHA-512", "64"},
            {"SHA3-224WITHRSAANDMGF1", "SHA3-224", "28"},
            {"SHA3-256WITHRSAANDMGF1", "SHA3-256", "32"},
            {"SHA3-384WITHRSAANDMGF1", "SHA3-384", "48"},
            {"SHA3-512WITHRSAANDMGF1", "SHA3-512", "64"},
    };

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        sharedKeyPair = kpg.generateKeyPair();
    }

    private static byte[] randomMessage(int len)
    {
        byte[] m = new byte[len];
        RANDOM.nextBytes(m);
        return m;
    }

    private static PSSParameterSpec pssSpec(String jcaDigest, int saltLen)
    {
        return new PSSParameterSpec(jcaDigest, "MGF1", new MGF1ParameterSpec(jcaDigest), saltLen, 1);
    }

    /**
     * For each named algorithm: the implicit per-name default must equal an
     * explicit {@link PSSParameterSpec} of the same digest. Verified both ways
     * against BouncyCastle, which proves the registration wired the correct
     * digest / MGF1 / salt (a name collapsing to the wrong digest would fail
     * BC's explicit-param verify).
     */
    @Test
    public void testNamedDefault_matchesExplicitParams_bothDirections() throws Exception
    {
        for (String[] c : CASES)
        {
            String jslName = c[0];
            String jcaDigest = c[1];
            int saltLen = Integer.parseInt(c[2]);
            PSSParameterSpec spec = pssSpec(jcaDigest, saltLen);
            byte[] msg = randomMessage(200);

            // Sign with JSL named (no setParameter), verify with BC explicit params.
            Signature joSigner = Signature.getInstance(jslName, JostleProvider.PROVIDER_NAME);
            joSigner.initSign(sharedKeyPair.getPrivate());
            joSigner.update(msg);
            byte[] joSig = joSigner.sign();

            Signature bcVerifier = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
            bcVerifier.setParameter(spec);
            bcVerifier.initVerify(sharedKeyPair.getPublic());
            bcVerifier.update(msg);
            Assertions.assertTrue(bcVerifier.verify(joSig),
                    jslName + ": JSL-signed sig failed BC verify with explicit " + jcaDigest + " params");

            // Sign with BC explicit params, verify with JSL named (no setParameter).
            Signature bcSigner = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
            bcSigner.setParameter(spec);
            bcSigner.initSign(sharedKeyPair.getPrivate());
            bcSigner.update(msg);
            byte[] bcSig = bcSigner.sign();

            Signature joVerifier = Signature.getInstance(jslName, JostleProvider.PROVIDER_NAME);
            joVerifier.initVerify(sharedKeyPair.getPublic());
            joVerifier.update(msg);
            Assertions.assertTrue(joVerifier.verify(bcSig),
                    jslName + ": BC-signed sig (explicit " + jcaDigest + ") failed JSL named verify");
        }
    }

    @Test
    public void testWithRSASSAPSSAlias_resolvesAndRoundTrips() throws Exception
    {
        for (String[] c : CASES)
        {
            // ProvRSA registers the alias as digestName + "WITHRSASSA-PSS", where
            // digestName is the leading token of the WITHRSAANDMGF1 name
            // (e.g. "SHA256", "SHA3-256").
            String digestName = c[0].substring(0, c[0].indexOf("WITHRSAANDMGF1"));
            String aliasName = digestName + "WITHRSASSA-PSS";

            byte[] msg = randomMessage(128);
            Signature signer = Signature.getInstance(aliasName, JostleProvider.PROVIDER_NAME);
            signer.initSign(sharedKeyPair.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(aliasName, JostleProvider.PROVIDER_NAME);
            verifier.initVerify(sharedKeyPair.getPublic());
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig), aliasName + ": alias round-trip failed");
        }
    }

    /**
     * An explicit {@code setParameter} must override the name's implicit digest
     * default. Sign with the SHA-256 name but SHA-384 params; the SHA-384
     * explicit verify succeeds while the SHA-256 default-name verify must fail
     * — proving the override took effect (and the name default is not frozen).
     */
    @Test
    public void testSetParameter_overridesNameDefault() throws Exception
    {
        byte[] msg = randomMessage(200);
        PSSParameterSpec sha384 = pssSpec("SHA-384", 48);

        Signature signer = Signature.getInstance("SHA256WITHRSAANDMGF1", JostleProvider.PROVIDER_NAME);
        signer.setParameter(sha384);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        // SHA-384 explicit verify succeeds.
        Signature okVerifier = Signature.getInstance("RSASSA-PSS", JostleProvider.PROVIDER_NAME);
        okVerifier.setParameter(sha384);
        okVerifier.initVerify(sharedKeyPair.getPublic());
        okVerifier.update(msg);
        Assertions.assertTrue(okVerifier.verify(sig), "SHA-384 override sig failed explicit SHA-384 verify");

        // SHA-256 default (name default, no setParameter) must NOT verify a
        // SHA-384 signature.
        Signature wrongVerifier = Signature.getInstance("SHA256WITHRSAANDMGF1", JostleProvider.PROVIDER_NAME);
        wrongVerifier.initVerify(sharedKeyPair.getPublic());
        wrongVerifier.update(msg);
        Assertions.assertFalse(wrongVerifier.verify(sig),
                "SHA-256 default unexpectedly verified a SHA-384 signature");
    }

    @Test
    public void testTamperedMessage_doesNotVerify() throws Exception
    {
        byte[] msg = randomMessage(200);
        Signature signer = Signature.getInstance("SHA256WITHRSAANDMGF1", JostleProvider.PROVIDER_NAME);
        signer.initSign(sharedKeyPair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        byte[] tampered = msg.clone();
        tampered[0] ^= 0x01;

        Signature verifier = Signature.getInstance("SHA256WITHRSAANDMGF1", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(sharedKeyPair.getPublic());
        verifier.update(tampered);
        Assertions.assertFalse(verifier.verify(sig), "tampered message unexpectedly verified");
    }
}
