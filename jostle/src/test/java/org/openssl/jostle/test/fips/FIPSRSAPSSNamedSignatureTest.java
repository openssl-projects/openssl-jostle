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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * FIPS analogue of {@code RSAPSSNamedSignatureTest}: each per-digest
 * {@code <digest>WITHRSAANDMGF1} convenience Signature name registered by the
 * FIPS provider ("JSLFIPS") must carry its own implicit digest default (MGF1
 * over the same hash, salt = digest length), because BC's PKIX/CMS layer drives
 * these names <em>without</em> calling {@code setParameter}.
 *
 * <p>The java-spi guide flags name-based digest defaults as exactly where a
 * registration bug silently collapses a name to the wrong digest, so this test
 * cross-checks each name's implicit default against an explicit
 * {@link PSSParameterSpec} verified by BouncyCastle, in both directions.
 *
 * <p><b>SHA-1 is excluded from the signing matrix</b> — the FIPS module gates
 * SHA-1 signature generation, so the {@code SHA1WITHRSAANDMGF1} name (present in
 * the non-FIPS reference) is deliberately omitted here; the SHA-1 reject-gate is
 * exercised elsewhere.
 *
 * <p><b>Key origin.</b> The keypair is generated through the FIPS module and,
 * because JSLFIPS private keys are provider-isolated, both halves are encoded
 * and re-decoded through BC's {@code KeyFactory} so BC can sign with the same
 * key material. Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSRSAPSSNamedSignatureTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static PublicKey fipsPub;
    private static PrivateKey fipsPriv;
    private static PublicKey bcPub;
    private static PrivateKey bcPriv;

    /**
     * {jslAlgName, jcaDigestName, saltLen (= digest output length)}. SHA-1 is
     * intentionally excluded — the FIPS module refuses SHA-1 signing.
     */
    private static final String[][] CASES = {
            {"SHA224WITHRSAANDMGF1", "SHA-224", "28"},
            {"SHA256WITHRSAANDMGF1", "SHA-256", "32"},
            {"SHA384WITHRSAANDMGF1", "SHA-384", "48"},
            {"SHA512WITHRSAANDMGF1", "SHA-512", "64"},
            {"SHA3-224WITHRSAANDMGF1", "SHA3-224", "28"},
            {"SHA3-256WITHRSAANDMGF1", "SHA3-256", "32"},
            {"SHA3-384WITHRSAANDMGF1", "SHA3-384", "48"},
            {"SHA3-512WITHRSAANDMGF1", "SHA3-512", "64"},
    };

    private static void ensureProviders() throws Exception
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        if (fipsPriv == null)
        {
            // Generate one 2048-bit keypair in the module (2048 is the FIPS
            // floor), then decode both halves into BC so BC can operate the
            // same key material (JSLFIPS private keys are provider-isolated).
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", FIPS);
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            byte[] pubEnc = kp.getPublic().getEncoded();
            byte[] privEnc = kp.getPrivate().getEncoded();

            KeyFactory fipsKf = KeyFactory.getInstance("RSA", FIPS);
            fipsPub = fipsKf.generatePublic(new X509EncodedKeySpec(pubEnc));
            fipsPriv = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(privEnc));

            KeyFactory bcKf = KeyFactory.getInstance("RSA", BC);
            bcPub = bcKf.generatePublic(new X509EncodedKeySpec(pubEnc));
            bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(privEnc));
        }
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
     * For each named algorithm registered by the FIPS provider: the implicit
     * per-name default must equal an explicit {@link PSSParameterSpec} of the
     * same digest. Verified both ways against BouncyCastle, which proves the
     * registration wired the correct digest / MGF1 / salt (a name collapsing to
     * the wrong digest would fail BC's explicit-param verify). SHA-1 is excluded
     * — the module refuses SHA-1 signing.
     */
    @Test
    public void namedPssDefaultsMatchExplicitParams() throws Exception
    {
        ensureProviders();

        for (String[] c : CASES)
        {
            String jslName = c[0];
            String jcaDigest = c[1];
            int saltLen = Integer.parseInt(c[2]);
            PSSParameterSpec spec = pssSpec(jcaDigest, saltLen);
            byte[] msg = randomMessage(200);

            // Sign with JSLFIPS named (no setParameter), verify with BC explicit params.
            Signature joSigner = Signature.getInstance(jslName, FIPS);
            joSigner.initSign(fipsPriv);
            joSigner.update(msg);
            byte[] joSig = joSigner.sign();

            Signature bcVerifier = Signature.getInstance("RSASSA-PSS", BC);
            bcVerifier.setParameter(spec);
            bcVerifier.initVerify(bcPub);
            bcVerifier.update(msg);
            Assertions.assertTrue(bcVerifier.verify(joSig),
                    jslName + ": JSLFIPS-signed sig failed BC verify with explicit " + jcaDigest + " params");

            // Sign with BC explicit params, verify with JSLFIPS named (no setParameter).
            Signature bcSigner = Signature.getInstance("RSASSA-PSS", BC);
            bcSigner.setParameter(spec);
            bcSigner.initSign(bcPriv);
            bcSigner.update(msg);
            byte[] bcSig = bcSigner.sign();

            Signature joVerifier = Signature.getInstance(jslName, FIPS);
            joVerifier.initVerify(fipsPub);
            joVerifier.update(msg);
            Assertions.assertTrue(joVerifier.verify(bcSig),
                    jslName + ": BC-signed sig (explicit " + jcaDigest + ") failed JSLFIPS named verify");

            // Differentiator: a tampered message must NOT verify under the
            // named default — proves the named verify actually consults the
            // message (not a stubbed always-true).
            byte[] tampered = msg.clone();
            tampered[RANDOM.nextInt(tampered.length)] ^= (byte) 0x01;
            Signature joBad = Signature.getInstance(jslName, FIPS);
            joBad.initVerify(fipsPub);
            joBad.update(tampered);
            Assertions.assertFalse(joBad.verify(bcSig),
                    jslName + ": tampered message must not verify under the named default");
        }
    }

    /**
     * The FIPS provider must also register the {@code <digest>WITHRSASSA-PSS}
     * alias for each PSS name — BC's PKIX/CMS layer derives that fallback name
     * from an {@code id-RSASSA-PSS} AlgorithmIdentifier, so without the alias
     * RSASSA-PSS verification through BC against JSLFIPS fails with
     * NoSuchAlgorithmException (it resolves fine against the non-FIPS JSL).
     */
    @Test
    public void namedPss_RSASSA_PSS_alias_resolves() throws Exception
    {
        ensureProviders();
        for (String[] c : CASES)
        {
            String pssAlias = c[0].replace("WITHRSAANDMGF1", "WITHRSASSA-PSS");
            // Resolving through the FIPS provider must not throw, and the
            // resolved instance must be the FIPS provider's.
            Signature sig = Signature.getInstance(pssAlias, FIPS);
            Assertions.assertEquals(FIPS, sig.getProvider().getName(),
                    pssAlias + " must resolve to the FIPS provider");
        }
    }
}
