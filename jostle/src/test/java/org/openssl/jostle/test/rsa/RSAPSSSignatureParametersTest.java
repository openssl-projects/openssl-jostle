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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * What an RSASSA-PSS Signature reports through {@code getParameters()}.
 *
 * <p>It reports the EFFECTIVE parameters, not null, because a caller that
 * never called {@code setParameter} still signs under a concrete set and has
 * to put it in the AlgorithmIdentifier. BouncyCastle does the same (it reports
 * its own SHA-1 default); SunRsaSign returns null until parameters are set.
 * The value differs from both because this provider's default digest is
 * SHA-256, a deliberate deviation from the JCE historical default.
 *
 * <p>The parameters come from this provider's own instance. A name would be
 * re-resolvable — {@code removeProvider} plus {@code addProvider} swaps what it
 * points at, and {@code getInstance(alg, Provider)} never required
 * registration — so the instance is the identity that matters.
 */
public class RSAPSSSignatureParametersTest
{
    private static Provider jsl;
    private static KeyPair keyPair;

    @BeforeAll
    public static void setUp()
        throws Exception
    {
        jsl = new JostleProvider();
        Security.addProvider(jsl);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", jsl);
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    private static PSSParameterSpec specOf(Signature signature)
        throws Exception
    {
        AlgorithmParameters params = signature.getParameters();
        Assertions.assertNotNull(params, signature.getAlgorithm() + " reported no parameters");
        Assertions.assertSame(jsl, params.getProvider(),
                signature.getAlgorithm() + " resolved parameters through another provider");
        return params.getParameterSpec(PSSParameterSpec.class);
    }

    @Test
    public void aFreshPssSignatureReportsItsEffectiveDefaults()
        throws Exception
    {
        PSSParameterSpec spec = specOf(Signature.getInstance("RSASSA-PSS", jsl));
        Assertions.assertEquals("SHA-256", spec.getDigestAlgorithm());
        Assertions.assertEquals("MGF1", spec.getMGFAlgorithm());
        Assertions.assertEquals("SHA-256",
                ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm());
        // The native sentinel is -1 for "digest output length"; the reported
        // value must be the resolved byte count, not the sentinel.
        Assertions.assertEquals(32, spec.getSaltLength());
        Assertions.assertEquals(1, spec.getTrailerField());
    }

    /**
     * A per-digest name carries its own digest, so its report must too — this
     * is what BouncyCastle does for its equivalent {@code SHA256withRSA/PSS}.
     * The salt length tracks the digest, which is the part a transcribed table
     * would get wrong.
     */
    @Test
    public void eachNamedPssSignatureReportsItsOwnDigestAndSaltLength()
        throws Exception
    {
        String[][] cases = {
                {"SHA1WITHRSAANDMGF1", "SHA-1", "20"},
                {"SHA224WITHRSAANDMGF1", "SHA-224", "28"},
                {"SHA256WITHRSAANDMGF1", "SHA-256", "32"},
                {"SHA384WITHRSAANDMGF1", "SHA-384", "48"},
                {"SHA512WITHRSAANDMGF1", "SHA-512", "64"},
                {"SHA3-256WITHRSAANDMGF1", "SHA3-256", "32"},
                {"SHA3-512WITHRSAANDMGF1", "SHA3-512", "64"},
                {"SHA512(224)WITHRSAANDMGF1", "SHA-512/224", "28"},
                {"SHA512(256)WITHRSAANDMGF1", "SHA-512/256", "32"},
        };
        for (String[] row : cases)
        {
            PSSParameterSpec spec = specOf(Signature.getInstance(row[0], jsl));
            Assertions.assertEquals(row[1], spec.getDigestAlgorithm(), row[0]);
            Assertions.assertEquals(row[1],
                    ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm(), row[0]);
            Assertions.assertEquals(Integer.parseInt(row[2]), spec.getSaltLength(), row[0]);
        }
    }

    @Test
    public void setParametersAreReportedBackUnchangedAndSurviveSigning()
        throws Exception
    {
        PSSParameterSpec chosen =
                new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA384, 20, 1);

        Signature signature = Signature.getInstance("RSASSA-PSS", jsl);
        signature.setParameter(chosen);

        PSSParameterSpec beforeSigning = specOf(signature);
        Assertions.assertEquals("SHA-512", beforeSigning.getDigestAlgorithm());
        Assertions.assertEquals("SHA-384",
                ((MGF1ParameterSpec) beforeSigning.getMGFParameters()).getDigestAlgorithm());
        Assertions.assertEquals(20, beforeSigning.getSaltLength());

        signature.initSign(keyPair.getPrivate());
        signature.update("payload".getBytes("UTF-8"));
        byte[] produced = signature.sign();
        Assertions.assertTrue(produced.length > 0);

        // The order the JDK's TLS stack uses: set, then read back.
        AlgorithmParameters after = signature.getParameters();
        AlgorithmParameters expected = AlgorithmParameters.getInstance("RSASSA-PSS", jsl);
        expected.init(chosen);
        Assertions.assertTrue(Arrays.areEqual(expected.getEncoded(), after.getEncoded()),
                "the reported parameters changed across a sign");
    }

    /**
     * The reported parameters must be the ones the signature can actually be
     * verified under. Asserting the encoding alone would pass for a report
     * that names a digest the SPI never used.
     */
    @Test
    public void theReportedParametersVerifyTheSignatureTheyDescribe()
        throws Exception
    {
        Signature signer = Signature.getInstance("SHA384WITHRSAANDMGF1", jsl);
        signer.initSign(keyPair.getPrivate());
        signer.update("payload".getBytes("UTF-8"));
        byte[] produced = signer.sign();

        PSSParameterSpec reported = specOf(signer);

        Signature verifier = Signature.getInstance("RSASSA-PSS", jsl);
        verifier.setParameter(reported);
        verifier.initVerify(keyPair.getPublic());
        verifier.update("payload".getBytes("UTF-8"));
        Assertions.assertTrue(verifier.verify(produced),
                "the reported parameters do not describe the signature that was produced");

        // Differentiator: a different digest must NOT verify, so the cell
        // above is not satisfied by any parameters at all.
        Signature wrong = Signature.getInstance("RSASSA-PSS", jsl);
        wrong.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        wrong.initVerify(keyPair.getPublic());
        wrong.update("payload".getBytes("UTF-8"));
        Assertions.assertFalse(wrong.verify(produced),
                "a different digest verified, so the parameters are not being applied");
    }
}
