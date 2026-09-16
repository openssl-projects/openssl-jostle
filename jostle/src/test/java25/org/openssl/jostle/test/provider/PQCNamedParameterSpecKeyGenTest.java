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

package org.openssl.jostle.test.provider;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyPairGenerator;
import org.openssl.jostle.test.multirelease.MultiReleaseOverrides;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.NamedParameterSpec;

/**
 * Companion to {@code PQCForeignParamSpecRefusalRegressionTest} for the
 * later-JVM source set: drives the ML-KEM / ML-DSA / SLH-DSA
 * {@code KeyPairGenerator}s with the JDK's own {@link NamedParameterSpec}
 * (a Java 11 API — see {@code JdkSpecs}). NamedParameterSpec is unavailable at
 * the Java 8 baseline, which is why this test lives in
 * {@code src/test/java25}.
 *
 * <p>The {@code java11} {@code JdkSpecs} override is served only from a jar
 * carrying {@code META-INF/versions/11} — see {@link MultiReleaseOverrides}.
 * This test follows {@code NamedParameterSpecAcceptanceTest}'s pattern and
 * asserts BOTH branches rather than assuming the override is active: when it
 * is, the spec is accepted and the OID is checked; when it is not (a
 * class-directory classpath), the refusal is asserted, never skipped.
 */
public class PQCNamedParameterSpecKeyGenTest
{
    private static final String ML_KEM_512_OID = "2.16.840.1.101.3.4.4.1";
    private static final String ML_DSA_44_OID = "2.16.840.1.101.3.4.3.17";
    private static final String SLH_DSA_SHA2_128F_OID = "2.16.840.1.101.3.4.3.21";

    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** Is the {@code java11} {@code JdkSpecs} override the copy LOADED? */
    private static boolean overrideActive()
    {
        return MultiReleaseOverrides.overrideActive(
                MLKEMKeyPairGenerator.class, "java.security.spec.NamedParameterSpec");
    }

    @Test
    public void mlkem_namedParameterSpec() throws Exception
    {
        assertNamedSpecContract("ML-KEM", "ML-KEM-512", ML_KEM_512_OID);
    }

    @Test
    public void mldsa_namedParameterSpec() throws Exception
    {
        assertNamedSpecContract("ML-DSA", "ML-DSA-44", ML_DSA_44_OID);
    }

    @Test
    public void slhdsa_namedParameterSpec() throws Exception
    {
        assertNamedSpecContract("SLH-DSA", "SLH-DSA-SHA2-128F", SLH_DSA_SHA2_128F_OID);
    }

    // --- High-strength (>= 192/256-bit category) sets. ---------------------
    // generateKeyPair() succeeding (when the override is active) proves the
    // NamedParameterSpec name resolved AND a strength-appropriate (>= 256-bit)
    // default RandSource was wired for the resolved type — else the C RAND
    // gate rejects with JO_RAND_INSUFFICIENT_STRENGTH (GH #34).

    @Test
    public void mlkem_highStrengthNamedParameterSpec() throws Exception
    {
        assertNamedSpecContract("ML-KEM", "ML-KEM-1024", NISTObjectIdentifiers.id_alg_ml_kem_1024.getId());
    }

    @Test
    public void mldsa_highStrengthNamedParameterSpec() throws Exception
    {
        assertNamedSpecContract("ML-DSA", "ML-DSA-87", NISTObjectIdentifiers.id_ml_dsa_87.getId());
    }

    @Test
    public void slhdsa_highStrengthNamedParameterSpec() throws Exception
    {
        assertNamedSpecContract("SLH-DSA", "SLH-DSA-SHA2-256F", NISTObjectIdentifiers.id_slh_dsa_sha2_256f.getId());
    }

    private static void assertNamedSpecContract(String genName, String paramSetName, String expectedOid)
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(genName, JostleProvider.PROVIDER_NAME);
        NamedParameterSpec spec = new NamedParameterSpec(paramSetName);

        if (!overrideActive())
        {
            // The baseline JdkSpecs copy is loaded (class-directory
            // classpath), so it always answers null — refusal is CORRECT
            // here. Assert it rather than skipping: a skip would let a
            // genuinely broken baseline pass unnoticed.
            Assertions.assertThrows(InvalidAlgorithmParameterException.class, () -> kpg.initialize(spec),
                    genName + ": the baseline JdkSpecs copy cannot reference NamedParameterSpec and must refuse it");
            return;
        }

        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();

        String pubOid = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
                .getAlgorithm().getAlgorithm().getId();
        String privOid = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded())
                .getPrivateKeyAlgorithm().getAlgorithm().getId();

        Assertions.assertEquals(expectedOid, pubOid, genName + ": public key OID");
        Assertions.assertEquals(expectedOid, privOid, genName + ": private key OID");
    }
}
