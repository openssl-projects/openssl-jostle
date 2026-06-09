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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.NamedParameterSpec;

/**
 * Companion to {@code PQCForeignParamSpecKeyGenTest} for the later-JVM source set:
 * drives the ML-KEM / ML-DSA / SLH-DSA {@code KeyPairGenerator}s with the JDK's own
 * {@link NamedParameterSpec} (added in Java 9 / RFC-era PQC support landed Java 11+).
 * It is a foreign {@link java.security.spec.AlgorithmParameterSpec} carrying a
 * {@code getName()}, so it must be accepted via the same reflective name-resolution
 * path as BouncyCastle's specs — confirming the support is not specific to BC's
 * spec classes. NamedParameterSpec is unavailable at the Java 8 baseline, which is
 * why this test lives in {@code src/test/java25}.
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

    @Test
    public void mlkem_acceptsNamedParameterSpec() throws Exception
    {
        assertNamedSpecSelectsParamSet("ML-KEM", "ML-KEM-512", ML_KEM_512_OID);
    }

    @Test
    public void mldsa_acceptsNamedParameterSpec() throws Exception
    {
        assertNamedSpecSelectsParamSet("ML-DSA", "ML-DSA-44", ML_DSA_44_OID);
    }

    @Test
    public void slhdsa_acceptsNamedParameterSpec() throws Exception
    {
        assertNamedSpecSelectsParamSet("SLH-DSA", "SLH-DSA-SHA2-128F", SLH_DSA_SHA2_128F_OID);
    }

    // --- High-strength (>= 192/256-bit category) sets. ---------------------
    // generateKeyPair() succeeding proves the NamedParameterSpec name resolved
    // AND a strength-appropriate (>= 256-bit) default RandSource was wired for
    // the resolved type — else the C RAND gate rejects with
    // JO_RAND_INSUFFICIENT_STRENGTH (GH #34).

    @Test
    public void mlkem_acceptsHighStrengthNamedParameterSpec() throws Exception
    {
        assertNamedSpecSelectsParamSet("ML-KEM", "ML-KEM-1024",
                NISTObjectIdentifiers.id_alg_ml_kem_1024.getId());
    }

    @Test
    public void mldsa_acceptsHighStrengthNamedParameterSpec() throws Exception
    {
        assertNamedSpecSelectsParamSet("ML-DSA", "ML-DSA-87",
                NISTObjectIdentifiers.id_ml_dsa_87.getId());
    }

    @Test
    public void slhdsa_acceptsHighStrengthNamedParameterSpec() throws Exception
    {
        assertNamedSpecSelectsParamSet("SLH-DSA", "SLH-DSA-SHA2-256F",
                NISTObjectIdentifiers.id_slh_dsa_sha2_256f.getId());
    }

    private static void assertNamedSpecSelectsParamSet(String genName, String paramSetName, String expectedOid)
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(genName, JostleProvider.PROVIDER_NAME);
        kpg.initialize(new NamedParameterSpec(paramSetName));
        KeyPair kp = kpg.generateKeyPair();

        String pubOid = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
                .getAlgorithm().getAlgorithm().getId();
        String privOid = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded())
                .getPrivateKeyAlgorithm().getAlgorithm().getId();

        Assertions.assertEquals(expectedOid, pubOid, genName + ": public key OID");
        Assertions.assertEquals(expectedOid, privOid, genName + ": private key OID");
    }
}
