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
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;

import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/**
 * The ML-KEM / ML-DSA / SLH-DSA {@code KeyPairGenerator}s do not
 * read a foreign {@link AlgorithmParameterSpec} reflectively — BouncyCastle's
 * {@code org.bouncycastle.jcajce.spec.*ParameterSpec} classes are refused
 * typed. Jostle's own spec classes are the positive twin, asserting the
 * parameter set actually selected via the algorithm OID carried in the
 * generated key's encoding — proving the name was resolved to the right
 * {@code OSSLKeyType}, not silently defaulted.
 */
public class PQCForeignParamSpecRefusalRegressionTest
{
    // 128-bit-category parameter sets — usable with the JCE default SecureRandom.
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

    // --- BC specs are refused typed. -----------------------------------

    @Test
    public void mlkem_refusesBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecRefused("ML-KEM", org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_512);
    }

    @Test
    public void mldsa_refusesBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecRefused("ML-DSA", org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
    }

    @Test
    public void slhdsa_refusesBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecRefused("SLH-DSA", org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_sha2_128f);
    }

    @Test
    public void mlkem_refusesHighStrengthBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecRefused("ML-KEM", org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_1024);
    }

    @Test
    public void mldsa_refusesHighStrengthBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecRefused("ML-DSA", org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87);
    }

    @Test
    public void slhdsa_refusesHighStrengthBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecRefused("SLH-DSA", org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_sha2_256f);
    }

    @Test
    public void rejectsForeignSpecWithoutGetName() throws Exception
    {
        // IvParameterSpec is neither our own spec nor a JDK NamedParameterSpec,
        // so it must be refused rather than NPE or silently default.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(new IvParameterSpec(new byte[16])));
    }

    // --- Jostle's own specs are the positive twin. ---

    @Test
    public void mlkem_ownSpecSelectsParamSet() throws Exception
    {
        assertOwnSpecSelectsParamSet("ML-KEM", MLKEMParameterSpec.ml_kem_512, ML_KEM_512_OID);
    }

    @Test
    public void mldsa_ownSpecSelectsParamSet() throws Exception
    {
        assertOwnSpecSelectsParamSet("ML-DSA", MLDSAParameterSpec.ml_dsa_44, ML_DSA_44_OID);
    }

    @Test
    public void slhdsa_ownSpecSelectsParamSet() throws Exception
    {
        assertOwnSpecSelectsParamSet("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_128f, SLH_DSA_SHA2_128F_OID);
    }

    // --- High-strength (>= 192/256-bit category) sets, own spec. -------
    // ML-KEM-1024, ML-DSA-87 and SLH-DSA-SHA2-256f require an RNG above the
    // JDK default 128-bit DRBG; generateKeyPair() succeeding proves the
    // resolved type was wired a strength-appropriate default RandSource.

    @Test
    public void mlkem_ownSpecSelectsHighStrengthParamSet() throws Exception
    {
        assertOwnSpecSelectsParamSet("ML-KEM", MLKEMParameterSpec.ml_kem_1024,
                NISTObjectIdentifiers.id_alg_ml_kem_1024.getId());
    }

    @Test
    public void mldsa_ownSpecSelectsHighStrengthParamSet() throws Exception
    {
        assertOwnSpecSelectsParamSet("ML-DSA", MLDSAParameterSpec.ml_dsa_87,
                NISTObjectIdentifiers.id_ml_dsa_87.getId());
    }

    @Test
    public void slhdsa_ownSpecSelectsHighStrengthParamSet() throws Exception
    {
        assertOwnSpecSelectsParamSet("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_256f,
                NISTObjectIdentifiers.id_slh_dsa_sha2_256f.getId());
    }

    private static void assertForeignSpecRefused(String genName, AlgorithmParameterSpec foreignSpec) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(genName, JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class, () -> kpg.initialize(foreignSpec),
                genName + " must refuse " + foreignSpec.getClass().getName());
    }

    private static void assertOwnSpecSelectsParamSet(String genName, AlgorithmParameterSpec ownSpec, String expectedOid)
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(genName, JostleProvider.PROVIDER_NAME);
        kpg.initialize(ownSpec);
        KeyPair kp = kpg.generateKeyPair();

        String pubOid = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
                .getAlgorithm().getAlgorithm().getId();
        String privOid = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded())
                .getPrivateKeyAlgorithm().getAlgorithm().getId();

        Assertions.assertEquals(expectedOid, pubOid, genName + ": public key OID");
        Assertions.assertEquals(expectedOid, privOid, genName + ": private key OID");
    }
}
