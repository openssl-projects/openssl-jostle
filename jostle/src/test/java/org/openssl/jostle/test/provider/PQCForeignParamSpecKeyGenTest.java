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
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Verifies the ML-KEM / ML-DSA / SLH-DSA {@code KeyPairGenerator}s accept a
 * <em>foreign</em> {@link AlgorithmParameterSpec} — one that is NOT Jostle's own
 * spec type — by reflecting on its {@code getName()} method (the bc-java
 * {@code SpecUtil.getNameFrom} pattern). The concrete foreign specs here are
 * BouncyCastle's {@code org.bouncycastle.jcajce.spec.*ParameterSpec} classes, so
 * code written against the BC provider can drive Jostle's generators unchanged.
 * <p>
 * The parameter set actually selected is asserted via the algorithm OID carried
 * in the generated key's encoding, proving the reflected name was resolved to the
 * right {@code OSSLKeyType} (not silently defaulted).
 */
public class PQCForeignParamSpecKeyGenTest
{
    // 128-bit-category parameter sets — usable with the JCE default SecureRandom
    // (no strength-gate interaction; the reflection path is what's under test).
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
    public void mlkem_acceptsBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecSelectsParamSet("ML-KEM", MLKEMParameterSpec.ml_kem_512, ML_KEM_512_OID);
    }

    @Test
    public void mldsa_acceptsBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecSelectsParamSet("ML-DSA", MLDSAParameterSpec.ml_dsa_44, ML_DSA_44_OID);
    }

    @Test
    public void slhdsa_acceptsBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecSelectsParamSet("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_128f, SLH_DSA_SHA2_128F_OID);
    }

    // --- High-strength (>= 192/256-bit category) sets. ---------------------
    // These exercise the strength gate, NOT just name resolution: ML-KEM-1024,
    // ML-DSA-87 and SLH-DSA-SHA2-256f require an RNG above the JDK default
    // 128-bit DRBG. generateKeyPair() succeeding proves the foreign-spec init
    // resolved the name AND wired a strength-appropriate default RandSource for
    // the resolved type — otherwise the C RAND gate rejects keygen with
    // JO_RAND_INSUFFICIENT_STRENGTH (GH #34).

    @Test
    public void mlkem_acceptsHighStrengthBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecSelectsParamSet("ML-KEM", MLKEMParameterSpec.ml_kem_1024,
                NISTObjectIdentifiers.id_alg_ml_kem_1024.getId());
    }

    @Test
    public void mldsa_acceptsHighStrengthBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecSelectsParamSet("ML-DSA", MLDSAParameterSpec.ml_dsa_87,
                NISTObjectIdentifiers.id_ml_dsa_87.getId());
    }

    @Test
    public void slhdsa_acceptsHighStrengthBouncyCastleParameterSpec() throws Exception
    {
        assertForeignSpecSelectsParamSet("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_256f,
                NISTObjectIdentifiers.id_slh_dsa_sha2_256f.getId());
    }

    @Test
    public void rejectsForeignSpecWithoutGetName() throws Exception
    {
        // IvParameterSpec has no getName() — reflection yields null, so the
        // generator must reject it rather than NPE or silently default.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(new IvParameterSpec(new byte[16])));
    }

    @Test
    public void rejectsForeignSpecWithUnknownName() throws Exception
    {
        // A well-formed foreign spec whose getName() ("ML-KEM-512") is unknown to
        // the ML-DSA generator must be rejected, not coerced.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(MLKEMParameterSpec.ml_kem_512));
    }

    private static void assertForeignSpecSelectsParamSet(String genName, AlgorithmParameterSpec foreignSpec, String expectedOid)
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(genName, JostleProvider.PROVIDER_NAME);
        kpg.initialize(foreignSpec);
        KeyPair kp = kpg.generateKeyPair();

        String pubOid = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
                .getAlgorithm().getAlgorithm().getId();
        String privOid = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded())
                .getPrivateKeyAlgorithm().getAlgorithm().getId();

        Assertions.assertEquals(expectedOid, pubOid, genName + ": public key OID");
        Assertions.assertEquals(expectedOid, privOid, genName + ": private key OID");
    }
}
