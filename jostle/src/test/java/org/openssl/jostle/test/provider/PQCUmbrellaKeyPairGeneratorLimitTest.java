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

import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.jcajce.interfaces.MLKEMKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * The generic ML-DSA and ML-KEM KeyPairGenerators, and their MLDSA and MLKEM aliases, used without initialize()
 * generate ML-DSA-87 and ML-KEM-768, BouncyCastle's defaults. The parameter set is read back by BouncyCastle from
 * the encodings, so a key that merely reports the right name cannot pass. The generic SLH-DSA generator has no
 * default and still refuses typed.
 */
public class PQCUmbrellaKeyPairGeneratorLimitTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void bareMlDsaGeneratorsGenerateMlDsa87() throws Exception
    {
        assertBareDefault(JSL, "ML-DSA", "ML-DSA-87");
        assertBareDefault(JSL, "MLDSA", "ML-DSA-87");
    }

    @Test
    public void bareMlKemGeneratorsGenerateMlKem768() throws Exception
    {
        assertBareDefault(JSL, "ML-KEM", "ML-KEM-768");
        assertBareDefault(JSL, "MLKEM", "ML-KEM-768");
    }

    /**
     * The default must not fix the parameter set: an initialize() on the generic generator still selects any set,
     * the smallest included so the default cannot satisfy it.
     */
    @Test
    public void initializeStillSelectsTheParameterSet() throws Exception
    {
        assertInitialized(JSL, "ML-DSA", MLDSAParameterSpec.ml_dsa_44, "ML-DSA-44");
        assertInitialized(JSL, "MLDSA", MLDSAParameterSpec.ml_dsa_65, "ML-DSA-65");
        assertInitialized(JSL, "ML-KEM", MLKEMParameterSpec.ml_kem_512, "ML-KEM-512");
        assertInitialized(JSL, "MLKEM", MLKEMParameterSpec.ml_kem_1024, "ML-KEM-1024");
    }

    @Test
    public void bareSlhDsaGeneratorStillRefusesTyped() throws Exception
    {
        assertSlhDsaRefuses(JSL);
    }

    /**
     * Generates with {@code umbrella} and no initialize(), and requires the pair to be {@code expected}: the same
     * algorithm name and encoding sizes as the typed generator's pair, and {@code expected} as BouncyCastle reads it
     * from both encodings.
     */
    public static void assertBareDefault(String provider, String umbrella, String expected) throws Exception
    {
        KeyPair bare = KeyPairGenerator.getInstance(umbrella, provider).generateKeyPair();
        KeyPair typed = KeyPairGenerator.getInstance(expected, provider).generateKeyPair();
        Assertions.assertEquals(typed.getPublic().getAlgorithm(), bare.getPublic().getAlgorithm(), umbrella);
        Assertions.assertEquals(typed.getPublic().getEncoded().length, bare.getPublic().getEncoded().length, umbrella);
        Assertions.assertEquals(typed.getPrivate().getEncoded().length, bare.getPrivate().getEncoded().length,
                umbrella);
        assertBcReads(expected, bare, umbrella);
    }

    public static void assertInitialized(String provider, String umbrella, AlgorithmParameterSpec spec,
                                         String expected) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(umbrella, provider);
        kpg.initialize(spec);
        assertBcReads(expected, kpg.generateKeyPair(), umbrella);
    }

    public static void assertSlhDsaRefuses(String provider) throws Exception
    {
        for (String name : new String[]{"SLH-DSA", "SLHDSA"})
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, provider);
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, kpg::generateKeyPair,
                    name);
            Assertions.assertEquals("SLH-DSA is parameter-set based; call initialize(SLHDSAParameterSpec) "
                    + "before generateKeyPair(), or use a typed generator "
                    + "(e.g. KeyPairGenerator.getInstance(\"SLH-DSA-SHA2-128S\"))", e.getMessage(), name);
        }
    }

    /**
     * The parameter set BouncyCastle reads from the public and private encodings of {@code pair}.
     */
    static void assertBcReads(String expected, KeyPair pair, String label) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(expected.startsWith("ML-DSA") ? "ML-DSA" : "ML-KEM", BC);
        Key pub = kf.generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));
        Key priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded()));
        Assertions.assertEquals(expected, bcParameterSet(pub), label + " public");
        Assertions.assertEquals(expected, bcParameterSet(priv), label + " private");
    }

    static String bcParameterSet(Key key)
    {
        if (key instanceof MLDSAKey)
        {
            return ((MLDSAKey) key).getParameterSpec().getName();
        }
        return ((MLKEMKey) key).getParameterSpec().getName();
    }
}
