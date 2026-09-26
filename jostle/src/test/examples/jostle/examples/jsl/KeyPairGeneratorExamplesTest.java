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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * Key-pair generators. Classical families take a size or a named curve; the post-quantum families have one
 * generator per parameter set, plus a generic one (`MLDSA`, `MLKEM`, `SLHDSA`) initialised with the set.
 * Pass no SecureRandom for the post-quantum families: JSL picks a DRBG strong enough for the set.
 */
public class KeyPairGeneratorExamplesTest
        extends JslExamples
{
    /**
     * RSA at 3072 bits, and EC on a named curve.
     */
    @Test
    public void rsaAndEc()
            throws Exception
    {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA", "JSL");
        rsa.initialize(3072);
        KeyPair rsaPair = rsa.generateKeyPair();
        Assertions.assertEquals(3072, ((RSAPublicKey) rsaPair.getPublic()).getModulus().bitLength());

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", "JSL");
        ec.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair ecPair = ec.generateKeyPair();
        Assertions.assertEquals(384, ((ECPublicKey) ecPair.getPublic()).getParams().getOrder().bitLength());
    }

    /**
     * Finite-field DSA and Diffie-Hellman keys at 2048 bits.
     */
    @Test
    public void dsaAndDh()
            throws Exception
    {
        for (String name : new String[]{"DSA", "DH"})
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, "JSL");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            Assertions.assertEquals(name, kp.getPublic().getAlgorithm());
            Assertions.assertNotNull(kp.getPrivate().getEncoded());
        }
    }

    /**
     * The Edwards and Montgomery curves need no parameters. The generic `ED` generator makes Ed25519 keys.
     */
    @Test
    public void edwardsAndMontgomeryCurves()
            throws Exception
    {
        String[] names = {"ED25519", "ED448", "X25519", "X448", "ED"};
        String[] algorithms = {"Ed25519", "Ed448", "X25519", "X448", "Ed25519"};
        for (int i = 0; i < names.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(names[i], "JSL").generateKeyPair();
            Assertions.assertEquals(algorithms[i], kp.getPublic().getAlgorithm(), names[i]);
        }
    }

    /**
     * One generator per ML-DSA and ML-KEM parameter set, or the generic generator initialised with the set.
     */
    @Test
    public void mlDsaAndMlKem()
            throws Exception
    {
        String[] names = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
        for (String name : names)
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, "JSL").generateKeyPair();
            Assertions.assertEquals(name, kp.getPublic().getAlgorithm(), name);
        }
        KeyPairGenerator mldsa = KeyPairGenerator.getInstance("MLDSA", "JSL");
        mldsa.initialize(MLDSAParameterSpec.ml_dsa_65);
        Assertions.assertEquals("ML-DSA-65", mldsa.generateKeyPair().getPublic().getAlgorithm());
        KeyPairGenerator mlkem = KeyPairGenerator.getInstance("MLKEM", "JSL");
        mlkem.initialize(MLKEMParameterSpec.ml_kem_1024);
        Assertions.assertEquals("ML-KEM-1024", mlkem.generateKeyPair().getPublic().getAlgorithm());
    }

    /**
     * One generator per SLH-DSA parameter set: SHA2 or SHAKE, security level 128, 192 or 256, and the S
     * (smaller signatures) or F (faster signing) trade-off. The generic `SLHDSA` generator takes the set.
     */
    @Test
    public void slhDsa()
            throws Exception
    {
        String[] names = {"SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192F",
                "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128F",
                "SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192F", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHAKE-256F"};
        for (String name : names)
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, "JSL").generateKeyPair();
            Assertions.assertEquals(name, kp.getPublic().getAlgorithm(), name);
        }
        KeyPairGenerator slhdsa = KeyPairGenerator.getInstance("SLHDSA", "JSL");
        slhdsa.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f);
        Assertions.assertEquals("SLH-DSA-SHA2-128F", slhdsa.generateKeyPair().getPublic().getAlgorithm());
    }

    /**
     * The hybrid TLS groups: an ML-KEM key and an elliptic-curve key in one pair, for key encapsulation.
     */
    @Test
    public void hybridKemGroups()
            throws Exception
    {
        String[] names = {"X25519MLKEM768", "X448MLKEM1024", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"};
        for (String name : names)
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, "JSL").generateKeyPair();
            Assertions.assertTrue(name.equalsIgnoreCase(kp.getPublic().getAlgorithm()), name);
        }
    }
}
