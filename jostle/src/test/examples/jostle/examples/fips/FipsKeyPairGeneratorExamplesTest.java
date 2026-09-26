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

package jostle.examples.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

/**
 * Key-pair generators in the FIPS module. RSA keys are at least 2048 bits. The 3.5.8 module generates EC,
 * finite-field DH on named groups, Ed25519 and Ed448, ML-DSA, ML-KEM, SLH-DSA and three hybrid groups; it refuses
 * DSA key generation and serves no X25519 or X448.
 */
public class FipsKeyPairGeneratorExamplesTest
        extends FipsExamples
{
    /**
     * RSA, EC and DH. The generic `ED` generator makes Ed25519 keys where the module serves them.
     */
    @Test
    public void classicalKeyPairs()
            throws Exception
    {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA", "JSLFIPS");
        rsa.initialize(3072);
        Assertions.assertEquals(3072, ((RSAPublicKey) rsa.generateKeyPair().getPublic()).getModulus().bitLength());
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", "JSLFIPS");
        ec.initialize(new ECGenParameterSpec("secp384r1"));
        Assertions.assertEquals("EC", ec.generateKeyPair().getPublic().getAlgorithm());
        KeyPairGenerator dh = KeyPairGenerator.getInstance("DH", "JSLFIPS");
        dh.initialize(2048);
        Assertions.assertEquals("DH", dh.generateKeyPair().getPublic().getAlgorithm());
    }

    /**
     * Ed25519 and Ed448, and the generic `ED` generator.
     */
    @Test
    public void edwardsCurves()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("KeyPairGenerator", "ED25519") != null);
        String[] names = {"ED25519", "ED448", "ED"};
        String[] algorithms = {"Ed25519", "Ed448", "Ed25519"};
        for (int i = 0; i < names.length; i++)
        {
            Assertions.assertEquals(algorithms[i],
                    KeyPairGenerator.getInstance(names[i], "JSLFIPS").generateKeyPair().getPublic().getAlgorithm());
        }
    }

    /**
     * DSA: where the module refuses DSA key generation, as the 3.5.8 module does, `generateKeyPair` throws
     * `ProviderException` saying so. DSA keys made elsewhere can still be imported and used to verify.
     */
    @Test
    public void dsaKeyPairs()
            throws Exception
    {
        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA", "JSLFIPS");
        dsa.initialize(2048);
        try
        {
            Assertions.assertEquals("DSA", dsa.generateKeyPair().getPublic().getAlgorithm());
        }
        catch (ProviderException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("DSA key generation is not supported"), e.getMessage());
        }
    }

    /**
     * ML-DSA, ML-KEM and SLH-DSA, one generator per parameter set or the generic one initialised with the set.
     */
    @Test
    public void postQuantumKeyPairs()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("KeyPairGenerator", "ML-DSA-65") != null);
        String[] names = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192F",
                "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128F",
                "SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192F", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHAKE-256F"};
        for (String name : names)
        {
            Assertions.assertEquals(name,
                    KeyPairGenerator.getInstance(name, "JSLFIPS").generateKeyPair().getPublic().getAlgorithm());
        }
        KeyPairGenerator mldsa = KeyPairGenerator.getInstance("MLDSA", "JSLFIPS");
        mldsa.initialize(MLDSAParameterSpec.ml_dsa_87);
        KeyPairGenerator mlkem = KeyPairGenerator.getInstance("MLKEM", "JSLFIPS");
        mlkem.initialize(MLKEMParameterSpec.ml_kem_512);
        KeyPairGenerator slhdsa = KeyPairGenerator.getInstance("SLHDSA", "JSLFIPS");
        slhdsa.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f);
        Assertions.assertEquals("ML-DSA-87", mldsa.generateKeyPair().getPublic().getAlgorithm());
        Assertions.assertEquals("ML-KEM-512", mlkem.generateKeyPair().getPublic().getAlgorithm());
        Assertions.assertEquals("SLH-DSA-SHA2-128F", slhdsa.generateKeyPair().getPublic().getAlgorithm());
    }

    /**
     * The hybrid TLS groups the module serves.
     */
    @Test
    public void hybridKemGroups()
            throws Exception
    {
        Assumptions.assumeTrue(
                Security.getProvider("JSLFIPS").getService("KeyPairGenerator", "X25519MLKEM768") != null);
        for (String name : new String[]{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, "JSLFIPS").generateKeyPair();
            Assertions.assertTrue(name.equalsIgnoreCase(kp.getPublic().getAlgorithm()), name);
        }
    }

    /**
     * Operations inside the module draw randomness from the module's own DRBG and ignore a SecureRandom the
     * caller passes: two generators given identically seeded SecureRandoms still produce different keys.
     */
    @Test
    public void aCallerSecureRandomIsIgnored()
            throws Exception
    {
        SecureRandom r1 = SecureRandom.getInstance("SHA1PRNG");
        r1.setSeed(new byte[]{42});
        SecureRandom r2 = SecureRandom.getInstance("SHA1PRNG");
        r2.setSeed(new byte[]{42});
        KeyPairGenerator g1 = KeyPairGenerator.getInstance("EC", "JSLFIPS");
        g1.initialize(new ECGenParameterSpec("secp256r1"), r1);
        KeyPairGenerator g2 = KeyPairGenerator.getInstance("EC", "JSLFIPS");
        g2.initialize(new ECGenParameterSpec("secp256r1"), r2);
        Assertions.assertFalse(Arrays.equals(g1.generateKeyPair().getPublic().getEncoded(),
                g2.generateKeyPair().getPublic().getEncoded()));
    }
}
