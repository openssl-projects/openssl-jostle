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

package org.openssl.jostle.test.mlkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/**
 * Regression coverage for <a href="https://github.com/openssl-projects/openssl-jostle/issues/34">GH issue #34</a>.
 *
 * <p>The issue: ML-KEM-768 (192-bit strength) and ML-KEM-1024 (256-bit
 * strength) keypair generation and encapsulation failed when the
 * caller didn't supply an explicit {@link java.security.SecureRandom}
 * with sufficient strength, because the JDK default DRBG only reports
 * 128 bits. The C-side RAND gate then refused to honour the strength
 * request and surfaced an {@code OpenSSLException}.
 *
 * <p>This test pins the no-explicit-SecureRandom code path for each of
 * the three ML-KEM variants and asserts it succeeds end-to-end:
 * keypair generation → encapsulation → decapsulation → shared-secret
 * agreement. If the fix regresses, the ML-KEM-768 / -1024 paths will
 * throw on the encap call (the exact stack trace from issue #34).
 */
public class MLKEMRandStrengthTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    // -----------------------------------------------------------------
    // KeyPairGenerator path — no SecureRandom passed to initialize()
    // -----------------------------------------------------------------

    @Test
    public void mlkem512_noExplicitRandom_keyPairGen() throws Exception
    {
        KeyPair kp = generateKeyPair(MLKEMParameterSpec.ml_kem_512);
        Assertions.assertNotNull(kp);
        Assertions.assertNotNull(kp.getPublic());
        Assertions.assertNotNull(kp.getPrivate());
    }

    @Test
    public void mlkem768_noExplicitRandom_keyPairGen() throws Exception
    {
        // The reproducer for GH issue #34 (keypair side).
        KeyPair kp = generateKeyPair(MLKEMParameterSpec.ml_kem_768);
        Assertions.assertNotNull(kp);
        Assertions.assertNotNull(kp.getPublic());
        Assertions.assertNotNull(kp.getPrivate());
    }

    @Test
    public void mlkem1024_noExplicitRandom_keyPairGen() throws Exception
    {
        // The reproducer for GH issue #34 (keypair side).
        KeyPair kp = generateKeyPair(MLKEMParameterSpec.ml_kem_1024);
        Assertions.assertNotNull(kp);
        Assertions.assertNotNull(kp.getPublic());
        Assertions.assertNotNull(kp.getPrivate());
    }


    // -----------------------------------------------------------------
    // KeyGenerator (encap/decap) path — the exact stack trace path in
    // GH issue #34, line 138 of MLKEMKeyGenerator.
    // -----------------------------------------------------------------

    @Test
    public void mlkem512_noExplicitRandom_encapDecap() throws Exception
    {
        encapDecapRoundTrip("ML-KEM-512", MLKEMParameterSpec.ml_kem_512);
    }

    @Test
    public void mlkem768_noExplicitRandom_encapDecap() throws Exception
    {
        // The exact reproducer from issue #34. With the JDK default
        // 128-bit DRBG and no explicit SecureRandom passed to init,
        // this previously failed at the encap call inside
        // MLKEMKeyGenerator.engineGenerateKey:138 with
        // "OpenSSL Error: ... rand up-call failed with code -97".
        encapDecapRoundTrip("ML-KEM-768", MLKEMParameterSpec.ml_kem_768);
    }

    @Test
    public void mlkem1024_noExplicitRandom_encapDecap() throws Exception
    {
        // The exact reproducer from issue #34 (256-bit strength case).
        encapDecapRoundTrip("ML-KEM-1024", MLKEMParameterSpec.ml_kem_1024);
    }


    // -----------------------------------------------------------------
    // Strength-bits helper
    // -----------------------------------------------------------------

    @Test
    public void mlkemParameterSpec_getRequiredStrengthBits()
    {
        Assertions.assertEquals(128, MLKEMParameterSpec.ml_kem_512.getRequiredStrengthBits());
        Assertions.assertEquals(192, MLKEMParameterSpec.ml_kem_768.getRequiredStrengthBits());
        Assertions.assertEquals(256, MLKEMParameterSpec.ml_kem_1024.getRequiredStrengthBits());
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------


    /**
     * Generate an ML-KEM keypair via the JCE surface with NO explicit
     * SecureRandom passed to init. This is the path that previously
     * failed for ML-KEM-768 / ML-KEM-1024 due to the 128-bit JDK
     * default DRBG.
     */
    private static KeyPair generateKeyPair(MLKEMParameterSpec spec) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(),
                JostleProvider.PROVIDER_NAME);
        // Note: passing only the spec, NO SecureRandom — this is the
        // reproducer trigger.
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    /**
     * Drive a full ML-KEM encap → decap round-trip via the JCE KEM
     * surface with NO explicit SecureRandom passed to init. Confirms
     * Alice and Bob agree on the shared secret.
     */
    private static void encapDecapRoundTrip(String alg, MLKEMParameterSpec spec) throws Exception
    {
        KeyPair kp = generateKeyPair(spec);

        // Encapsulation side — also driven without an explicit
        // SecureRandom; this is the exact path from the issue #34
        // stack trace.
        KeyGenerator kg = KeyGenerator.getInstance(alg, JostleProvider.PROVIDER_NAME);
        kg.init(KEMGenerateSpec.builder()
                .withPublicKey(kp.getPublic())
                .withAlgorithmName("AES")
                .withKeySizeInBits(256)
                .build());
        SecretKey encapKey = kg.generateKey();

        Assertions.assertNotNull(encapKey);
        byte[] encapBytes = encapKey.getEncoded();
        Assertions.assertTrue(encapBytes.length > 0, alg + ": empty encapsulated key");

        // Decapsulation side.
        KeyGenerator decapKg = KeyGenerator.getInstance(alg, JostleProvider.PROVIDER_NAME);
        byte[] wrapped = ((org.openssl.jostle.jcajce.SecretKeyWithEncapsulation) encapKey).getEncapsulation();
        decapKg.init(KEMExtractSpec.builder()
                .withPrivate(kp.getPrivate())
                .withAlgorithmName("AES")
                .withKeySizeInBits(256)
                .withEncapsulatedKey(wrapped)
                .build());
        SecretKey decapKey = decapKg.generateKey();

        Assertions.assertNotNull(decapKey);
        Assertions.assertTrue(Arrays.areEqual(encapKey.getEncoded(), decapKey.getEncoded()),
                alg + ": Alice and Bob derived different shared secrets");
    }
}
