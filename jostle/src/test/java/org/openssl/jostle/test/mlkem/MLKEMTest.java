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
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kts.KemSizes;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMPrivateKeySpec;
import org.openssl.jostle.jcajce.spec.MLKEMPublicKeySpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MLKEMTest
{
    /**
     * Class-level seeding random — used to derive each test's local
     * SHA1PRNG seed. Per CLAUDE.md: "cache one SecureRandom per test
     * class, not per @Test method."
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Per-test seeded random. The seed is logged on every call so a
     * flaky failure can be reproduced by re-running with the same
     * seed (per CLAUDE.md).
     */
    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static MLKEMParameterSpec[] joSpec = new MLKEMParameterSpec[]{
            MLKEMParameterSpec.ml_kem_512,
            MLKEMParameterSpec.ml_kem_768,
            MLKEMParameterSpec.ml_kem_1024,

    };

    @BeforeAll
    public static void before()
    {
        synchronized (JostleProvider.class)
        {
            if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
            {
                Security.addProvider(new JostleProvider());
            }


        }
    }

    @Test
    public void testIncorrectForcedType_KeyPairGenerator() throws Exception
    {
        //
        // Testing the KeyPairGenerator will enforce a fixed key type by
        // Creating it for one spec, but trying to initialize it with another.
        // Test that is rejects an incorrect initialization
        // Test that it accepts the correct initialization
        //

        List<MLKEMParameterSpec> specsGood = new ArrayList<MLKEMParameterSpec>(MLKEMParameterSpec.getParameterSpecs());


        for (int t = 0; t < specsGood.size(); t++)
        {
            MLKEMParameterSpec specGood = specsGood.get(t);
            MLKEMParameterSpec specBad = specsGood.get((t + 1) % specsGood.size()); // Off by one

            KeyPairGenerator keyFactory = KeyPairGenerator.getInstance(specGood.getName(), JostleProvider.PROVIDER_NAME);
            try
            {
                keyFactory.initialize(specBad);
                Assertions.fail();
            } catch (InvalidAlgorithmParameterException e)
            {
                Assertions.assertEquals(
                        String.format("expected %s but was supplied %s", specGood.getName(), specBad.getName()), e.getMessage());
            }

            // Does it actually work
            keyFactory.initialize(specGood);
        }

    }


    @Test
    public void testUnknownAlgorithm()
    {
        try
        {
            new MLKEMKeyPairGenerator("FISH");
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("unknown algorithm: FISH", e.getMessage());
        }
    }

    @Test
    public void basicJSLtoJSLTest() throws Exception
    {

        for (MLKEMParameterSpec spec : joSpec)
        {

            KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            keyFactory.initialize(spec);

            KeyPair keyPair = keyFactory.generateKeyPair();

            KeyGenerator encapsulator = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            encapsulator.init(KEMGenerateSpec.builder()
                    .withPublicKey(keyPair.getPublic())
                    .withKeySizeInBits(256)
                    .withAlgorithmName("AES").withNoKdf().build());

            SecretKeyWithEncapsulation secretKey = (SecretKeyWithEncapsulation) encapsulator.generateKey();


            KeyGenerator extractor = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            extractor.init(KEMExtractSpec.builder()
                    .withPrivate(keyPair.getPrivate())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(256)
                    .withEncapsulatedKey(secretKey.getEncapsulation())
                    .withNoKdf().build());

            SecretKeyWithEncapsulation recoveredKey = (SecretKeyWithEncapsulation) extractor.generateKey();

            Assertions.assertArrayEquals(secretKey.getEncoded(), recoveredKey.getEncoded());
            Assertions.assertArrayEquals(secretKey.getEncoded(), secretKey.getSecretKey().getEncoded());
            Assertions.assertArrayEquals(secretKey.getEncapsulation(), recoveredKey.getEncapsulation());
        }
    }



    @Test
    public void generateFromSeed() throws Exception
    {


        for (MLKEMParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("MLKEM", JostleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(spec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            MLKEMPrivateKey privateKey = (MLKEMPrivateKey) keyPair.getPrivate();

            MLKEMPrivateKey seedOnly1 = privateKey.getPrivateKey(true);
            MLKEMPrivateKey fullEncoding2 = privateKey.getPrivateKey(false);

            MLKEMPrivateKey fullEncodingFromSeedOnly3 = seedOnly1.getPrivateKey(false);
            MLKEMPrivateKey seedOnltFromFullEncoding4 = fullEncoding2.getPrivateKey(true);

            // Should be the full encoding
            Assertions.assertArrayEquals(
                    privateKey.getEncoded(),
                    fullEncoding2.getEncoded());
            Assertions.assertArrayEquals(
                    privateKey.getEncoded(),
                    fullEncodingFromSeedOnly3.getEncoded());

            // Seed encoding
            Assertions.assertArrayEquals(
                    seedOnly1.getEncoded(),
                    seedOnltFromFullEncoding4.getEncoded());

            Assertions.assertEquals(86, seedOnly1.getEncoded().length);
            Assertions.assertEquals(86, seedOnltFromFullEncoding4.getEncoded().length);


            Assertions.assertNotEquals(86, privateKey.getEncoded().length);
            Assertions.assertNotEquals(86, fullEncodingFromSeedOnly3.getEncoded().length);
        }
    }




    @Test
    public void testLoadRawKey() throws Exception
    {
        // Jostle->Jostle round trip: keygen with Jostle, extract long-form
        // raw bytes, rebuild via MLKEM*KeySpec / KeyFactory (which exercises
        // mlkem_decode_public_key / mlkem_decode_private_key success paths),
        // then encap/decap with the reconstructed keys.

        for (MLKEMParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLKEM", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicData = ((MLKEMPublicKey) keyPair.getPublic()).getPublicData();
            byte[] privateData = ((MLKEMPrivateKey) keyPair.getPrivate()).getPrivateData();

            MLKEMPublicKeySpec publicKeySpec = new MLKEMPublicKeySpec(spec, publicData);
            MLKEMPrivateKeySpec privateKeySpec = new MLKEMPrivateKeySpec(spec, privateData, publicData);

            KeyFactory keyFactory = KeyFactory.getInstance("MLKEM", JostleProvider.PROVIDER_NAME);
            PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
            PrivateKey privKey = keyFactory.generatePrivate(privateKeySpec);

            KeyGenerator encapsulator = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            encapsulator.init(KEMGenerateSpec.builder()
                    .withPublicKey(pubKey)
                    .withKeySizeInBits(256)
                    .withAlgorithmName("AES").withNoKdf().build());
            SecretKeyWithEncapsulation secretKey = (SecretKeyWithEncapsulation) encapsulator.generateKey();

            KeyGenerator extractor = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            extractor.init(KEMExtractSpec.builder()
                    .withPrivate(privKey)
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(256)
                    .withEncapsulatedKey(secretKey.getEncapsulation())
                    .withNoKdf().build());
            SecretKeyWithEncapsulation recoveredKey = (SecretKeyWithEncapsulation) extractor.generateKey();

            Assertions.assertArrayEquals(secretKey.getEncoded(), recoveredKey.getEncoded());
            Assertions.assertArrayEquals(secretKey.getEncapsulation(), recoveredKey.getEncapsulation());
        }
    }


    /**
     * Cross-spec parity guard: all three PQC {@code ParameterSpec.fromName}
     * methods must share one contract — {@code null} → NullPointerException,
     * an unknown name → IllegalArgumentException. Locks the consistency so a
     * future edit to one spec can't silently diverge from the other two.
     */
    @Test
    public void fromName_nullAndUnknown_contractAcrossPqcSpecs()
    {
        Assertions.assertThrows(NullPointerException.class, () -> MLKEMParameterSpec.fromName(null));
        Assertions.assertThrows(NullPointerException.class, () -> MLDSAParameterSpec.fromName(null));
        Assertions.assertThrows(NullPointerException.class, () -> SLHDSAParameterSpec.fromName(null));

        Assertions.assertThrows(IllegalArgumentException.class,
                () -> MLKEMParameterSpec.fromName("not-a-real-parameter-set"));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> MLDSAParameterSpec.fromName("not-a-real-parameter-set"));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> SLHDSAParameterSpec.fromName("not-a-real-parameter-set"));
    }


    /**
     * Per parameter set, the lengths the key getters and the KEM queries report equal FIPS 203's sizes and the memo
     * the reporting library keeps. Shared with the FIPS agreement test, which runs it against JSLFIPS.
     */
    public static void assertLengthsEqualTheMemo(Provider provider, MLKEMServiceNI ni) throws Exception
    {
        // FIPS 203 table 3: encapsulation key, decapsulation key, ciphertext; the seed is d || z, 64 bytes.
        int[][] sizes = {{800, 1632, 768}, {1184, 2400, 1088}, {1568, 3168, 1568}};
        String[] names = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
        for (int i = 0; i < names.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(names[i], provider).generateKeyPair();
            PKEYKeySpec spec = ((OSSLKey) kp.getPublic()).getSpec();
            String type = spec.getType().name();
            Assertions.assertEquals(sizes[i][0], ((MLKEMPublicKey) kp.getPublic()).getPublicData().length, names[i]);
            Assertions.assertEquals(sizes[i][1], ((MLKEMPrivateKey) kp.getPrivate()).getPrivateData().length,
                    names[i]);
            Assertions.assertEquals(64, ((MLKEMPrivateKey) kp.getPrivate()).getSeed().length, names[i]);
            Assertions.assertEquals(sizes[i][0], ni.keyLengthCache().get(type + "/PUBLIC"), names[i]);
            Assertions.assertEquals(sizes[i][1], ni.keyLengthCache().get(type + "/PRIVATE"), names[i]);
            Assertions.assertEquals(64, ni.keyLengthCache().get(type + "/SEED"), names[i]);

            Assertions.assertEquals(32, KemSizes.sharedSecretLength(spec, TestUtil.RNDSrc), names[i]);
            Assertions.assertEquals(sizes[i][2], KemSizes.ciphertextLength(spec, TestUtil.RNDSrc), names[i]);
            Assertions.assertEquals(32, spec.getSpecNI().secretLengthCache().get(spec.getType()), names[i]);
            Assertions.assertEquals(sizes[i][2], spec.getSpecNI().lengthCache().get(spec.getType()), names[i]);
        }
    }

    @Test
    public void keyAndKemLengthsEqualTheMemoPerSet() throws Exception
    {
        assertLengthsEqualTheMemo(Security.getProvider(JostleProvider.PROVIDER_NAME), NISelector.MLKEMServiceNI);
    }
}
