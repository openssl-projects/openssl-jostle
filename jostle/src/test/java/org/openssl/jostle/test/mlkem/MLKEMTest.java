package org.openssl.jostle.test.mlkem;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MLKEMTest
{
    private static SecureRandom random = new SecureRandom();

    private static MLKEMParameterSpec[] joSpec = new MLKEMParameterSpec[]{
            MLKEMParameterSpec.ml_kem_512,
            MLKEMParameterSpec.ml_kem_768,
            MLKEMParameterSpec.ml_kem_1024,

    };

    private static org.bouncycastle.jcajce.spec.MLKEMParameterSpec[] bcSpec = new org.bouncycastle.jcajce.spec.MLKEMParameterSpec[]{
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_512,
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_768,
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_1024,
    };

    private static Map<org.bouncycastle.jcajce.spec.MLKEMParameterSpec, MLKEMParameterSpec> bcToJostle = new HashMap<>();
    private static Map<MLKEMParameterSpec, org.bouncycastle.jcajce.spec.MLKEMParameterSpec> jostleToBc = new HashMap<>();

    static
    {
        for (int i = 0; i < joSpec.length; i++)
        {
            bcToJostle.put(bcSpec[i], joSpec[i]);
            jostleToBc.put(joSpec[i], bcSpec[i]);
        }
    }

    @BeforeAll
    public static void before()
    {
        synchronized (JostleProvider.class)
        {
            if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
            {
                Security.addProvider(new JostleProvider());
            }

            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            {
                Security.addProvider(new BouncyCastleProvider());
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
                    .withAlgorithmName("AES").build());

            SecretKeyWithEncapsulation secretKey = (SecretKeyWithEncapsulation) encapsulator.generateKey();


            KeyGenerator extractor = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            extractor.init(KEMExtractSpec.builder()
                    .withPrivate(keyPair.getPrivate())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(256)
                    .withEncapsulatedKey(secretKey.getEncapsulation())
                    .build());

            SecretKeyWithEncapsulation recoveredKey = (SecretKeyWithEncapsulation) extractor.generateKey();

            Assertions.assertArrayEquals(secretKey.getSecretKey().getEncoded(), recoveredKey.getSecretKey().getEncoded());
            Assertions.assertArrayEquals(secretKey.getEncapsulation(), recoveredKey.getEncapsulation());
        }
    }


    @Test
    public void testKeyExchangeJSLToBC() throws Exception
    {
        for (int i = 0; i < joSpec.length; i++)
        {

            //
            // BC receiver
            //
            KeyPairGenerator bcGen = KeyPairGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            bcGen.initialize(bcSpec[i]);
            KeyPair receiverKeyPair = bcGen.generateKeyPair();


            //
            // Use JSL to reconstitute encoded BC key and then encapsulate a key
            //
            KeyFactory joKeyFactory = KeyFactory.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            PublicKey receiverRecoveredPublicKey = joKeyFactory.generatePublic(new X509EncodedKeySpec(receiverKeyPair.getPublic().getEncoded()));

            KeyGenerator joKeyGenerator = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            joKeyGenerator.init(KEMGenerateSpec.builder()
                    .withKeySizeInBits(256)
                    .withPublicKey(receiverRecoveredPublicKey)
                    .withAlgorithmName("AES")
                    .build()
            );
            SecretKeyWithEncapsulation encapsulation = (SecretKeyWithEncapsulation) joKeyGenerator.generateKey();


            //
            // Use BC to decapsulate the key
            //
            KeyGenerator serverKeyFactory = KeyGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            serverKeyFactory.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder(receiverKeyPair.getPrivate(), encapsulation.getEncapsulation(), "AES", 256)
                    .withKdfAlgorithm(null)
                    .build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation decapsulatedKey = (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) serverKeyFactory.generateKey();

            Assertions.assertArrayEquals(encapsulation.getEncoded(), decapsulatedKey.getEncoded());
            Assertions.assertArrayEquals(encapsulation.getEncapsulation(), decapsulatedKey.getEncapsulation());

        }
    }

    @Test
    public void testKeyExchangeBCToJSL() throws Exception
    {
        for (int i = 0; i < joSpec.length; i++)
        {

            //
            // JSL receiver
            //
            KeyPairGenerator bcGen = KeyPairGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            bcGen.initialize(joSpec[i]);
            KeyPair receiverKeyPair = bcGen.generateKeyPair();


            //
            // Use BC to encapsulate the key, verify BC can reconstitute and encoded public key from JSL
            //
            KeyFactory joKeyFactory = KeyFactory.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey receiverRecoveredPublicKey = joKeyFactory.generatePublic(new X509EncodedKeySpec(receiverKeyPair.getPublic().getEncoded()));

            KeyGenerator joKeyGenerator = KeyGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            joKeyGenerator.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(receiverRecoveredPublicKey, "AES", 256)
                    .withKdfAlgorithm(null)
                    .build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation encapsulation = (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) joKeyGenerator.generateKey();


            //
            // Use JSL to decapsulate the key
            //
            KeyGenerator serverKeyFactory = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            serverKeyFactory.init(KEMExtractSpec.builder()
                    .withEncapsulatedKey(encapsulation.getEncapsulation())
                    .withAlgorithmName("AES")
                    .withPrivate(receiverKeyPair.getPrivate())
                    .withKeySizeInBits(256).build()
            );
            SecretKeyWithEncapsulation decapsulatedKey = (SecretKeyWithEncapsulation) serverKeyFactory.generateKey();

            Assertions.assertArrayEquals(encapsulation.getEncoded(), decapsulatedKey.getEncoded());
            Assertions.assertArrayEquals(encapsulation.getEncapsulation(), decapsulatedKey.getEncapsulation());


            //
            // Vandalise encapsulation must fail
            //

            byte[] vandalised = decapsulatedKey.getEncapsulation();
            vandalised[0] ^= 1;
            serverKeyFactory.init(KEMExtractSpec.builder()
                    .withEncapsulatedKey(vandalised)
                    .withAlgorithmName("AES")
                    .withPrivate(receiverKeyPair.getPrivate())
                    .withKeySizeInBits(256).build()
            );
            SecretKeyWithEncapsulation vandalisedDecapsulatedKey = (SecretKeyWithEncapsulation) serverKeyFactory.generateKey();
            Assertions.assertFalse(Arrays.areEqual(encapsulation.getEncoded(), vandalisedDecapsulatedKey.getEncoded()));

        }
    }




}
