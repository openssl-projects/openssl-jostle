package org.openssl.jostle.test.slhdsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SLHDSATest
{

    private static SecureRandom random = new SecureRandom();

    private static SLHDSAParameterSpec[] joSpec = new SLHDSAParameterSpec[]{
            SLHDSAParameterSpec.slh_dsa_sha2_128f,
            SLHDSAParameterSpec.slh_dsa_sha2_128s,
            SLHDSAParameterSpec.slh_dsa_sha2_192f,
            SLHDSAParameterSpec.slh_dsa_sha2_192s,
            SLHDSAParameterSpec.slh_dsa_sha2_256f,
            SLHDSAParameterSpec.slh_dsa_sha2_256s,

            SLHDSAParameterSpec.slh_dsa_shake_128f,
            SLHDSAParameterSpec.slh_dsa_shake_128s,
            SLHDSAParameterSpec.slh_dsa_shake_192f,
            SLHDSAParameterSpec.slh_dsa_shake_192s,
            SLHDSAParameterSpec.slh_dsa_shake_256f,
            SLHDSAParameterSpec.slh_dsa_shake_256s,

    };

    private static org.bouncycastle.jcajce.spec.SLHDSAParameterSpec[] bcSpec = new org.bouncycastle.jcajce.spec.SLHDSAParameterSpec[]{
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_sha2_128f,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_sha2_128s,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_sha2_192f,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_sha2_192s,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_sha2_256f,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_sha2_256s,

            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_shake_128f,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_shake_128s,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_shake_192f,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_shake_192s,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_shake_256f,
            org.bouncycastle.jcajce.spec.SLHDSAParameterSpec.slh_dsa_shake_256s,
    };

    private static Map<org.bouncycastle.jcajce.spec.SLHDSAParameterSpec, SLHDSAParameterSpec> bcToJostle = new HashMap<>();
    private static Map<SLHDSAParameterSpec, org.bouncycastle.jcajce.spec.SLHDSAParameterSpec> jostleToBc = new HashMap<>();

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

        List<SLHDSAParameterSpec> specsGood = new ArrayList<SLHDSAParameterSpec>(SLHDSAParameterSpec.getParameterSpecs());


        for (int t = 0; t < specsGood.size(); t++)
        {
            SLHDSAParameterSpec specGood = specsGood.get(t);
            SLHDSAParameterSpec specBad = specsGood.get((t + 1) % specsGood.size()); // Off by one

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
            new SLHDSAKeyPairGenerator("FISH");
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("unknown algorithm: FISH", e.getMessage());
        }
    }


    @Test
    public void testUnknownParameterSpec() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        try
        {
            signature.setParameter(new AlgorithmParameterSpec()
            {
            });
            Assertions.fail();
        } catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("unknown AlgorithmParameterSpec", e.getMessage());
        }

        Signature verifier = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        try
        {
            signature.setParameter(new AlgorithmParameterSpec()
            {
            });
            Assertions.fail();
        } catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("unknown AlgorithmParameterSpec", e.getMessage());
        }

    }


    @Test
    public void testInitVerifyWrongClass() throws Exception
    {
        PublicKey publicKey = new PublicKey()
        {
            @Override
            public String getAlgorithm()
            {
                return "Cthulu";
            }

            @Override
            public String getFormat()
            {
                return "Wraaa";
            }

            @Override
            public byte[] getEncoded()
            {
                return Hex.decode("4f6e6c7920416d696761206d61646520697420706f737369626c65");
            }
        };

        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signature.initVerify(publicKey);
            Assertions.fail();
        } catch (InvalidKeyException e)
        {
            Assertions.assertEquals("expected only SLHDSAPublicKey", e.getMessage());
        }
    }

    @Test
    public void testInitSignWrongClass() throws Exception
    {
        PrivateKey publicKey = new PrivateKey()
        {
            @Override
            public String getAlgorithm()
            {
                return "Cthulu";
            }

            @Override
            public String getFormat()
            {
                return "Wraaa";
            }

            @Override
            public byte[] getEncoded()
            {
                return Hex.decode("466172206f757421");
            }
        };

        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signature.initSign(publicKey);
            Assertions.fail();
        } catch (InvalidKeyException e)
        {
            Assertions.assertEquals("expected only SLHDSAPrivateKey", e.getMessage());
        }
    }


    @Test
    public void testSignVerifyWithReuse() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = new byte[1025];
        random.nextBytes(message);


        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());

        signature.update(message);
        byte[] firstSignature = signature.sign();

        //
        // Signer should have reset
        //
        signature.update(message);
        byte[] secondSignature = signature.sign();

        //
        // Set up verifier, it should verify second signature
        //
        Signature verifier = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(secondSignature));

        //
        // Verifier should have reset
        //
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(firstSignature));

        message[0] ^= 1;
        verifier.update(message);
        Assertions.assertFalse(verifier.verify(firstSignature));

    }


    @Test
    public void testSignVerifyWithContextAndReuse() throws Exception
    {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx = new byte[129];
        random.nextBytes(ctx);

        byte[] message = new byte[1025];
        random.nextBytes(message);


        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(new ContextParameterSpec(ctx));

        signature.update(message);
        byte[] firstSignature = signature.sign();

        //
        // Signer should have reset
        //
        signature.update(message);
        byte[] secondSignature = signature.sign();

        //
        // Set up verifier, it should verify second signature
        //
        Signature verifier = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.setParameter(new ContextParameterSpec(ctx));
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(secondSignature));

        //
        // Verifier should have reset
        //
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(firstSignature));


        // Vandalise message
        message[0] ^= 1;
        verifier.update(message);
        Assertions.assertFalse(verifier.verify(firstSignature));
    }


    @Test
    public void testSingleByteUpdateSign() throws Exception
    {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("SLH-DSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

        byte[] message = new byte[1025];
        random.nextBytes(message);

        Signature signatureJo = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        signatureJo.initSign(keyPair.getPrivate());
        signatureJo.update(message);
        byte[] signatureBytes = signatureJo.sign();


        for (int i = 0; i < message.length; i++)
        {
            signatureJo.update(message[i]);
        }

        byte[] sigBytesSingleByteUpdate = signatureJo.sign();

        // -- you cannot compare signatures directly..

        //
        // Verify both signature against BC
        //
        Signature verifierBc = Signature.getInstance("SLH-DSA", "BC");
        verifierBc.initVerify(pubKeyBC);
        verifierBc.update(message);
        Assertions.assertTrue(verifierBc.verify(signatureBytes));

        verifierBc.update(message);
        Assertions.assertTrue(verifierBc.verify(sigBytesSingleByteUpdate));

    }


    @Test
    public void testSingleByteUpdateVerify() throws Exception
    {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("SLH-DSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));


        byte[] message = new byte[1025];
        random.nextBytes(message);


        Signature signatureBc = Signature.getInstance("SLH-DSA", "BC");
        signatureBc.initSign(privKeyBC);
        signatureBc.update(message);
        byte[] signatureBytesBc = signatureBc.sign();


        Signature verifierJo = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        verifierJo.initVerify(keyPair.getPublic());

        // whole message in one
        verifierJo.update(message);
        Assertions.assertTrue(verifierJo.verify(signatureBytesBc));

        // Pass in each byte
        for (int i = 0; i < message.length; i++)
        {
            verifierJo.update(message[i]);
        }
        Assertions.assertTrue(verifierJo.verify(signatureBytesBc));

        // Damage message
        message[0] ^= 1;

        // Should fail verification
        verifierJo.update(message);
        Assertions.assertFalse(verifierJo.verify(signatureBytesBc));

        for (int i = 0; i < message.length; i++)
        {
            verifierJo.update(message[i]);
        }
        Assertions.assertFalse(verifierJo.verify(signatureBytesBc));
    }


    @Test
    public void testKeyGen() throws Exception
    {

        for (SLHDSAParameterSpec spec : joSpec)
        {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            //
            // Verify encoded key can be handled by BC and is usable
            //
            KeyFactory factory = KeyFactory.getInstance("SLH-DSA", "BC");
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

            byte[] msg = new byte[65];

            random.nextBytes(msg);

            Signature signatureBC = Signature.getInstance("SLH-DSA", "BC");
            signatureBC.initSign(privKeyBC);
            signatureBC.update(msg);
            byte[] signature = signatureBC.sign();

            Signature verifierBC = Signature.getInstance("SLH-DSA", "BC");
            verifierBC.initVerify(pubKeyBC);
            verifierBC.update(msg);

            Assertions.assertTrue(verifierBC.verify(signature));
        }
    }

    @Test
    public void testKeyRecovery() throws Exception
    {
        for (org.bouncycastle.jcajce.spec.SLHDSAParameterSpec spec : bcSpec)
        {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", "BC");
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKeyX509 = keyPair.getPublic().getEncoded();
            byte[] privateKeyX509 = keyPair.getPrivate().getEncoded();


            KeyFactory jostleFactory = KeyFactory.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
            PrivateKey privateKey = jostleFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyX509));
            PublicKey publicKey = jostleFactory.generatePublic(new X509EncodedKeySpec(publicKeyX509));


            byte[] msg = new byte[65];
            random.nextBytes(msg);

            Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
            signature.initSign(privateKey);
            signature.update(msg);
            byte[] signatureBytes = signature.sign();

            Signature verifier = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
            verifier.initVerify(publicKey);
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(signatureBytes));
        }

    }


    @Test
    public void testSetParamsAfterUpdateFails() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());

        // Is ok!
        signature.setParameter(new ContextParameterSpec(new byte[10]));

        signature.update("Hello World".getBytes());
        try
        {
            signature.setParameter(new ContextParameterSpec(new byte[10]));
            Assertions.fail();
        } catch (ProviderException e)
        {
            Assertions.assertEquals("cannot call setParameter in the middle of update", e.getMessage());
        }

        byte[] sig = signature.sign();

        // Is ok too!
        signature.setParameter(new ContextParameterSpec(new byte[10]));
    }


    @Test
    public void testChangeContextAfterTakingSignature() throws Exception
    {
        //
        // Automatic reuse of the key but change the context before taking
        // the second signatur


        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx1 = new byte[129];
        random.nextBytes(ctx1);

        byte[] ctx2 = new byte[65];
        random.nextBytes(ctx2);

        byte[] message = new byte[1025];
        random.nextBytes(message);

        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(new ContextParameterSpec(ctx1));

        signature.update(message);
        byte[] firstSignature = signature.sign();

        //
        // Signer should have reset
        //
        signature.setParameter(new ContextParameterSpec(ctx2));
        signature.update(message);
        byte[] secondSignature = signature.sign();

        //
        // Set up verifier, it should verify second signature
        //
        Signature verifier = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.setParameter(new ContextParameterSpec(ctx2));
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(secondSignature));

        //
        // Verifier should have reset
        //
        verifier.setParameter(new ContextParameterSpec(ctx1));
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(firstSignature));


        // Vandalise message
        // Sanity check it will fail.
        message[0] ^= 1;
        verifier.update(message);
        Assertions.assertFalse(verifier.verify(firstSignature));


    }

    @Test
    public void testChangeContextToNullAfterTakingSignature() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx1 = new byte[129];
        random.nextBytes(ctx1);

        byte[] message = new byte[1025];
        random.nextBytes(message);

        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(new ContextParameterSpec(ctx1));

        signature.update(message);
        byte[] firstSignature = signature.sign();

        //
        // Signer should have reset
        //
        signature.setParameter(null);
        signature.update(message);
        byte[] secondSignature = signature.sign();

        //
        // Set up verifier, it should verify second signature
        //
        Signature verifier = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.setParameter(null);
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(secondSignature));

        //
        // Verifier should have reset
        //
        verifier.setParameter(new ContextParameterSpec(ctx1));
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(firstSignature));


        // Vandalise message
        // Sanity check it will fail.
        message[0] ^= 1;
        verifier.update(message);
        Assertions.assertFalse(verifier.verify(firstSignature));


    }

    @Test
    public void testInitSignWithForcedKeySpec() throws Exception
    {

        //
        // Create a signature instance with a fixed key spec
        // Then try to initialise it with a different spec
        //

        List<SLHDSAParameterSpec> specsGood = new ArrayList<SLHDSAParameterSpec>(SLHDSAParameterSpec.getParameterSpecs());


        for (int t = 0; t < specsGood.size(); t++)
        {
            SLHDSAParameterSpec specGood = specsGood.get(t);
            SLHDSAParameterSpec specBad = specsGood.get((t + 1) % specsGood.size()); // Off by one

            KeyPairGenerator keyGeneratorWrong = KeyPairGenerator.getInstance("SLH-DSA", JostleProvider.PROVIDER_NAME);
            keyGeneratorWrong.initialize(specBad);
            KeyPair keyPairWrongSpec = keyGeneratorWrong.generateKeyPair();

            KeyPairGenerator keyGeneratorGood = KeyPairGenerator.getInstance("SLH-DSA", JostleProvider.PROVIDER_NAME);
            keyGeneratorGood.initialize(specGood);
            KeyPair keyPairGoodSpec = keyGeneratorGood.generateKeyPair();

            Signature signature = Signature.getInstance(specGood.getName(), JostleProvider.PROVIDER_NAME);
            try
            {
                signature.initSign(keyPairWrongSpec.getPrivate());
                Assertions.fail();
            } catch (InvalidKeyException e)
            {
                Assertions.assertEquals(
                        String.format("required %s key type but got %s", specGood.getName(), specBad.getName()), e.getMessage());
            }

            // Does it actually work
            signature.initSign(keyPairGoodSpec.getPrivate());
        }

    }

    @Test
    public void testInitVerifyWithForcedKeySpec() throws Exception
    {

        //
        // Create a verifier instance with a fixed key spec
        // Then try to initialise it with a different spec
        //

        List<SLHDSAParameterSpec> specsGood = new ArrayList<SLHDSAParameterSpec>(SLHDSAParameterSpec.getParameterSpecs());


        for (int t = 0; t < specsGood.size(); t++)
        {
            SLHDSAParameterSpec specGood = specsGood.get(t);
            SLHDSAParameterSpec specBad = specsGood.get((t + 1) % specsGood.size()); // Off by one

            KeyPairGenerator keyGeneratorWrong = KeyPairGenerator.getInstance("SLH-DSA", JostleProvider.PROVIDER_NAME);
            keyGeneratorWrong.initialize(specBad);
            KeyPair keyPairWrongSpec = keyGeneratorWrong.generateKeyPair();

            KeyPairGenerator keyGeneratorGood = KeyPairGenerator.getInstance("SLH-DSA", JostleProvider.PROVIDER_NAME);
            keyGeneratorGood.initialize(specGood);
            KeyPair keyPairGoodSpec = keyGeneratorGood.generateKeyPair();

            Signature verifier = Signature.getInstance(specGood.getName(), JostleProvider.PROVIDER_NAME);
            try
            {
                verifier.initVerify(keyPairWrongSpec.getPublic());
                Assertions.fail();
            } catch (InvalidKeyException e)
            {
                Assertions.assertEquals(
                        String.format("required %s key type but got %s", specGood.getName(), specBad.getName()), e.getMessage());
            }

            // Does it actually work
            verifier.initVerify(keyPairGoodSpec.getPublic());
        }

    }


    @Test
    public void nullSignatureOnVerifyFails() throws Exception
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();


        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        signature.initVerify(keyPair.getPublic());
        try
        {
            signature.verify(null);
            Assertions.fail();

        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("sig is null", e.getMessage());
        }
    }

    @Test
    public void nullMessageOnUpdateFails() throws Exception
    {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();


        Signature signature = Signature.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);

        //
        // When initialized for sign
        //
        signature.initSign(keyPair.getPrivate());
        try
        {
            signature.update(null, 0, 99);
            Assertions.fail();

        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("data is null", e.getMessage());
        }

        //
        // When initialized for verify
        //
        signature.initVerify(keyPair.getPublic());
        try
        {
            signature.update(null, 0, 99);
            Assertions.fail();

        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("data is null", e.getMessage());
        }

    }

    @Test
    public void testDeterministic() throws Exception
    {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SLH-DSA", JostleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();


        Signature signature = Signature.getInstance("DET-SLH-DSA-PURE", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());

        byte[] messageBytes = new byte[65];
        random.nextBytes(messageBytes);
        signature.update(messageBytes, 0, messageBytes.length);
        byte[] signatureByte1 = signature.sign();

        signature.update(messageBytes, 0, messageBytes.length);
        byte[] signatureBytes2 = signature.sign();

        Assertions.assertArrayEquals(signatureByte1, signatureBytes2);

        signature = Signature.getInstance("SLH-DSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.update(messageBytes, 0, messageBytes.length);
        byte[] signatureBytes3 = signature.sign();

        Assertions.assertFalse(Arrays.areEqual(signatureByte1, signatureBytes3));

    }


    @Test
    public void testNondeterministicByDefault() throws Exception
    {
        for (SLHDSAParameterSpec spec : SLHDSAParameterSpec.getParameterSpecs())
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(spec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            byte[] messageBytes = new byte[65];
            random.nextBytes(messageBytes);

            Signature signature = Signature.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME);
            signature.initSign(keyPair.getPrivate());
            signature.update(messageBytes, 0, messageBytes.length);
            byte[] signatureByte1 = signature.sign();

            signature.update(messageBytes, 0, messageBytes.length);
            byte[] signatureBytes2 = signature.sign();

            Assertions.assertFalse(Arrays.areEqual(signatureByte1, signatureBytes2));

        }
    }


    private void crossProviderVerification(String algoName, SLHDSAParameterSpec specJostle, org.bouncycastle.jcajce.spec.SLHDSAParameterSpec specBC) throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(specJostle);
        KeyPair keyPair = keyGen.generateKeyPair();


        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("SLH-DSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

        byte[] msg = new byte[2049];
        random.nextBytes(msg);

        Signature bcSigner = Signature.getInstance(algoName, "BC");
        bcSigner.initSign(privKeyBC);
        bcSigner.update(msg);
        byte[] bcSignature = bcSigner.sign();


        Signature signatureJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        signatureJostle.initSign(keyPair.getPrivate());
        signatureJostle.update(msg);
        byte[] jostleSignature = signatureJostle.sign();


        // BC verifies jostle
        Signature bcVerifier = Signature.getInstance(algoName, "BC");
        bcVerifier.initVerify(pubKeyBC);
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(jostleSignature));


        byte[] vandalised = Arrays.clone(jostleSignature);
        vandalised[1] ^= 1;
        bcVerifier = Signature.getInstance(algoName, "BC");
        bcVerifier.initVerify(pubKeyBC);
        bcVerifier.update(msg);
        Assertions.assertFalse(bcVerifier.verify(vandalised));


        // Jostle verifies BC
        Signature verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        verifierJostle.initVerify(keyPair.getPublic());
        verifierJostle.update(msg);
        Assertions.assertTrue(verifierJostle.verify(bcSignature));

        vandalised = Arrays.clone(bcSignature);
        vandalised[0] ^= 1;
        verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        verifierJostle.initVerify(keyPair.getPublic());
        verifierJostle.update(msg);
        Assertions.assertFalse(verifierJostle.verify(vandalised));


    }

    private void crossProviderVerificationWithContext(String algoName, SLHDSAParameterSpec specJostle, org.bouncycastle.jcajce.spec.SLHDSAParameterSpec specBC, byte[] ctx) throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(specJostle);
        KeyPair keyPair = keyGen.generateKeyPair();


        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("SLH-DSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));


        byte[] msg = new byte[2049];
        random.nextBytes(msg);

        Signature bcSigner = Signature.getInstance(algoName, "BC");
        bcSigner.initSign(privKeyBC);
        bcSigner.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(ctx));
        bcSigner.update(msg);
        byte[] bcSignature = bcSigner.sign();


        Signature signatureJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        signatureJostle.initSign(keyPair.getPrivate());
        signatureJostle.setParameter(new ContextParameterSpec(ctx));
        signatureJostle.update(msg);
        byte[] jostleSignature = signatureJostle.sign();


        // BC verifies jostle
        Signature bcVerifier = Signature.getInstance(algoName, "BC");
        bcVerifier.initVerify(pubKeyBC);
        bcVerifier.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(ctx));
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(jostleSignature));


        // Vandalise context and check for verification failure.
        byte[] vandalised = Arrays.clone(ctx);
        if (vandalised.length == 0)
        {
            vandalised = new byte[]{1};
        }
        vandalised[0] ^= 1;


        bcVerifier = Signature.getInstance(algoName, "BC");
        bcVerifier.initVerify(pubKeyBC);
        bcVerifier.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(vandalised));
        bcVerifier.update(msg);
        Assertions.assertFalse(bcVerifier.verify(jostleSignature));


        // Jostle verifies BC
        Signature verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        verifierJostle.initVerify(keyPair.getPublic());
        verifierJostle.setParameter(new ContextParameterSpec(ctx));
        verifierJostle.update(msg);
        Assertions.assertTrue(verifierJostle.verify(bcSignature));


        // Vandalise context and check for verification failure
        vandalised = Arrays.clone(ctx);
        if (vandalised.length == 0)
        {
            vandalised = new byte[]{1};
        } else
        {
            vandalised[0] ^= 1;
        }
        verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        verifierJostle.initVerify(keyPair.getPublic());
        verifierJostle.setParameter(new ContextParameterSpec(vandalised));
        verifierJostle.update(msg);
        Assertions.assertFalse(verifierJostle.verify(bcSignature));
    }


    @Test
    public void testSLHDSASignature() throws Exception
    {

        for (int t = 0; t < joSpec.length; t++)
        {
            crossProviderVerification("SLH-DSA", joSpec[t], bcSpec[t]);
        }


        for (int ctxLen : new int[]{0, 1, 255})
        {
            byte[] ctx = new byte[ctxLen];
            random.nextBytes(ctx);

            for (int t = 0; t < joSpec.length; t++)
            {
                crossProviderVerificationWithContext("SLH-DSA", joSpec[t], bcSpec[t], ctx);
            }
        }
    }

    @Test
    public void keyFactoryByNameTest() throws Exception
    {


        String[] names = SLHDSAParameterSpec.getParameterNames().toArray(new String[0]);


        for (int t = 0; t < names.length; t++)
        {
            String name = names[t];

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            {
                KeyFactory keyFactory = KeyFactory.getInstance(name, JostleProvider.PROVIDER_NAME);
                PublicKey pubK = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
                PrivateKey privK = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

                Assertions.assertTrue(name.equalsIgnoreCase(pubK.getAlgorithm()));
                Assertions.assertTrue(name.equalsIgnoreCase(privK.getAlgorithm()));
            }

            //
            // Check it will actually fail
            //

            {
                String failingName = names[(t + 1) % names.length];

                try
                {
                    KeyFactory keyFactory = KeyFactory.getInstance(failingName, JostleProvider.PROVIDER_NAME);
                    keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

                    Assertions.fail();
                } catch (InvalidKeySpecException ikse)
                {
                    Assertions.assertEquals("expected " + failingName + " but got " + name, ikse.getMessage());
                }

            }

        }


    }

}
