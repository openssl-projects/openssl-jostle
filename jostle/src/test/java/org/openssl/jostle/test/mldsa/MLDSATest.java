package org.openssl.jostle.test.mldsa;


import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAKeyPairGeneratorImpl;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAPrivateKeySpec;
import org.openssl.jostle.jcajce.spec.MLDSAPublicKeySpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.MLDSAProxyPrivateKey;
import org.openssl.jostle.util.Strings;
import org.openssl.jostle.util.encoders.Hex;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class MLDSATest
{

    private static SecureRandom random = new SecureRandom();

    private static MLDSAParameterSpec[] joSpec = new MLDSAParameterSpec[]{
            MLDSAParameterSpec.ml_dsa_44,
            MLDSAParameterSpec.ml_dsa_65,
            MLDSAParameterSpec.ml_dsa_87,

    };

    private static org.bouncycastle.jcajce.spec.MLDSAParameterSpec[] bcSpec = new org.bouncycastle.jcajce.spec.MLDSAParameterSpec[]{
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44,
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65,
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87,
    };

    private static Map<org.bouncycastle.jcajce.spec.MLDSAParameterSpec, MLDSAParameterSpec> bcToJostle = new HashMap<>();
    private static Map<MLDSAParameterSpec, org.bouncycastle.jcajce.spec.MLDSAParameterSpec> jostleToBc = new HashMap<>();

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
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("ML-DSA-44", JostleProvider.PROVIDER_NAME);
        try
        {
            keyFactory.initialize(MLDSAParameterSpec.ml_dsa_65);
            Assertions.fail();
        } catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("expected ML_DSA_44 but was supplied ML_DSA_65", e.getMessage());
        }
        keyFactory.initialize(MLDSAParameterSpec.ml_dsa_44);

        keyFactory = KeyPairGenerator.getInstance("ML-DSA-65", JostleProvider.PROVIDER_NAME);
        try
        {
            keyFactory.initialize(MLDSAParameterSpec.ml_dsa_87);
            Assertions.fail();
        } catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("expected ML_DSA_65 but was supplied ML_DSA_87", e.getMessage());
        }
        keyFactory.initialize(MLDSAParameterSpec.ml_dsa_65);

        keyFactory = KeyPairGenerator.getInstance("ML-DSA-87", JostleProvider.PROVIDER_NAME);
        try
        {
            keyFactory.initialize(MLDSAParameterSpec.ml_dsa_44);
            Assertions.fail();
        } catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("expected ML_DSA_87 but was supplied ML_DSA_44", e.getMessage());
        }
        keyFactory.initialize(MLDSAParameterSpec.ml_dsa_87);

        try
        {
            keyFactory.initialize(new AlgorithmParameterSpec()
            {
            });
            Assertions.fail();
        } catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("only MLDSAParameterSpec is supported", e.getMessage());
        }
    }

    @Test
    public void testUnknownAlgorithm()
    {
        try
        {
            new MLDSAKeyPairGeneratorImpl("FISH");
            Assertions.fail();
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("unknown algorithm: FISH", e.getMessage());
        }
    }


    @Test
    public void testCustomParameterSpec() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();


        AlgorithmParameterSpec customSpec = new TestAlgorithmParameterSpec();


        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(customSpec);

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

        Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
    public void testUnknownParameterSpec() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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

        Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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

        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signature.initVerify(publicKey);
            Assertions.fail();
        } catch (InvalidKeyException e)
        {
            Assertions.assertEquals("expected only MLDSAPublicKey", e.getMessage());
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

        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signature.initSign(publicKey);
            Assertions.fail();
        } catch (InvalidKeyException e)
        {
            Assertions.assertEquals("expected only MLDSAPrivateKey", e.getMessage());
        }
    }


    @Test
    public void testSignVerifyWithReuse() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = new byte[1025];
        random.nextBytes(message);


        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
        Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx = new byte[129];
        random.nextBytes(ctx);

        byte[] message = new byte[1025];
        random.nextBytes(message);


        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
        Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
    public void testSignVerifyWithCustomContextAndReuse() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx = new byte[129];
        random.nextBytes(ctx);

        byte[] message = new byte[1025];
        random.nextBytes(message);


        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(new TestAlgorithmParameterSpec(ctx));

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
        Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.setParameter(new TestAlgorithmParameterSpec(ctx));
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
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

        byte[] message = new byte[1025];
        random.nextBytes(message);

        Signature signatureJo = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
        Signature verifierBc = Signature.getInstance("MLDSA", "BC");
        verifierBc.initVerify(pubKeyBC);
        verifierBc.update(message);
        Assertions.assertTrue(verifierBc.verify(signatureBytes));

        verifierBc.update(message);
        Assertions.assertTrue(verifierBc.verify(sigBytesSingleByteUpdate));

    }


    @Test
    public void testSingleByteUpdateVerify() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));


        byte[] message = new byte[1025];
        random.nextBytes(message);


        Signature signatureBc = Signature.getInstance("MLDSA", "BC");
        signatureBc.initSign(privKeyBC);
        signatureBc.update(message);
        byte[] signatureBytesBc = signatureBc.sign();


        Signature verifierJo = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
    public void testCalculateRawMu() throws Exception
    {

        for (MLDSAParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));


            byte[] msg = "Hello World!".getBytes();

            Signature jostle = Signature.getInstance("ML-DSA-CALCULATE-MU", JostleProvider.PROVIDER_NAME);
            jostle.initSign(keyPair.getPrivate());
            jostle.update(msg);
            byte[] jostleMuBytes = jostle.sign();

            Assertions.assertEquals(jostleMuBytes.length, 64);


            Signature bc = Signature.getInstance("ML-DSA-CALCULATE-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initSign(privKeyBC);
            bc.update(msg);
            byte[] bcMuBytes = bc.sign();

            Assertions.assertEquals(bcMuBytes.length, 64);

            Assertions.assertArrayEquals(bcMuBytes, jostleMuBytes);

            // Mu is the same between both providers.
            // Create a signature from the external mu.

            jostle = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
            jostle.initSign(keyPair.getPrivate());
            jostle.update(jostleMuBytes);
            byte[] jostleSigFromExternalMu = jostle.sign();


            // Check that BC in external Mu mode will verify the signature.
            bc = Signature.getInstance("ML-DSA-EXTERNAL-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initVerify(pubKeyBC);
            bc.update(jostleMuBytes);
            Assertions.assertTrue(bc.verify(jostleSigFromExternalMu));

            // Use BC to create a signature from an external mu

            bc = Signature.getInstance("ML-DSA-EXTERNAL-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initSign(privKeyBC);
            bc.update(bcMuBytes);
            byte[] bcSigFromExternalMu = bc.sign();

            // Use jostle to verify an external signature
            jostle = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
            jostle.initVerify(keyPair.getPublic());
            jostle.update(jostleMuBytes);
            Assertions.assertTrue(jostle.verify(bcSigFromExternalMu));


//            //
//            // Using proxy private key
//            //
//            Signature jostle = Signature.getInstance("ML-DSA-CALCULATE-MU", JostleProvider.PROVIDER_NAME);
//            jostle.initSign(keyPair.getPrivate());
//            jostle.update(msg);
//            byte[] jostleMuBytes = jostle.sign();
//
//            Assertions.assertEquals(jostleMuBytes.length, 64);


        }
    }


    @Test
    public void testCalculateRawMuProxyKey() throws Exception
    {

        for (MLDSAParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));


            byte[] msg = "Hello World!".getBytes();

            Signature jostle = Signature.getInstance("ML-DSA-CALCULATE-MU", JostleProvider.PROVIDER_NAME);
            jostle.initSign(new MLDSAProxyPrivateKey(keyPair.getPublic()));
            jostle.update(msg);
            byte[] jostleMuBytes = jostle.sign();

            Assertions.assertEquals(jostleMuBytes.length, 64);


            Signature bc = Signature.getInstance("ML-DSA-CALCULATE-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initSign(privKeyBC);
            bc.update(msg);
            byte[] bcMuBytes = bc.sign();

            Assertions.assertEquals(bcMuBytes.length, 64);

            Assertions.assertArrayEquals(bcMuBytes, jostleMuBytes);

            // Mu is the same between both providers.
            // Create a signature from the external mu.

            jostle = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
            jostle.initSign(keyPair.getPrivate());
            jostle.update(jostleMuBytes);
            byte[] jostleSigFromExternalMu = jostle.sign();


            // Check that BC in external Mu mode will verify the signature.
            bc = Signature.getInstance("ML-DSA-EXTERNAL-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initVerify(pubKeyBC);
            bc.update(jostleMuBytes);
            Assertions.assertTrue(bc.verify(jostleSigFromExternalMu));

            // Use BC to create a signature from an external mu

            bc = Signature.getInstance("ML-DSA-EXTERNAL-MU", BouncyCastleProvider.PROVIDER_NAME);
            bc.initSign(privKeyBC);
            bc.update(bcMuBytes);
            byte[] bcSigFromExternalMu = bc.sign();

            // Use jostle to verify an external signature
            jostle = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
            jostle.initVerify(keyPair.getPublic());
            jostle.update(jostleMuBytes);
            Assertions.assertTrue(jostle.verify(bcSigFromExternalMu));


        }
    }


    @Test
    public void testKeyGen() throws Exception
    {
        for (MLDSAParameterSpec spec : joSpec)
        {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            //
            // Verify encoded key can be handled by BC and is usable
            //
            KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

            byte[] msg = new byte[65];

            random.nextBytes(msg);

            Signature signatureBC = Signature.getInstance("MLDSA", "BC");
            signatureBC.initSign(privKeyBC);
            signatureBC.update(msg);
            byte[] signature = signatureBC.sign();

            Signature verifierBC = Signature.getInstance("MLDSA", "BC");
            verifierBC.initVerify(pubKeyBC);
            verifierBC.update(msg);

            Assertions.assertTrue(verifierBC.verify(signature));
        }
    }

    @Test
    public void testKeyRecovery() throws Exception
    {
        for (org.bouncycastle.jcajce.spec.MLDSAParameterSpec spec : bcSpec)
        {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKeyX509 = keyPair.getPublic().getEncoded();
            byte[] privateKeyX509 = keyPair.getPrivate().getEncoded();


            KeyFactory jostleFactory = KeyFactory.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            PrivateKey privateKey = jostleFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyX509));
            PublicKey publicKey = jostleFactory.generatePublic(new X509EncodedKeySpec(publicKeyX509));


            byte[] msg = new byte[65];
            random.nextBytes(msg);

            Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            signature.initSign(privateKey);
            signature.update(msg);
            byte[] signatureBytes = signature.sign();

            Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            verifier.initVerify(publicKey);
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(signatureBytes));
        }

    }


    @Test
    public void testLoadRawKey() throws Exception
    {

        for (org.bouncycastle.jcajce.spec.MLDSAParameterSpec spec : bcSpec)
        {
            // Generate on BC
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Get the raw encoding, not the X509 / PKCS8 version
            byte[] publicKey = ((org.bouncycastle.jcajce.interfaces.MLDSAPublicKey) keyPair.getPublic()).getPublicData();
            byte[] privateKey = ((org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey) keyPair.getPrivate()).getPrivateData();

            // Jostle specs
            MLDSAPrivateKeySpec privateKeySpec = new MLDSAPrivateKeySpec(bcToJostle.get(spec), privateKey, publicKey);
            MLDSAPublicKeySpec publicKeySpec = new MLDSAPublicKeySpec(bcToJostle.get(spec), publicKey);

            // Jostle KeyFactory
            KeyFactory keyFactory = KeyFactory.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            PrivateKey privKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);

            byte[] msg = new byte[65];
            random.nextBytes(msg);
            Signature signatureJostle = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            signatureJostle.initSign(privKey);
            signatureJostle.update(msg);
            byte[] signature = signatureJostle.sign();

            Signature verifierJostle = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            verifierJostle.initVerify(pubKey);
            verifierJostle.update(msg);
            Assertions.assertTrue(verifierJostle.verify(signature));
        }

    }

    @Test
    public void testSetParamsAfterUpdateFails() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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


        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
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
        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
        Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx1 = new byte[129];
        random.nextBytes(ctx1);

        byte[] message = new byte[1025];
        random.nextBytes(message);

        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
        Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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
    public void initSignWithForcedSpec() throws Exception
    {
        // Get a signature instance with a fixed spec
        // try to initialize sign with different spec
        for (MLDSAParameterSpec[] specs : new MLDSAParameterSpec[][]{
                // Key : Signer
                {MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_87},
                {MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_44},
                {MLDSAParameterSpec.ml_dsa_87, MLDSAParameterSpec.ml_dsa_44}
        })
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(specs[0]);
            KeyPair keyPair = keyGen.generateKeyPair();

            Signature signature = Signature.getInstance(specs[1].getName(), JostleProvider.PROVIDER_NAME);
            try
            {
                signature.initSign(keyPair.getPrivate());
                Assertions.fail();
            } catch (InvalidKeyException e)
            {
                Assertions.assertTrue(true);
            }
        }


    }

    @Test
    public void initVerifyWithForcedSpec() throws Exception
    {
        // Get a signature instance with a fixed spec
        // try to initialize sign with different spec
        for (MLDSAParameterSpec[] specs : new MLDSAParameterSpec[][]{
                // Key : Signer
                {MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_87},
                {MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_44},
                {MLDSAParameterSpec.ml_dsa_87, MLDSAParameterSpec.ml_dsa_44}
        })
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(specs[0]);
            KeyPair keyPair = keyGen.generateKeyPair();

            Signature verifier = Signature.getInstance(specs[1].getName(), JostleProvider.PROVIDER_NAME);
            try
            {
                verifier.initVerify(keyPair.getPublic());
                Assertions.fail();
            } catch (InvalidKeyException e)
            {
                Assertions.assertTrue(true);
            }
        }
    }

    @Test
    public void nullSignatureOnVerifyFails() throws Exception
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(MLDSAParameterSpec.ml_dsa_44);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();


        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
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

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(MLDSAParameterSpec.ml_dsa_44);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();


        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);

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

    private void crossProviderVerification(String algoName, MLDSAParameterSpec specJostle, org.bouncycastle.jcajce.spec.MLDSAParameterSpec specBC) throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(specJostle);
        KeyPair keyPair = keyGen.generateKeyPair();


        byte[] publicKey = ((MLDSAPublicKey) keyPair.getPublic()).getPublicData();
        byte[] privateKey = ((MLDSAPrivateKey) keyPair.getPrivate()).getPrivateData();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(specBC, privateKey, publicKey));
        PublicKey pubKeyBC = factory.generatePublic(new org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec(specBC, publicKey));


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


        {
            byte[] vandalised = Arrays.clone(jostleSignature);
            vandalised[0] ^= 1;
            bcVerifier = Signature.getInstance(algoName, "BC");
            bcVerifier.initVerify(pubKeyBC);
            bcVerifier.update(msg);
            Assertions.assertFalse(bcVerifier.verify(vandalised));
        }

        // Jostle verifies BC
        Signature verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        verifierJostle.initVerify(keyPair.getPublic());
        verifierJostle.update(msg);
        Assertions.assertTrue(verifierJostle.verify(bcSignature));


        {
            byte[] vandalised = Arrays.clone(bcSignature);
            vandalised[0] ^= 1;
            verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
            verifierJostle.initVerify(keyPair.getPublic());
            verifierJostle.update(msg);
            Assertions.assertFalse(verifierJostle.verify(vandalised));
        }

    }

    private void crossProviderVerificationWithContext(String algoName, MLDSAParameterSpec specJostle, org.bouncycastle.jcajce.spec.MLDSAParameterSpec specBC, byte[] ctx) throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(specJostle);
        KeyPair keyPair = keyGen.generateKeyPair();


        byte[] publicKey = ((MLDSAPublicKey) keyPair.getPublic()).getPublicData();
        byte[] privateKey = ((MLDSAPrivateKey) keyPair.getPrivate()).getPrivateData();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(specBC, privateKey, publicKey));
        PublicKey pubKeyBC = factory.generatePublic(new org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec(specBC, publicKey));


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
        }
        vandalised[0] ^= 1;
        verifierJostle = Signature.getInstance(algoName, JostleProvider.PROVIDER_NAME);
        verifierJostle.initVerify(keyPair.getPublic());
        verifierJostle.setParameter(new ContextParameterSpec(vandalised));
        verifierJostle.update(msg);
        Assertions.assertFalse(verifierJostle.verify(bcSignature));
    }

    @Test
    public void testMLDSASignature() throws Exception
    {

        crossProviderVerification("ML-DSA", MLDSAParameterSpec.ml_dsa_44, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44);
        crossProviderVerification("ML-DSA", MLDSAParameterSpec.ml_dsa_65, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65);
        crossProviderVerification("ML-DSA", MLDSAParameterSpec.ml_dsa_87, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87);


        for (int ctxLen = 0; ctxLen < 256; ctxLen++)
        {

            byte[] ctx = new byte[ctxLen];
            random.nextBytes(ctx);

            crossProviderVerificationWithContext("ML-DSA", MLDSAParameterSpec.ml_dsa_44, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44, ctx);
            crossProviderVerificationWithContext("ML-DSA", MLDSAParameterSpec.ml_dsa_65, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65, ctx);
            crossProviderVerificationWithContext("ML-DSA", MLDSAParameterSpec.ml_dsa_87, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87, ctx);
        }
    }

    @Test
    public void generateFromSeed() throws Exception
    {


        for (MLDSAParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(spec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            MLDSAPrivateKey privateKey = (MLDSAPrivateKey) keyPair.getPrivate();

            MLDSAPrivateKey seedOnly1 = privateKey.getPrivateKey(true);
            MLDSAPrivateKey fullEncoding2 = privateKey.getPrivateKey(false);

            MLDSAPrivateKey fullEncodingFromSeedOnly3 = seedOnly1.getPrivateKey(false);
            MLDSAPrivateKey seedOnltFromFullEncoding4 = fullEncoding2.getPrivateKey(true);

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

            Assertions.assertEquals(54, seedOnly1.getEncoded().length);
            Assertions.assertEquals(54, seedOnltFromFullEncoding4.getEncoded().length);

            Assertions.assertNotEquals(54, privateKey.getEncoded().length);
            Assertions.assertNotEquals(54, fullEncodingFromSeedOnly3.getEncoded().length);
        }
    }


    @Test
    public void testSeedOnlyKeyEncoding() throws Exception
    {
        for (int i = 0; i < joSpec.length; i++)
        {
            MLDSAParameterSpec spec = joSpec[i];
            org.bouncycastle.jcajce.spec.MLDSAParameterSpec bcSpec = jostleToBc.get(spec);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();

            MLDSAPrivateKey privKey = (MLDSAPrivateKey) keyPair.getPrivate();
            byte[] privateKeySeedOnly = privKey.getPrivateKey(true).getEncoded();



            //
            // Verify encoded key can be handled by BC and is usable
            //
            KeyFactory factory = KeyFactory.getInstance(bcSpec.getName(), "BC");
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKeySeedOnly));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

            byte[] msg = new byte[65];

            random.nextBytes(msg);

            Signature signatureBC = Signature.getInstance(bcSpec.getName(), "BC");
            signatureBC.initSign(privKeyBC);
            signatureBC.update(msg);
            byte[] signature = signatureBC.sign();

            Signature verifierBC = Signature.getInstance(bcSpec.getName(), "BC");
            verifierBC.initVerify(pubKeyBC);
            verifierBC.update(msg);

            Assertions.assertTrue(verifierBC.verify(signature));
        }
    }


    @Test
    public void keyFactoryByNameTest() throws Exception
    {
        String[] names = new String[]{
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
        };


        for (int t = 0; t < names.length; t++)
        {
            String name = names[t];

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            {
                KeyFactory keyFactory = KeyFactory.getInstance(name, JostleProvider.PROVIDER_NAME);
                PublicKey pubK = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
                PrivateKey privK = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

                Assertions.assertEquals(name, pubK.getAlgorithm());
                Assertions.assertEquals(name, privK.getAlgorithm());
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


    public static class TestAlgorithmParameterSpec implements AlgorithmParameterSpec
    {
        private final byte[] ctx;

        public TestAlgorithmParameterSpec(byte[] ctx)
        {
            this.ctx = ctx;
        }

        public TestAlgorithmParameterSpec()
        {
            this(Strings.toByteArray("Jostle"));
        }

        public byte[] getContext()
        {
            return ctx;
        }
    }
}
