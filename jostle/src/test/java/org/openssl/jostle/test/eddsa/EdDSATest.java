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

package org.openssl.jostle.test.eddsa;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519ctxSigner;
import org.bouncycastle.crypto.signers.Ed25519phSigner;
import org.bouncycastle.crypto.signers.Ed448phSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.jcajce.provider.ed.EdDSAKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAPrivateKeySpec;
import org.openssl.jostle.jcajce.spec.EdDSAPublicKeySpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.Pack;
import org.openssl.jostle.util.Strings;
import org.openssl.jostle.util.encoders.Hex;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EdDSATest
{

    private static SecureRandom random = new SecureRandom();

    private final EDServiceNI edServiceNI = TestNISelector.getEdNi();
    private final SpecNI specNI = TestNISelector.getSpecNI();


    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    @Test
    public void testIncorrectForcedType_KeyPairGenerator() throws Exception
    {
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        try
        {
            keyFactory.initialize(EdDSAParameterSpec.ED25519);
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("expected ED448 but was supplied ED25519", e.getMessage());
        }
        keyFactory.initialize(EdDSAParameterSpec.ED448);

        keyFactory = KeyPairGenerator.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        try
        {
            keyFactory.initialize(EdDSAParameterSpec.ED448);
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("expected ED25519 but was supplied ED448", e.getMessage());
        }
        keyFactory.initialize(EdDSAParameterSpec.ED25519);


        try
        {
            keyFactory.initialize(new AlgorithmParameterSpec()
            {
            });
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("expected instance of EdDSAParameterSpec", e.getMessage());
        }
    }

    @Test
    public void testUnknownAlgorithm()
    {
        try
        {
            new EdDSAKeyPairGenerator("FISH");
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("unknown algorithm: FISH", e.getMessage());
        }
    }


    @Test
    public void testCustomParameterSpec() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(EdDSAParameterSpec.ED25519);
        KeyPair keyPair = keyGen.generateKeyPair();


        AlgorithmParameterSpec customSpec = new EdDSATest.TestAlgorithmParameterSpec();


        Signature signature = Signature.getInstance("ED25519CTX", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(customSpec);

        try
        {
            signature.setParameter(new AlgorithmParameterSpec()
            {
            });
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("unknown AlgorithmParameterSpec", e.getMessage());
        }

        Signature verifier = Signature.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        try
        {
            signature.setParameter(new AlgorithmParameterSpec()
            {
            });
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("unknown AlgorithmParameterSpec", e.getMessage());
        }

    }

    @Test
    public void testUnknownParameterSpec() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(EdDSAParameterSpec.ED25519);
        KeyPair keyPair = keyGen.generateKeyPair();

        Signature signature = Signature.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        try
        {
            signature.setParameter(new AlgorithmParameterSpec()
            {
            });
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("unknown AlgorithmParameterSpec", e.getMessage());
        }

        Signature verifier = Signature.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        try
        {
            signature.setParameter(new AlgorithmParameterSpec()
            {
            });
            Assertions.fail();
        }
        catch (InvalidAlgorithmParameterException e)
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

        Signature signature = Signature.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signature.initVerify(publicKey);
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("expected only EdDSAPublicKey", e.getMessage());
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

        Signature signature = Signature.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signature.initSign(publicKey);
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("expected only EdDSAPrivateKey", e.getMessage());
        }
    }

    @Test
    public void testSignVerifyWithReuseEdDSA_ED25519() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(EdDSAParameterSpec.ED25519);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = new byte[1025];
        random.nextBytes(message);


        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
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
        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
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
    public void testSignVerifyWithReuseEdDSA_ED448() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(EdDSAParameterSpec.ED448);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = new byte[1025];
        random.nextBytes(message);


        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
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
        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
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
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(EdDSAParameterSpec.ED25519);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx = new byte[64];
        random.nextBytes(ctx);

        byte[] message = new byte[1025];
        random.nextBytes(message);


        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("ED25519CTX", JostleProvider.PROVIDER_NAME);
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
        Signature verifier = Signature.getInstance("ED25519CTX", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.setParameter(new ContextParameterSpec(ctx));
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(secondSignature));

        //
        // Verifier should have reset
        //
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(firstSignature));


        // Vandalize message
        message[0] ^= 1;
        verifier.update(message);
        Assertions.assertFalse(verifier.verify(firstSignature));
    }


    @Test
    public void testSignVerifyWithCustomContextAndReuse() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(EdDSAParameterSpec.ED25519);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx = new byte[64];
        random.nextBytes(ctx);

        byte[] message = new byte[1025];
        random.nextBytes(message);


        //
        // Take first signature on a fresh instance that is fully set up
        //
        Signature signature = Signature.getInstance("ED25519CTX", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(new EdDSATest.TestAlgorithmParameterSpec(ctx));

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
        Signature verifier = Signature.getInstance("Ed25519Ctx", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.setParameter(new EdDSATest.TestAlgorithmParameterSpec(ctx));
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
    public void testSignJostleVerifyBCEd25519() throws Exception
    {

        byte[] message = new byte[1025];
        random.nextBytes(message);

        KeyPairGenerator joKeyGen = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        joKeyGen.initialize(EdDSAParameterSpec.ED25519);
        KeyPair joKeyPair = joKeyGen.generateKeyPair();

        KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKeyGen.initialize(new org.bouncycastle.jcajce.spec.EdDSAParameterSpec("Ed25519"));
        KeyPair bcKeyPair = bcKeyGen.generateKeyPair();


        Signature joSigner = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(joKeyPair.getPrivate());

        joSigner.update(message);
        byte[] joSignature = joSigner.sign();


        Signature bcSigner = Signature.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(bcKeyPair.getPrivate());
        bcSigner.update(message);
        byte[] bcSignature = bcSigner.sign();


        //
        // Generate public key from encoded other key pair.
        //

        KeyFactory joKeyFactory = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        PublicKey joPubKeyFromBCKeyPair = joKeyFactory.generatePublic(new X509EncodedKeySpec(bcKeyPair.getPublic().getEncoded()));

        KeyFactory bcKeyFactory = KeyFactory.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPublicKeyFromJoKeyPair = bcKeyFactory.generatePublic(new X509EncodedKeySpec(joKeyPair.getPublic().getEncoded()));


        //
        // Verify BC generated signature using Jostle
        //
        joSigner.initVerify(joPubKeyFromBCKeyPair);
        joSigner.update(message);
        Assertions.assertTrue(joSigner.verify(bcSignature));

        //
        // Verify Jostle generated signature from BC key pair
        //
        bcSigner.initVerify(bcPublicKeyFromJoKeyPair);
        bcSigner.update(message);
        Assertions.assertTrue(bcSigner.verify(joSignature));

    }

    @Test
    public void testSignJostleVerifyBCEd448() throws Exception
    {

        byte[] message = new byte[1025];
        random.nextBytes(message);

        KeyPairGenerator joKeyGen = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        joKeyGen.initialize(EdDSAParameterSpec.ED448);
        KeyPair joKeyPair = joKeyGen.generateKeyPair();

        KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKeyGen.initialize(new org.bouncycastle.jcajce.spec.EdDSAParameterSpec("Ed448"));
        KeyPair bcKeyPair = bcKeyGen.generateKeyPair();


        Signature joSigner = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(joKeyPair.getPrivate());

        joSigner.update(message);
        byte[] joSignature = joSigner.sign();


        Signature bcSigner = Signature.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(bcKeyPair.getPrivate());
        bcSigner.update(message);
        byte[] bcSignature = bcSigner.sign();


        //
        // Generate public key from encoded other key pair.
        //

        KeyFactory joKeyFactory = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        PublicKey joPubKeyFromBCKeyPair = joKeyFactory.generatePublic(new X509EncodedKeySpec(bcKeyPair.getPublic().getEncoded()));

        KeyFactory bcKeyFactory = KeyFactory.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPublicKeyFromJoKeyPair = bcKeyFactory.generatePublic(new X509EncodedKeySpec(joKeyPair.getPublic().getEncoded()));


        //
        // Verify BC generated signature using Jostle
        //
        joSigner.initVerify(joPubKeyFromBCKeyPair);
        joSigner.update(message);
        Assertions.assertTrue(joSigner.verify(bcSignature));

        //
        // Verify Jostle generated signature from BC key pair
        //
        bcSigner.initVerify(bcPublicKeyFromJoKeyPair);
        bcSigner.update(message);
        Assertions.assertTrue(bcSigner.verify(joSignature));

    }

    @Test
    public void testSignJostleVerifyBCEd25519Ctx() throws Exception
    {

        byte[] message = new byte[1025];
        random.nextBytes(message);

        byte[] ctxBytes = new byte[128];
        random.nextBytes(ctxBytes);

        KeyPairGenerator joKeyGen = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        joKeyGen.initialize(EdDSAParameterSpec.ED25519);
        KeyPair joKeyPair = joKeyGen.generateKeyPair();

        KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKeyGen.initialize(new org.bouncycastle.jcajce.spec.EdDSAParameterSpec("Ed25519"));
        KeyPair bcKeyPair = joKeyGen.generateKeyPair();


        Signature joSigner = Signature.getInstance("Ed25519ctx", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(joKeyPair.getPrivate());
        joSigner.setParameter(new ContextParameterSpec(ctxBytes));

        joSigner.update(message);
        byte[] joSignature = joSigner.sign();


        //
        // No provider support in BC for ed25519 with context so use low level api
        //

        Ed25519ctxSigner bcLLSigner = new Ed25519ctxSigner(ctxBytes);
        bcLLSigner.init(true, PrivateKeyFactory.createKey(bcKeyPair.getPrivate().getEncoded()));
        bcLLSigner.update(message, 0, message.length);
        byte[] bcSignature = bcLLSigner.generateSignature();


        //
        // Generate public key from encoded other key pair.
        //

        KeyFactory joKeyFactory = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        PublicKey joPubKeyFromBCKeyPair = joKeyFactory.generatePublic(new X509EncodedKeySpec(bcKeyPair.getPublic().getEncoded()));

        KeyFactory bcKeyFactory = KeyFactory.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPublicKeyFromJoKeyPair = bcKeyFactory.generatePublic(new X509EncodedKeySpec(joKeyPair.getPublic().getEncoded()));


        //
        // Verify BC generated signature using Jostle
        //
        joSigner.initVerify(joPubKeyFromBCKeyPair);
        joSigner.setParameter(new ContextParameterSpec(ctxBytes));
        joSigner.update(message);

        Assertions.assertTrue(joSigner.verify(bcSignature));

        //
        // Verify Jostle generated signature from BC key pair
        //
        bcLLSigner.init(false, PublicKeyFactory.createKey(bcPublicKeyFromJoKeyPair.getEncoded()));
        bcLLSigner.update(message, 0, message.length);
        Assertions.assertTrue(bcLLSigner.verifySignature(joSignature));

    }


    @Test
    public void testSignJostleVerifyBCEd25519phCtx() throws Exception
    {
        byte[] message = new byte[1025];
        random.nextBytes(message);

        byte[] ctxBytes = new byte[128];
        random.nextBytes(ctxBytes);


        MessageDigest bcMD = MessageDigest.getInstance("SHA512", BouncyCastleProvider.PROVIDER_NAME);
        MessageDigest jostleMD = MessageDigest.getInstance("SHA512", JostleProvider.PROVIDER_NAME);

        bcMD.update(Pack.longToBigEndian(message.length));
        bcMD.update(message, 0, message.length);

        byte[] bcPreHash = bcMD.digest();

        jostleMD.update(Pack.longToBigEndian(message.length));
        jostleMD.update(message, 0, message.length);

        byte[] joPreHash = jostleMD.digest();


        KeyPairGenerator joKeyGen = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        joKeyGen.initialize(EdDSAParameterSpec.ED25519);
        KeyPair joKeyPair = joKeyGen.generateKeyPair();

        KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKeyGen.initialize(new org.bouncycastle.jcajce.spec.EdDSAParameterSpec("Ed25519"));
        KeyPair bcKeyPair = joKeyGen.generateKeyPair();


        Signature joSigner = Signature.getInstance("Ed25519ph", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(joKeyPair.getPrivate());
        joSigner.setParameter(new ContextParameterSpec(ctxBytes));

        joSigner.update(bcPreHash);
        byte[] joSignature = joSigner.sign();


        //
        // No provider support in BC for ed25519 pre hash so use low level api
        //

        Ed25519phSigner bcLLSigner = new Ed25519phSigner(ctxBytes);
        bcLLSigner.init(true, PrivateKeyFactory.createKey(bcKeyPair.getPrivate().getEncoded()));
        bcLLSigner.update(bcPreHash, 0, bcPreHash.length);
        byte[] bcSignature = bcLLSigner.generateSignature();


        //
        // Generate public key from encoded other key pair.
        //

        KeyFactory joKeyFactory = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        PublicKey joPubKeyFromBCKeyPair = joKeyFactory.generatePublic(new X509EncodedKeySpec(bcKeyPair.getPublic().getEncoded()));

        KeyFactory bcKeyFactory = KeyFactory.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPublicKeyFromJoKeyPair = bcKeyFactory.generatePublic(new X509EncodedKeySpec(joKeyPair.getPublic().getEncoded()));


        //
        // Verify BC generated signature using Jostle
        //
        joSigner.initVerify(joPubKeyFromBCKeyPair);
        joSigner.setParameter(new ContextParameterSpec(ctxBytes));
        joSigner.update(joPreHash);

        Assertions.assertTrue(joSigner.verify(bcSignature));

        //
        // Verify Jostle generated signature from BC key pair
        //
        bcLLSigner.init(false, PublicKeyFactory.createKey(bcPublicKeyFromJoKeyPair.getEncoded()));
        bcLLSigner.update(bcPreHash, 0, bcPreHash.length);
        Assertions.assertTrue(bcLLSigner.verifySignature(joSignature));

    }


    @Test
    public void testSignJostleVerifyBCEd448phCtx() throws Exception
    {
        byte[] message = new byte[1025];
        random.nextBytes(message);

        byte[] ctxBytes = new byte[128];
        random.nextBytes(ctxBytes);


        MessageDigest bcMD = MessageDigest.getInstance("SHA512", BouncyCastleProvider.PROVIDER_NAME);
        MessageDigest jostleMD = MessageDigest.getInstance("SHA512", JostleProvider.PROVIDER_NAME);

        bcMD.update(Pack.longToBigEndian(message.length));
        bcMD.update(message, 0, message.length);

        byte[] bcPreHash = bcMD.digest();

        jostleMD.update(Pack.longToBigEndian(message.length));
        jostleMD.update(message, 0, message.length);

        byte[] joPreHash = jostleMD.digest();


        KeyPairGenerator joKeyGen = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        joKeyGen.initialize(EdDSAParameterSpec.ED448);
        KeyPair joKeyPair = joKeyGen.generateKeyPair();

        KeyPairGenerator bcKeyGen = KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKeyGen.initialize(new org.bouncycastle.jcajce.spec.EdDSAParameterSpec("Ed448"));
        KeyPair bcKeyPair = joKeyGen.generateKeyPair();


        Signature joSigner = Signature.getInstance("ED448ph", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(joKeyPair.getPrivate());
        joSigner.setParameter(new ContextParameterSpec(ctxBytes));

        joSigner.update(bcPreHash);
        byte[] joSignature = joSigner.sign();


        //
        // No provider support in BC for ed448 pre hash so use low level api
        //

        Ed448phSigner bcLLSigner = new Ed448phSigner(ctxBytes);
        bcLLSigner.init(true, PrivateKeyFactory.createKey(bcKeyPair.getPrivate().getEncoded()));
        bcLLSigner.update(bcPreHash, 0, bcPreHash.length);
        byte[] bcSignature = bcLLSigner.generateSignature();


        //
        // Generate public key from encoded other key pair.
        //

        KeyFactory joKeyFactory = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        PublicKey joPubKeyFromBCKeyPair = joKeyFactory.generatePublic(new X509EncodedKeySpec(bcKeyPair.getPublic().getEncoded()));

        KeyFactory bcKeyFactory = KeyFactory.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPublicKeyFromJoKeyPair = bcKeyFactory.generatePublic(new X509EncodedKeySpec(joKeyPair.getPublic().getEncoded()));


        //
        // Verify BC generated signature using Jostle
        //
        joSigner.initVerify(joPubKeyFromBCKeyPair);
        joSigner.setParameter(new ContextParameterSpec(ctxBytes));
        joSigner.update(joPreHash);

        Assertions.assertTrue(joSigner.verify(bcSignature));

        //
        // Verify Jostle generated signature from BC key pair
        //
        bcLLSigner.init(false, PublicKeyFactory.createKey(bcPublicKeyFromJoKeyPair.getEncoded()));
        bcLLSigner.update(bcPreHash, 0, bcPreHash.length);
        Assertions.assertTrue(bcLLSigner.verifySignature(joSignature));

    }



    //
    // (1) Forced-type / key-type mismatch on Signature.
    //
    @Test
    public void testForcedType_ED25519_RejectsED448_initSign() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.initSign(kp.getPrivate());
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("required ED25519 key type but got ED448", e.getMessage());
        }
    }

    @Test
    public void testForcedType_ED25519_RejectsED448_initVerify() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.initVerify(kp.getPublic());
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("required ED25519 key type but got ED448", e.getMessage());
        }
    }

    @Test
    public void testForcedType_ED448_RejectsED25519_initSign() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.initSign(kp.getPrivate());
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("required ED448 key type but got ED25519", e.getMessage());
        }
    }

    @Test
    public void testForcedType_Ed25519ph_RejectsED448_initSign() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Ed25519ph", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.initSign(kp.getPrivate());
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("required Ed25519ph key type but got ED448", e.getMessage());
        }
    }

    @Test
    public void testForcedType_Ed448ph_RejectsED25519_initVerify() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Ed448ph", JostleProvider.PROVIDER_NAME);
        try
        {
            sig.initVerify(kp.getPublic());
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("required ED448ph key type but got ED25519", e.getMessage());
        }
    }


    //
    // (2) Context spec on a forced type that does not accept context.
    //
    @Test
    public void testContextOnED25519_RejectsAtInitSign() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        sig.setParameter(new ContextParameterSpec(new byte[]{1, 2, 3}));

        try
        {
            sig.initSign(kp.getPrivate());
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("ED25519 does not accept a context parameter", e.getMessage());
        }
    }

    @Test
    public void testContextOnED448_RejectsAtInitVerify() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        sig.setParameter(new ContextParameterSpec(new byte[]{1, 2, 3}));

        try
        {
            sig.initVerify(kp.getPublic());
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("ED448 does not accept a context parameter", e.getMessage());
        }
    }


    //
    // (3) setParameter is rejected after update has been called.
    //
    @Test
    public void testSetParameterAfterUpdate_Throws() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Ed25519ctx", JostleProvider.PROVIDER_NAME);
        sig.initSign(kp.getPrivate());
        sig.setParameter(new ContextParameterSpec(new byte[]{1}));
        sig.update(new byte[]{42});

        try
        {
            sig.setParameter(new ContextParameterSpec(new byte[]{2}));
            Assertions.fail();
        }
        catch (ProviderException e)
        {
            Assertions.assertEquals("cannot call setParameter in the middle of update", e.getMessage());
        }
    }


    //
    // (4) Round-trip via EdDSAPublicKeySpec / EdDSAPrivateKeySpec (raw byte form).
    //
    @Test
    public void testKeyFactory_PublicSpec_RawRoundTrip_ED25519() throws Exception
    {
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new org.bouncycastle.jcajce.spec.EdDSAParameterSpec("Ed25519"));
        KeyPair bcKp = bcKpg.generateKeyPair();

        Ed25519PublicKeyParameters bcPub = (Ed25519PublicKeyParameters) PublicKeyFactory.createKey(bcKp.getPublic().getEncoded());
        byte[] rawPub = bcPub.getEncoded();
        Assertions.assertEquals(32, rawPub.length);

        Ed25519PrivateKeyParameters bcPriv = (Ed25519PrivateKeyParameters) PrivateKeyFactory.createKey(bcKp.getPrivate().getEncoded());
        byte[] rawPriv = bcPriv.getEncoded();
        Assertions.assertEquals(32, rawPriv.length);

        KeyFactory kf = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        PublicKey joPub = kf.generatePublic(new EdDSAPublicKeySpec(EdDSAParameterSpec.ED25519, rawPub));
        PrivateKey joPriv = kf.generatePrivate(new EdDSAPrivateKeySpec(EdDSAParameterSpec.ED25519, rawPriv, rawPub));

        byte[] message = new byte[1025];
        random.nextBytes(message);

        Signature signer = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(joPriv);
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(joPub);
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testKeyFactory_PublicSpec_RawRoundTrip_ED448() throws Exception
    {
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new org.bouncycastle.jcajce.spec.EdDSAParameterSpec("Ed448"));
        KeyPair bcKp = bcKpg.generateKeyPair();

        Ed448PublicKeyParameters bcPub = (Ed448PublicKeyParameters) PublicKeyFactory.createKey(bcKp.getPublic().getEncoded());
        byte[] rawPub = bcPub.getEncoded();
        Assertions.assertEquals(57, rawPub.length);

        Ed448PrivateKeyParameters bcPriv = (Ed448PrivateKeyParameters) PrivateKeyFactory.createKey(bcKp.getPrivate().getEncoded());
        byte[] rawPriv = bcPriv.getEncoded();
        Assertions.assertEquals(57, rawPriv.length);

        KeyFactory kf = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        PublicKey joPub = kf.generatePublic(new EdDSAPublicKeySpec(EdDSAParameterSpec.ED448, rawPub));
        PrivateKey joPriv = kf.generatePrivate(new EdDSAPrivateKeySpec(EdDSAParameterSpec.ED448, rawPriv, rawPub));

        byte[] message = new byte[1025];
        random.nextBytes(message);

        Signature signer = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(joPriv);
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(joPub);
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig));
    }


    //
    // (5) Fixed-type KeyFactory rejects wrong-typed encoded spec.
    //
    @Test
    public void testKeyFactory_FixedED25519_RejectsED448PKCS8() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        KeyFactory kf = KeyFactory.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        try
        {
            kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            Assertions.fail();
        }
        catch (java.security.spec.InvalidKeySpecException e)
        {
            // engine-level message bubbles up as cause; assert main and cause where useful
            Assertions.assertTrue(e.getMessage() != null && e.getMessage().contains("ED25519"));
        }
    }

    @Test
    public void testKeyFactory_FixedED448_RejectsED25519X509() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();
        byte[] x509 = kp.getPublic().getEncoded();

        KeyFactory kf = KeyFactory.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        try
        {
            kf.generatePublic(new X509EncodedKeySpec(x509));
            Assertions.fail();
        }
        catch (java.security.spec.InvalidKeySpecException e)
        {
            Assertions.assertTrue(e.getMessage() != null && e.getMessage().contains("ED448"));
        }
    }

    @Test
    public void testKeyFactory_FixedED25519_RejectsED448RawSpec() throws Exception
    {
        // Raw-bytes path: a fixed-type ED25519 KeyFactory must reject a spec
        // whose EdDSAParameterSpec says ED448.
        byte[] raw = new byte[57];
        random.nextBytes(raw);

        KeyFactory kf = KeyFactory.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        try
        {
            kf.generatePublic(new EdDSAPublicKeySpec(EdDSAParameterSpec.ED448, raw));
            Assertions.fail();
        }
        catch (java.security.spec.InvalidKeySpecException e)
        {
            Assertions.assertNotNull(e.getMessage());
        }
    }


    //
    // (6) engineGetKeySpec for all four supported KeySpec classes.
    //
    @Test
    public void testKeyFactory_GetKeySpec_X509() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(EdDSAParameterSpec.ED25519);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        X509EncodedKeySpec spec = kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
        Assertions.assertArrayEquals(kp.getPublic().getEncoded(), spec.getEncoded());

        // Round-trip back through generatePublic to confirm.
        PublicKey roundTripped = kf.generatePublic(spec);
        Assertions.assertArrayEquals(kp.getPublic().getEncoded(), roundTripped.getEncoded());
    }

    @Test
    public void testKeyFactory_GetKeySpec_PKCS8() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(EdDSAParameterSpec.ED25519);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec spec = kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
        Assertions.assertArrayEquals(kp.getPrivate().getEncoded(), spec.getEncoded());

        PrivateKey roundTripped = kf.generatePrivate(spec);
        Assertions.assertArrayEquals(kp.getPrivate().getEncoded(), roundTripped.getEncoded());
    }

    @Test
    public void testKeyFactory_GetKeySpec_EdDSAPublicSpec() throws Exception
    {
        // Generate a Jostle ED25519 keypair, retrieve EdDSAPublicKeySpec, then
        // construct a fresh public key from those raw bytes and confirm it
        // verifies signatures made by the original private key.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(EdDSAParameterSpec.ED25519);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        EdDSAPublicKeySpec spec = kf.getKeySpec(kp.getPublic(), EdDSAPublicKeySpec.class);
        Assertions.assertEquals(EdDSAParameterSpec.ED25519, spec.getParameterSpec());
        Assertions.assertEquals(32, spec.getPublicData().length);

        PublicKey rebuilt = kf.generatePublic(spec);

        byte[] message = new byte[1025];
        random.nextBytes(message);

        Signature signer = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(rebuilt);
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testKeyFactory_GetKeySpec_EdDSAPrivateSpec() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(EdDSAParameterSpec.ED25519);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        EdDSAPrivateKeySpec spec = kf.getKeySpec(kp.getPrivate(), EdDSAPrivateKeySpec.class);
        Assertions.assertEquals(EdDSAParameterSpec.ED25519, spec.getParameterSpec());
        Assertions.assertEquals(32, spec.getPrivateData().length);
        Assertions.assertEquals(32, spec.getPublicData().length);

        PrivateKey rebuilt = kf.generatePrivate(spec);

        byte[] message = new byte[1025];
        random.nextBytes(message);

        Signature signer = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(rebuilt);
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig));
    }


    //
    // (7) Single-byte engineUpdate and empty-message sign/verify.
    //
    @Test
    public void testEngineUpdateByte() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(EdDSAParameterSpec.ED25519);
        KeyPair kp = kpg.generateKeyPair();

        byte[] message = new byte[64];
        random.nextBytes(message);

        Signature signer = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        for (byte b : message)
        {
            signer.update(b);
        }
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        for (byte b : message)
        {
            verifier.update(b);
        }
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testEmptyMessage_SignAndVerify_ED25519() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(EdDSAParameterSpec.ED25519);
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        // No update calls — sign over empty message.
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        Assertions.assertTrue(verifier.verify(sig));
    }


    //
    // (8) setParameter(null) must clear context state and re-initialise.
    // Use Ed25519ph because RFC 8032 allows an empty context for *ph variants;
    // Ed25519ctx requires a non-empty context.
    //
    @Test
    public void testSetParameterNull() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(EdDSAParameterSpec.ED25519);
        KeyPair kp = kpg.generateKeyPair();

        byte[] ctx = new byte[16];
        random.nextBytes(ctx);
        byte[] message = new byte[64];
        random.nextBytes(message);

        Signature signer = Signature.getInstance("Ed25519ph", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.setParameter(new ContextParameterSpec(ctx));
        // Override back to empty context.
        signer.setParameter(null);
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("Ed25519ph", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.setParameter(null);
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig));

        // Re-verify the same signature under the original (non-empty) ctx — must fail.
        Signature verifier2 = Signature.getInstance("Ed25519ph", JostleProvider.PROVIDER_NAME);
        verifier2.initVerify(kp.getPublic());
        verifier2.setParameter(new ContextParameterSpec(ctx));
        verifier2.update(message);
        Assertions.assertFalse(verifier2.verify(sig));
    }


    //
    // (9) Re-init with a different key type on a generic "EdDSA" Signature instance.
    //
    @Test
    public void testReInit_DifferentKeyType_GenericEdDSA() throws Exception
    {
        KeyPairGenerator kpg25519 = KeyPairGenerator.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        KeyPair kp25519 = kpg25519.generateKeyPair();

        KeyPairGenerator kpg448 = KeyPairGenerator.getInstance("ED448", JostleProvider.PROVIDER_NAME);
        KeyPair kp448 = kpg448.generateKeyPair();

        byte[] message = new byte[256];
        random.nextBytes(message);

        Signature sig = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);

        // First init with ED25519 — sign and verify.
        sig.initSign(kp25519.getPrivate());
        sig.update(message);
        byte[] s25519 = sig.sign();

        sig.initVerify(kp25519.getPublic());
        sig.update(message);
        Assertions.assertTrue(sig.verify(s25519));

        // Re-init the same instance with ED448 — sign and verify under the new key.
        sig.initSign(kp448.getPrivate());
        sig.update(message);
        byte[] s448 = sig.sign();

        sig.initVerify(kp448.getPublic());
        sig.update(message);
        Assertions.assertTrue(sig.verify(s448));

        // ED448 verifier must reject the ED25519 signature.
        sig.initVerify(kp448.getPublic());
        sig.update(message);
        Assertions.assertFalse(sig.verify(s25519));
    }


    //
    // Native-layer round-trip / length-query surface tests for getPublicKey / getPrivateKey.
    // (Moved from EdDSALimitTest — these are happy-path surface checks, not error-path.)
    //
    @Test
    public void EDDSAServiceNI_getPublicKey_lengthQuery_ed25519() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);
            // null output array → returns the size needed.
            int len = edServiceNI.getPublicKey(keyRef, null);
            Assertions.assertEquals(32, len);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void EDDSAServiceNI_getPublicKey_lengthQuery_ed448() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED448.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);
            int len = edServiceNI.getPublicKey(keyRef, null);
            Assertions.assertEquals(57, len);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void EDDSAServiceNI_getPublicKey_roundTrip_ed25519() throws Exception
    {
        long keyRef = 0;
        long roundTripRef = 0;
        try
        {
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            byte[] raw = new byte[32];
            int written = edServiceNI.getPublicKey(keyRef, raw);
            Assertions.assertEquals(32, written);

            // round-trip via decode_publicKey
            roundTripRef = specNI.allocate();
            Assertions.assertTrue(roundTripRef > 0);
            int decoded = edServiceNI.decode_publicKey(roundTripRef, OSSLKeyType.ED25519.getKsType(), raw, 0, raw.length);
            Assertions.assertEquals(0, decoded);

            byte[] raw2 = new byte[32];
            edServiceNI.getPublicKey(roundTripRef, raw2);
            Assertions.assertArrayEquals(raw, raw2);
        }
        finally
        {
            specNI.dispose(keyRef);
            specNI.dispose(roundTripRef);
        }
    }


    @Test
    public void EDDSAServiceNI_getPrivateKey_lengthQuery_ed25519() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);
            int len = edServiceNI.getPrivateKey(keyRef, null);
            Assertions.assertEquals(32, len);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void EDDSAServiceNI_getPrivateKey_lengthQuery_ed448() throws Exception
    {
        long keyRef = 0;
        try
        {
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED448.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);
            int len = edServiceNI.getPrivateKey(keyRef, null);
            Assertions.assertEquals(57, len);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }


    @Test
    public void EDDSAServiceNI_getPrivateKey_roundTrip_ed25519() throws Exception
    {
        long keyRef = 0;
        long roundTripRef = 0;
        try
        {
            keyRef = edServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            byte[] raw = new byte[32];
            int written = edServiceNI.getPrivateKey(keyRef, raw);
            Assertions.assertEquals(32, written);

            // round-trip via decode_privateKey
            roundTripRef = specNI.allocate();
            Assertions.assertTrue(roundTripRef > 0);
            int decoded = edServiceNI.decode_privateKey(roundTripRef, OSSLKeyType.ED25519.getKsType(), raw, 0, raw.length);
            Assertions.assertEquals(0, decoded);

            byte[] raw2 = new byte[32];
            edServiceNI.getPrivateKey(roundTripRef, raw2);
            Assertions.assertArrayEquals(raw, raw2);
        }
        finally
        {
            specNI.dispose(keyRef);
            specNI.dispose(roundTripRef);
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
