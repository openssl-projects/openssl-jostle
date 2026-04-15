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
import org.openssl.jostle.jcajce.provider.ed.EdDSAKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.util.Pack;
import org.openssl.jostle.util.Strings;
import org.openssl.jostle.util.encoders.Hex;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class EdDSATest
{

    private static SecureRandom random = new SecureRandom();


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
        KeyPair bcKeyPair = joKeyGen.generateKeyPair();


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
        KeyPair bcKeyPair = joKeyGen.generateKeyPair();


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
