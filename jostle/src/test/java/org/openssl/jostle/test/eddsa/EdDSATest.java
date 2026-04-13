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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.ed.EdDSAKeyPairGenerator;

import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.util.Strings;
import org.openssl.jostle.util.encoders.Hex;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class EdDSATest
{

    private static SecureRandom random = new SecureRandom();

    private static EdDSAParameterSpec[] joSpec = new EdDSAParameterSpec[]{
            EdDSAParameterSpec.ED25519,
            EdDSAParameterSpec.ED448,
    };

    private static org.bouncycastle.jcajce.spec.EdDSAParameterSpec[] bcSpec = new org.bouncycastle.jcajce.spec.EdDSAParameterSpec[]{
            new org.bouncycastle.jcajce.spec.EdDSAParameterSpec(org.bouncycastle.jcajce.spec.EdDSAParameterSpec.Ed25519),
            new org.bouncycastle.jcajce.spec.EdDSAParameterSpec(org.bouncycastle.jcajce.spec.EdDSAParameterSpec.Ed448),
    };


    private static Map<org.bouncycastle.jcajce.spec.EdDSAParameterSpec, EdDSAParameterSpec> bcToJostle = new HashMap<>();
    private static Map<EdDSAParameterSpec, org.bouncycastle.jcajce.spec.EdDSAParameterSpec> jostleToBc = new HashMap<>();

    static
    {
        for (int i = 0; i < joSpec.length; i++)
        {
            bcToJostle.put(bcSpec[i], joSpec[i]);
            jostleToBc.put(joSpec[i], bcSpec[i]);
        }
    }



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
        } catch (InvalidAlgorithmParameterException e)
        {
            Assertions.assertEquals("expected ED448 but was supplied ED25519", e.getMessage());
        }
        keyFactory.initialize(EdDSAParameterSpec.ED448);

        keyFactory = KeyPairGenerator.getInstance("ED25519", JostleProvider.PROVIDER_NAME);
        try
        {
            keyFactory.initialize(EdDSAParameterSpec.ED448);
            Assertions.fail();
        } catch (InvalidAlgorithmParameterException e)
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
        } catch (InvalidAlgorithmParameterException e)
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
        } catch (IllegalArgumentException e)
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


        Signature signature = Signature.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
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

        Signature verifier = Signature.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
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
        } catch (InvalidAlgorithmParameterException e)
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

        Signature signature = Signature.getInstance("EDDSA", JostleProvider.PROVIDER_NAME);
        try
        {
            signature.initVerify(publicKey);
            Assertions.fail();
        } catch (InvalidKeyException e)
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
        } catch (InvalidKeyException e)
        {
            Assertions.assertEquals("expected only EdDSAPrivateKey", e.getMessage());
        }
    }

    @Test
    public void testSignVerifyWithReuse() throws Exception
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
        Signature signature = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
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
        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
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
        Signature signature = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
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
        Signature verifier = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
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
