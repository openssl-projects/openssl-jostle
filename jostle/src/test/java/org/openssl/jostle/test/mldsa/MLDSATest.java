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
            // A foreign spec with no resolvable getName() is rejected. (The
            // suffix is the anonymous class name, so match only the prefix.)
            Assertions.assertTrue(e.getMessage().startsWith("unknown algorithm:"), e.getMessage());
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
        SecureRandom sr = seededRandom("testSignVerifyWithReuse");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = new byte[1025];
        sr.nextBytes(message);


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
        SecureRandom sr = seededRandom("testSignVerifyWithContextAndReuse");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx = new byte[129];
        sr.nextBytes(ctx);

        byte[] message = new byte[1025];
        sr.nextBytes(message);


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
        SecureRandom sr = seededRandom("testSignVerifyWithCustomContextAndReuse");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx = new byte[129];
        sr.nextBytes(ctx);

        byte[] message = new byte[1025];
        sr.nextBytes(message);


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
        SecureRandom sr = seededRandom("testSingleByteUpdateSign");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

        byte[] message = new byte[1025];
        sr.nextBytes(message);

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
        SecureRandom sr = seededRandom("testSingleByteUpdateVerify");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        KeyFactory factory = KeyFactory.getInstance("MLDSA", "BC");
        PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));


        byte[] message = new byte[1025];
        sr.nextBytes(message);


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


    /**
     * Streaming chunking matrix per CLAUDE.md, iterated over every
     * ML-DSA parameter set. ML-DSA's mu computation absorbs the
     * message via SHAKE-256 — adversarial chunks around 136 (the SHAKE
     * rate, "block size" for absorption purposes) pivot the
     * partial-block path. Each chunked signature is verified through
     * the one-shot verify path; then a pinned signature is verified
     * through every chunking strategy.
     */
    @Test
    public void testMLDSA_ChunkingMatrix_allVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testMLDSA_ChunkingMatrix_allVerify");
        for (MLDSAParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] msg = new byte[1024];
            sr.nextBytes(msg);

            int[] chunks = {1, 135, 136, 137, 271, 272, 273, msg.length};

            // Sign-side chunking matrix.
            for (int chunk : chunks)
            {
                byte[] sig = signWithChunking("MLDSA", keyPair, msg, chunk);
                Assertions.assertTrue(verifyOneShot("MLDSA", keyPair, msg, sig),
                        spec + " sign-chunk=" + chunk + ": chunked-signed signature did not verify");
            }
            for (int trial = 0; trial < 5; trial++)
            {
                byte[] sig = signWithRandomSplits("MLDSA", sr, keyPair, msg);
                Assertions.assertTrue(verifyOneShot("MLDSA", keyPair, msg, sig),
                        spec + " random-split trial=" + trial + ": signature did not verify");
            }

            // Verify-side chunking matrix.
            byte[] oneSig = signOneShot("MLDSA", keyPair, msg);
            for (int chunk : chunks)
            {
                Assertions.assertTrue(verifyWithChunking("MLDSA", keyPair, msg, oneSig, chunk),
                        spec + " verify-chunk=" + chunk + ": chunked verify diverged from one-shot");
            }
            for (int trial = 0; trial < 5; trial++)
            {
                Assertions.assertTrue(verifyWithRandomSplits("MLDSA", sr, keyPair, msg, oneSig),
                        spec + " random-split verify trial=" + trial + ": verify diverged");
            }
        }
    }

    private static byte[] signOneShot(String alg, KeyPair kp, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        return signer.sign();
    }

    private static byte[] signWithChunking(String alg, KeyPair kp, byte[] msg, int chunk) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            signer.update(msg, off, len);
        }
        return signer.sign();
    }

    private static byte[] signWithRandomSplits(String alg, SecureRandom sr, KeyPair kp, byte[] msg) throws Exception
    {
        Signature signer = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        int pos = 0;
        while (pos < msg.length)
        {
            int remaining = msg.length - pos;
            int chunk = 1 + sr.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            signer.update(msg, pos, chunk);
            pos += chunk;
        }
        return signer.sign();
    }

    private static boolean verifyOneShot(String alg, KeyPair kp, byte[] msg, byte[] sig) throws Exception
    {
        Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        return verifier.verify(sig);
    }

    private static boolean verifyWithChunking(String alg, KeyPair kp, byte[] msg, byte[] sig, int chunk)
            throws Exception
    {
        Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            verifier.update(msg, off, len);
        }
        return verifier.verify(sig);
    }

    private static boolean verifyWithRandomSplits(String alg, SecureRandom sr, KeyPair kp, byte[] msg, byte[] sig)
            throws Exception
    {
        Signature verifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        int pos = 0;
        while (pos < msg.length)
        {
            int remaining = msg.length - pos;
            int chunk = 1 + sr.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            verifier.update(msg, pos, chunk);
            pos += chunk;
        }
        return verifier.verify(sig);
    }


    @Test
    public void testCalculateRawMu() throws Exception
    {
        SecureRandom sr = seededRandom("testCalculateRawMu");
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

            // Random content AND random length per CLAUDE.md "Random message
            // content AND length" — a single fixed message would miss bugs in
            // mu computation that ignores parts of the input, or external-mu
            // sign/verify desync tied to message-bit patterns.
            byte[] msg = new byte[16 + sr.nextInt(256)];
            sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testCalculateRawMuProxyKey");
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

            // Random content AND random length per CLAUDE.md "Random message
            // content AND length" — a single fixed message would miss bugs in
            // mu computation that ignores parts of the input, or external-mu
            // sign/verify desync tied to message-bit patterns.
            byte[] msg = new byte[16 + sr.nextInt(256)];
            sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testKeyGen");
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

            sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testKeyRecovery");
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
            sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testLoadRawKey");

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
            sr.nextBytes(msg);
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

        SecureRandom sr = seededRandom("testChangeContextAfterTakingSignature");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx1 = new byte[129];
        sr.nextBytes(ctx1);

        byte[] ctx2 = new byte[65];
        sr.nextBytes(ctx2);

        byte[] message = new byte[1025];
        sr.nextBytes(message);

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
        SecureRandom sr = seededRandom("testChangeContextToNullAfterTakingSignature");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx1 = new byte[129];
        sr.nextBytes(ctx1);

        byte[] message = new byte[1025];
        sr.nextBytes(message);

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

    private void crossProviderVerification(String algoName, MLDSAParameterSpec specJostle, org.bouncycastle.jcajce.spec.MLDSAParameterSpec specBC, SecureRandom sr) throws Exception
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
        sr.nextBytes(msg);


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

    private void crossProviderVerificationWithContext(String algoName, MLDSAParameterSpec specJostle, org.bouncycastle.jcajce.spec.MLDSAParameterSpec specBC, byte[] ctx, SecureRandom sr) throws Exception
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
        sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testMLDSASignature");

        crossProviderVerification("ML-DSA", MLDSAParameterSpec.ml_dsa_44, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44, sr);
        crossProviderVerification("ML-DSA", MLDSAParameterSpec.ml_dsa_65, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65, sr);
        crossProviderVerification("ML-DSA", MLDSAParameterSpec.ml_dsa_87, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87, sr);


        for (int ctxLen = 0; ctxLen < 256; ctxLen++)
        {

            byte[] ctx = new byte[ctxLen];
            sr.nextBytes(ctx);

            crossProviderVerificationWithContext("ML-DSA", MLDSAParameterSpec.ml_dsa_44, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_44, ctx, sr);
            crossProviderVerificationWithContext("ML-DSA", MLDSAParameterSpec.ml_dsa_65, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_65, ctx, sr);
            crossProviderVerificationWithContext("ML-DSA", MLDSAParameterSpec.ml_dsa_87, org.bouncycastle.jcajce.spec.MLDSAParameterSpec.ml_dsa_87, ctx, sr);
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
        SecureRandom sr = seededRandom("testSeedOnlyKeyEncoding");
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

            sr.nextBytes(msg);

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


    @Test
    public void testEmptyMessageSignVerify() throws Exception
    {
        // Sign with no preceding update — valid usage that exercises the
        // SHAKE-256 finalisation with no message bytes accumulated. Cross-checks
        // against BC ensure the empty-input encoding is interop-compatible.
        for (MLDSAParameterSpec spec : joSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Roundtrip the keys through BC so we can sign/verify on the BC side.
            KeyFactory bcFactory = KeyFactory.getInstance("MLDSA", BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey privKeyBC = bcFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));
            PublicKey pubKeyBC = bcFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));

            // Jostle sign empty.
            Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            signature.initSign(keyPair.getPrivate());
            byte[] jostleSig = signature.sign();
            Assertions.assertNotNull(jostleSig);
            Assertions.assertTrue(jostleSig.length > 0);

            // Jostle verifies its own empty-message signature.
            Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
            verifier.initVerify(keyPair.getPublic());
            Assertions.assertTrue(verifier.verify(jostleSig));

            // BC verifies Jostle's empty-message signature.
            Signature bcVerifier = Signature.getInstance("MLDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcVerifier.initVerify(pubKeyBC);
            Assertions.assertTrue(bcVerifier.verify(jostleSig));

            // BC signs empty, Jostle verifies — confirms the reverse interop.
            Signature bcSigner = Signature.getInstance("MLDSA", BouncyCastleProvider.PROVIDER_NAME);
            bcSigner.initSign(privKeyBC);
            byte[] bcSig = bcSigner.sign();

            verifier.initVerify(keyPair.getPublic());
            Assertions.assertTrue(verifier.verify(bcSig));

            // Sanity: a verifier fed a non-empty message must reject the
            // empty-message signature, so the previous accepts aren't trivial.
            verifier.initVerify(keyPair.getPublic());
            verifier.update((byte) 0x01);
            Assertions.assertFalse(verifier.verify(jostleSig));
        }
    }


    @Test
    public void testUpdateSliceVariant() throws Exception
    {
        // The 3-arg update(buf, off, len) flows through a different JNI path
        // than update(buf). Confirms the slice indexing matches the contiguous
        // form for both signer and verifier.
        SecureRandom sr = seededRandom("testUpdateSliceVariant");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = new byte[513];
        sr.nextBytes(message);

        // Embed the message inside a larger buffer with leading + trailing pad.
        byte[] padded = new byte[message.length + 64];
        sr.nextBytes(padded);
        System.arraycopy(message, 0, padded, 32, message.length);

        Signature signature = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.update(padded, 32, message.length);
        byte[] sig = signature.sign();

        // Verify using the contiguous form to confirm the slice was equivalent.
        Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig));

        // And verify in slice form too.
        verifier.initVerify(keyPair.getPublic());
        verifier.update(padded, 32, message.length);
        Assertions.assertTrue(verifier.verify(sig));

        // Wrong slice (off-by-one) must fail.
        verifier.initVerify(keyPair.getPublic());
        verifier.update(padded, 33, message.length);
        Assertions.assertFalse(verifier.verify(sig));
    }


    @Test
    public void testExternalMuZeroLengthUpdate() throws Exception
    {
        // Regression: a zero-length update in EXTERNAL_MU mode must be a
        // no-op, not a JO_OPENSSL_ERROR. The native BIO_write(...,0) returns
        // 0, which an earlier truthy-check incorrectly treated as failure.
        SecureRandom sr = seededRandom("testExternalMuZeroLengthUpdate");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] mu = new byte[64];
        sr.nextBytes(mu);

        Signature signature = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());

        // Empty updates either side of the real Mu must not error.
        signature.update(new byte[0]);
        signature.update(mu);
        signature.update(new byte[0]);
        byte[] sig = signature.sign();

        // Verify with EXTERNAL_MU using the same Mu — confirms the empty
        // updates didn't perturb the buffered bytes.
        Signature verifier = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(new byte[0]);
        verifier.update(mu);
        verifier.update(new byte[0]);
        Assertions.assertTrue(verifier.verify(sig));
    }


    @Test
    public void testExternalMuWrongLength() throws Exception
    {
        // EXTERNAL_MU mode requires exactly 64 bytes accumulated before sign().
        // The native JO_EXTERNAL_MU_INVALID_LEN must surface to the JCE caller
        // as IllegalArgumentException.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        Signature signature = Signature.getInstance("ML-DSA-EXTERNAL-MU", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.update(new byte[63]); // one byte short

        try
        {
            signature.sign();
            Assertions.fail();
        }
        catch (Exception e)
        {
            Throwable cause = e instanceof SignatureException && e.getCause() != null ? e.getCause() : e;
            Assertions.assertEquals("external Mu invalid length", cause.getMessage());
        }
    }


    @Test
    public void testReinitFlipsDirection() throws Exception
    {
        // Re-initialising an existing Signature must reset the underlying ctx
        // cleanly — no stale hash/mu_buf leaking from the previous direction.
        SecureRandom sr = seededRandom("testReinitFlipsDirection");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = new byte[256];
        sr.nextBytes(message);

        Signature instance = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);

        // Sign first.
        instance.initSign(keyPair.getPrivate());
        instance.update(message);
        byte[] sig = instance.sign();

        // Same instance, flip to verify.
        instance.initVerify(keyPair.getPublic());
        instance.update(message);
        Assertions.assertTrue(instance.verify(sig));

        // Flip back to sign and produce a fresh signature.
        instance.initSign(keyPair.getPrivate());
        instance.update(message);
        byte[] sig2 = instance.sign();

        // Independent verifier confirms the new signature.
        Signature verifier = Signature.getInstance("MLDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig2));
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
