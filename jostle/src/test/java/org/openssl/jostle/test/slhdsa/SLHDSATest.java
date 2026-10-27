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

package org.openssl.jostle.test.slhdsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.SLHDSAPublicKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.SLHDSAPrivateKeySpec;
import org.openssl.jostle.jcajce.spec.SLHDSAPublicKeySpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class SLHDSATest
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
            // A foreign key goes through the factory; the refusal names the class, never the key.
            Assertions.assertEquals("unable to translate " + publicKey.getClass().getName() + " to an SLH-DSA key",
                    e.getMessage());
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
            Assertions.assertEquals("unable to translate " + publicKey.getClass().getName() + " to an SLH-DSA key",
                    e.getMessage());
        }
    }


    @Test
    public void testSignVerifyWithReuse() throws Exception
    {
        SecureRandom sr = seededRandom("testSignVerifyWithReuse");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] message = new byte[1025];
        sr.nextBytes(message);


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
        SecureRandom sr = seededRandom("testSignVerifyWithContextAndReuse");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx = new byte[129];
        sr.nextBytes(ctx);

        byte[] message = new byte[1025];
        sr.nextBytes(message);


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


    /**
     * Streaming chunking matrix per CLAUDE.md. SLH-DSA is randomized
     * (a per-signature pseudo-random nonce R is sampled), so we can't
     * byte-compare signatures across runs. Instead, sign each chunking
     * pattern and verify each resulting signature through the one-shot
     * verify path; then sign once and verify the SAME signature
     * through every chunking strategy. The SHA-2 variants absorb the
     * message via SHA-256 (block = 64 bytes); use 64 as the adversarial
     * pivot. We exercise one of the "fast" variants to keep CI time
     * reasonable — the streaming-input path is the same shape across
     * every parameter set.
     */
    @Test
    public void testSLHDSA_ChunkingMatrix_allVerify() throws Exception
    {
        SecureRandom sr = seededRandom("testSLHDSA_ChunkingMatrix_allVerify");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] msg = new byte[1024];
        sr.nextBytes(msg);

        int[] chunks = {1, 63, 64, 65, 127, 128, 129, msg.length};

        // Sign-side chunking matrix.
        for (int chunk : chunks)
        {
            byte[] sig = signWithChunking("SLHDSA", keyPair, msg, chunk);
            Assertions.assertTrue(verifyOneShot("SLHDSA", keyPair, msg, sig),
                    "sign-chunk=" + chunk + ": chunked-signed signature did not verify");
        }
        for (int trial = 0; trial < 5; trial++)
        {
            byte[] sig = signWithRandomSplits("SLHDSA", sr, keyPair, msg);
            Assertions.assertTrue(verifyOneShot("SLHDSA", keyPair, msg, sig),
                    "random-split trial=" + trial + ": signature did not verify");
        }

        // Verify-side chunking matrix.
        byte[] oneSig = signOneShot("SLHDSA", keyPair, msg);
        for (int chunk : chunks)
        {
            Assertions.assertTrue(verifyWithChunking("SLHDSA", keyPair, msg, oneSig, chunk),
                    "verify-chunk=" + chunk + ": chunked verify diverged from one-shot");
        }
        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertTrue(verifyWithRandomSplits("SLHDSA", sr, keyPair, msg, oneSig),
                    "random-split verify trial=" + trial + ": verify diverged");
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

        SecureRandom sr = seededRandom("testChangeContextAfterTakingSignature");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
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
        SecureRandom sr = seededRandom("testChangeContextToNullAfterTakingSignature");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLHDSA", JostleProvider.PROVIDER_NAME);
        keyGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] ctx1 = new byte[129];
        sr.nextBytes(ctx1);

        byte[] message = new byte[1025];
        sr.nextBytes(message);

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
        // Signature.verify declares SignatureException; the bridge's refusal travels as the cause.
        SignatureException e = Assertions.assertThrows(SignatureException.class, () -> signature.verify(null));
        Assertions.assertEquals("sig is null", e.getMessage());
        Assertions.assertEquals(IllegalArgumentException.class, e.getCause().getClass());
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
        SecureRandom sr = seededRandom("testDeterministic");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SLH-DSA", JostleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128s);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();


        Signature signature = Signature.getInstance("DET-SLH-DSA-PURE", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());

        byte[] messageBytes = new byte[65];
        sr.nextBytes(messageBytes);
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
        SecureRandom sr = seededRandom("testNondeterministicByDefault");
        for (SLHDSAParameterSpec spec : SLHDSAParameterSpec.getParameterSpecs())
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(spec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            byte[] messageBytes = new byte[65];
            sr.nextBytes(messageBytes);

            Signature signature = Signature.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME);
            signature.initSign(keyPair.getPrivate());

            signature.update(messageBytes, 0, messageBytes.length);
            byte[] signatureByte1 = signature.sign();

            signature.update(messageBytes, 0, messageBytes.length);
            byte[] signatureBytes2 = signature.sign();

            Assertions.assertFalse(Arrays.areEqual(signatureByte1, signatureBytes2));

        }
    }


    @Test
    public void rawKeySpecRoundTrip() throws Exception
    {
        // Regression for the SLHDSAPrivateKeySpec(params, data) constructor,
        // which previously rejected every valid SLH-DSA private encoding with a
        // copy-pasted 32-byte "seed" check. Extract the raw KeySpecs from a
        // generated key and rebuild working keys from them — both halves, both
        // directions through the KeyFactory — then prove sign/verify works and a
        // tampered message fails.
        SecureRandom sr = seededRandom("rawKeySpecRoundTrip");

        for (SLHDSAParameterSpec spec : new SLHDSAParameterSpec[]{
                SLHDSAParameterSpec.slh_dsa_sha2_128f,
                SLHDSAParameterSpec.slh_dsa_shake_192f})
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME);
            kpg.initialize(spec, sr);
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME);

            // key -> raw KeySpec -> key (both halves).
            SLHDSAPrivateKeySpec privSpec = kf.getKeySpec(kp.getPrivate(), SLHDSAPrivateKeySpec.class);
            SLHDSAPublicKeySpec pubSpec = kf.getKeySpec(kp.getPublic(), SLHDSAPublicKeySpec.class);

            PrivateKey priv = kf.generatePrivate(privSpec);
            PublicKey pub = kf.generatePublic(pubSpec);

            byte[] msg = new byte[137];
            sr.nextBytes(msg);

            Signature signer = Signature.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME);
            signer.initSign(priv, sr);
            signer.update(msg);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME);
            verifier.initVerify(pub);
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig), spec.getName() + " reconstructed key failed to verify");

            byte[] tampered = Arrays.clone(msg);
            tampered[0] ^= 1;
            Signature verifier2 = Signature.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME);
            verifier2.initVerify(pub);
            verifier2.update(tampered);
            Assertions.assertFalse(verifier2.verify(sig), spec.getName() + " tampered message verified");
        }
    }

    /**
     * The two raw encodings answer FIPS 205's sizes per set (2n public, 4n private), and each equals the length the
     * library reported first for that type and part, which bounds every later answer.
     */
    @Test
    public void rawKeyLengthsEqualTheMemoPerSet() throws Exception
    {
        SLHDSAServiceNI ni = NISelector.SLHDSAServiceNI;
        for (SLHDSAParameterSpec spec : joSpec)
        {
            KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME).generateKeyPair();
            String type = spec.getKeyType().name();
            int n = spec.getName().contains("128") ? 16 : spec.getName().contains("192") ? 24 : 32;
            byte[] pub = ((SLHDSAPublicKey) kp.getPublic()).getPublicData();
            byte[] priv = KeyFactory.getInstance(spec.getName(), JostleProvider.PROVIDER_NAME)
                    .getKeySpec(kp.getPrivate(), SLHDSAPrivateKeySpec.class).getPrivateData();
            Assertions.assertEquals(2 * n, pub.length, spec.getName());
            Assertions.assertEquals(4 * n, priv.length, spec.getName());
            Assertions.assertEquals(2 * n, ni.keyLengthCache().get(type + "/PUBLIC"), spec.getName());
            Assertions.assertEquals(4 * n, ni.keyLengthCache().get(type + "/PRIVATE"), spec.getName());
        }
    }

    /**
     * A refused init leaves the previous key in place: setParameter then re-initialises on that key instead of
     * failing, and the session still signs (the ML-DSA shape).
     */
    @Test
    public void aRefusedInitKeepsThePreviousKey() throws Exception
    {
        KeyPair good = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128F", JostleProvider.PROVIDER_NAME)
                .generateKeyPair();
        PublicKey other = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", JostleProvider.PROVIDER_NAME)
                .generateKeyPair().getPublic();
        Signature s = Signature.getInstance("SLH-DSA-SHA2-128F", JostleProvider.PROVIDER_NAME);
        s.initSign(good.getPrivate());
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class, () -> s.initVerify(other));
        Assertions.assertEquals("required SLH-DSA-SHA2-128F key type but got SLH-DSA-SHA2-128S", e.getMessage());

        byte[] ctx = {7, 7};
        s.setParameter(new ContextParameterSpec(ctx));
        byte[] msg = {1, 2, 3};
        s.update(msg);
        byte[] sig = s.sign();
        Signature v = Signature.getInstance("SLH-DSA-SHA2-128F", JostleProvider.PROVIDER_NAME);
        v.setParameter(new ContextParameterSpec(ctx));
        v.initVerify(good.getPublic());
        v.update(msg);
        Assertions.assertTrue(v.verify(sig));
    }
}
