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

package jostle.examples.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Signatures in the FIPS module. The 3.5.8 module signs with SHA-2 and SHA-3 digests and verifies SHA-1 ones;
 * it verifies DSA signatures but does not make them; and it verifies but does not make signatures on curves
 * below 112 bits of strength. Each example signs, verifies, and checks that a changed message fails.
 */
public class FipsSignatureExamplesTest
        extends FipsExamples
{
    /**
     * RSASSA-PSS with an explicit `PSSParameterSpec`, so both sides agree whatever their defaults.
     */
    @Test
    public void rsaPss()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSLFIPS");
        kpg.initialize(3072);
        KeyPair kp = kpg.generateKeyPair();
        Signature s = Signature.getInstance("RSASSA-PSS", "JSLFIPS");
        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        s.initSign(kp.getPrivate());
        s.update("attack at dawn".getBytes(StandardCharsets.US_ASCII));
        byte[] sig = s.sign();
        s.initVerify(kp.getPublic());
        s.update("attack at dawn".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertTrue(s.verify(sig));
    }

    /**
     * RSA signatures, PKCS#1 v1.5 and PSS, over every SHA-2 and SHA-3 digest.
     */
    @Test
    public void everyRsaSignature()
            throws Exception
    {
        String[] names = {"SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA512(224)withRSA",
                "SHA512(256)withRSA", "SHA3-224withRSA", "SHA3-256withRSA", "SHA3-384withRSA", "SHA3-512withRSA",
                "SHA224withRSAandMGF1", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1",
                "SHA512(224)withRSAandMGF1", "SHA512(256)withRSAandMGF1", "SHA3-224withRSAandMGF1",
                "SHA3-256withRSAandMGF1", "SHA3-384withRSAandMGF1", "SHA3-512withRSAandMGF1"};
        KeyPair kp = KeyPairGenerator.getInstance("RSA", "JSLFIPS").generateKeyPair();
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            Signature s = Signature.getInstance(name, "JSLFIPS");
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), name);
            s.initVerify(kp.getPublic());
            s.update("attack at dusk".getBytes(StandardCharsets.US_ASCII));
            Assertions.assertFalse(s.verify(sig), name);
        }
    }

    /**
     * ECDSA over every SHA-2 and SHA-3 digest.
     */
    @Test
    public void everyEcdsaSignature()
            throws Exception
    {
        String[] names = {"SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA",
                "SHA3-224withECDSA", "SHA3-256withECDSA", "SHA3-384withECDSA", "SHA3-512withECDSA"};
        KeyPair kp = KeyPairGenerator.getInstance("EC", "JSLFIPS").generateKeyPair();
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            Signature s = Signature.getInstance(name, "JSLFIPS");
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), name);
            s.initVerify(kp.getPublic());
            s.update("attack at dusk".getBytes(StandardCharsets.US_ASCII));
            Assertions.assertFalse(s.verify(sig), name);
        }
    }

    /**
     * SHA-1 signatures, for verifying existing ones: JSLFIPS verifies them, and refuses to make them with
     * `InvalidKeyException` at `initSign`. Here JSL signs and JSLFIPS verifies, with the key moved across.
     */
    @Test
    public void sha1IsVerifyOnly()
            throws Exception
    {
        String[] names = {"SHA1withRSA", "SHA1withRSAandMGF1", "SHA1withECDSA"};
        String[] keyTypes = {"RSA", "RSA", "EC"};
        byte[] msg = "an old document".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < names.length; i++)
        {
            KeyPair jsl = KeyPairGenerator.getInstance(keyTypes[i], "JSL").generateKeyPair();
            Signature signer = Signature.getInstance(names[i], "JSL");
            signer.initSign(jsl.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();
            KeyFactory kf = KeyFactory.getInstance(keyTypes[i], "JSLFIPS");
            Signature v = Signature.getInstance(names[i], "JSLFIPS");
            v.initVerify(kf.generatePublic(new X509EncodedKeySpec(jsl.getPublic().getEncoded())));
            v.update(msg);
            Assertions.assertTrue(v.verify(sig), names[i]);
            PrivateKey fipsPrivate = kf.generatePrivate(new PKCS8EncodedKeySpec(jsl.getPrivate().getEncoded()));
            Assertions.assertThrows(InvalidKeyException.class, () -> v.initSign(fipsPrivate), names[i]);
        }
    }

    /**
     * DSA signatures are verify-only in the 3.5.8 module. A DSA key and signature made with JSL, verified by
     * JSLFIPS over every digest; `NONEwithDSA` verifies a signature over a digest computed by the caller.
     */
    @Test
    public void dsaIsVerifyOnly()
            throws Exception
    {
        String[] names = {"SHA1withDSA", "SHA224withDSA", "SHA256withDSA", "SHA384withDSA", "SHA512withDSA",
                "SHA3-224withDSA", "SHA3-256withDSA", "SHA3-384withDSA", "SHA3-512withDSA", "NONEwithDSA"};
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", "JSL");
        kpg.initialize(2048);
        KeyPair jsl = kpg.generateKeyPair();
        PublicKey pub = KeyFactory.getInstance("DSA", "JSLFIPS").generatePublic(
                new X509EncodedKeySpec(jsl.getPublic().getEncoded()));
        byte[] msg = MessageDigest.getInstance("SHA-256", "JSLFIPS").digest(new byte[]{1, 2, 3});
        for (String name : names)
        {
            Signature signer = Signature.getInstance(name, "JSL");
            signer.initSign(jsl.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();
            Signature v = Signature.getInstance(name, "JSLFIPS");
            v.initVerify(pub);
            v.update(msg);
            Assertions.assertTrue(v.verify(sig), name);
        }
    }

    /**
     * `NONEwithRSA` and `NONEwithECDSA` sign a digest the caller has already computed, here SHA-256.
     */
    @Test
    public void signAPrecomputedDigest()
            throws Exception
    {
        byte[] digest = MessageDigest.getInstance("SHA-256", "JSLFIPS").digest(
                "attack at dawn".getBytes(StandardCharsets.US_ASCII));
        String[] names = {"NONEwithRSA", "NONEwithECDSA"};
        String[] keyTypes = {"RSA", "EC"};
        for (int i = 0; i < names.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(keyTypes[i], "JSLFIPS").generateKeyPair();
            Signature s = Signature.getInstance(names[i], "JSLFIPS");
            s.initSign(kp.getPrivate());
            s.update(digest);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(digest);
            Assertions.assertTrue(s.verify(sig), names[i]);
        }
    }

    /**
     * Curves below 112 bits of strength, such as secp192r1, are verify-only: JSLFIPS verifies a signature made
     * elsewhere and refuses to sign with `InvalidKeyException`.
     */
    @Test
    public void weakCurvesAreVerifyOnly()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "JSL");
        kpg.initialize(new ECGenParameterSpec("secp192r1"));
        KeyPair jsl = kpg.generateKeyPair();
        Signature signer = Signature.getInstance("SHA256withECDSA", "JSL");
        signer.initSign(jsl.getPrivate());
        signer.update(new byte[]{1, 2, 3});
        byte[] sig = signer.sign();

        KeyFactory kf = KeyFactory.getInstance("EC", "JSLFIPS");
        Signature v = Signature.getInstance("SHA256withECDSA", "JSLFIPS");
        v.initVerify(kf.generatePublic(new X509EncodedKeySpec(jsl.getPublic().getEncoded())));
        v.update(new byte[]{1, 2, 3});
        Assertions.assertTrue(v.verify(sig));
        PrivateKey weak = kf.generatePrivate(new PKCS8EncodedKeySpec(jsl.getPrivate().getEncoded()));
        Assertions.assertThrows(InvalidKeyException.class, () -> v.initSign(weak));
    }

    /**
     * EdDSA: Ed25519, Ed448, their prehash variants, and `EdDSA` for either curve.
     */
    @Test
    public void edDsa()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("Signature", "ED25519") != null);
        String[] names = {"Ed25519", "Ed448", "Ed25519ph", "Ed448ph", "EdDSA"};
        String[] curves = {"ED25519", "ED448", "ED25519", "ED448", "ED25519"};
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < names.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(curves[i], "JSLFIPS").generateKeyPair();
            Signature s = Signature.getInstance(names[i], "JSLFIPS");
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), names[i]);
        }
    }

    /**
     * ML-DSA with a context string, and the generic `MLDSA` name for any parameter set.
     */
    @Test
    public void mlDsaWithContext()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("Signature", "ML-DSA-65") != null);
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : new String[]{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "MLDSA"})
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("MLDSA", "JSLFIPS");
            kpg.initialize(MLDSAParameterSpec.ml_dsa_65);
            KeyPair kp = name.equals("MLDSA") ? kpg.generateKeyPair()
                    : KeyPairGenerator.getInstance(name, "JSLFIPS").generateKeyPair();
            Signature s = Signature.getInstance(name, "JSLFIPS");
            s.setParameter(new ContextParameterSpec("app one".getBytes(StandardCharsets.US_ASCII)));
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), name);
        }
    }

    /**
     * ML-DSA with mu computed separately (`ML-DSA-CALCULATE-MU`) and signed without the message
     * (`ML-DSA-EXTERNAL-MU`).
     */
    @Test
    public void mlDsaExternalMu()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("Signature", "ML-DSA-65") != null);
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", "JSLFIPS").generateKeyPair();
        Signature calc = Signature.getInstance("ML-DSA-CALCULATE-MU", "JSLFIPS");
        calc.initSign(kp.getPrivate());
        calc.update("attack at dawn".getBytes(StandardCharsets.US_ASCII));
        byte[] mu = calc.sign();
        Signature external = Signature.getInstance("ML-DSA-EXTERNAL-MU", "JSLFIPS");
        external.initSign(kp.getPrivate());
        external.update(mu);
        byte[] sig = external.sign();
        Signature verifier = Signature.getInstance("ML-DSA-65", "JSLFIPS");
        verifier.initVerify(kp.getPublic());
        verifier.update("attack at dawn".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertTrue(verifier.verify(sig));
    }

    /**
     * SLH-DSA, one name per parameter set.
     */
    @Test
    public void slhDsaEveryParameterSet()
            throws Exception
    {
        Assumptions.assumeTrue(
                Security.getProvider("JSLFIPS").getService("Signature", "SLH-DSA-SHA2-128F") != null);
        String[] names = {"SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192F",
                "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128F",
                "SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192F", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHAKE-256F"};
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, "JSLFIPS").generateKeyPair();
            Signature s = Signature.getInstance(name, "JSLFIPS");
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), name);
        }
    }

    /**
     * The SLH-DSA variants: generic, pure, pre-reduced input, and deterministic.
     */
    @Test
    public void slhDsaVariants()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("Signature", "SLH-DSA-PURE") != null);
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        KeyPair kp = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128F", "JSLFIPS").generateKeyPair();
        for (String name : new String[]{"SLHDSA", "SLH-DSA-PURE", "SLH-DSA-NONE", "DET-SLH-DSA-PURE",
                "DET-SLH-DSA-NONE"})
        {
            Signature s = Signature.getInstance(name, "JSLFIPS");
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), name);
        }
    }
}
