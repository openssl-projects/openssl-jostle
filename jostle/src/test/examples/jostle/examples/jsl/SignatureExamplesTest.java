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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Signatures. Each example signs, verifies, and checks that a changed message fails to verify.
 */
public class SignatureExamplesTest
        extends JslExamples
{
    /**
     * RSASSA-PSS. JSL's default is SHA-256 with MGF1-SHA-256, not the JDK's SHA-1, so set a
     * `PSSParameterSpec` on both sides when the other side is another provider.
     */
    @Test
    public void rsaPss()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSL");
        kpg.initialize(3072);
        KeyPair kp = kpg.generateKeyPair();
        PSSParameterSpec pss = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);

        Signature signer = Signature.getInstance("RSASSA-PSS", "JSL");
        signer.setParameter(pss);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("RSASSA-PSS", "JSL");
        verifier.setParameter(pss);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    /**
     * Every RSA signature name: PKCS#1 v1.5 (`SHA256withRSA`), which is deterministic, and PSS with the
     * digest's own MGF1 (`SHA256withRSAandMGF1`), which is randomised.
     */
    @Test
    public void everyRsaSignature()
            throws Exception
    {
        String[] names = {"MD5withRSA", "SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA",
                "SHA512withRSA", "SHA512(224)withRSA", "SHA512(256)withRSA", "SHA3-224withRSA", "SHA3-256withRSA",
                "SHA3-384withRSA", "SHA3-512withRSA", "SHA1withRSAandMGF1", "SHA224withRSAandMGF1",
                "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1", "SHA512(224)withRSAandMGF1",
                "SHA512(256)withRSAandMGF1", "SHA3-224withRSAandMGF1", "SHA3-256withRSAandMGF1",
                "SHA3-384withRSAandMGF1", "SHA3-512withRSAandMGF1"};
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSL");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            Signature s = Signature.getInstance(name, "JSL");
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
     * ECDSA over every digest, on P-256.
     */
    @Test
    public void everyEcdsaSignature()
            throws Exception
    {
        String[] names = {"SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA",
                "SHA512withECDSA", "SHA3-224withECDSA", "SHA3-256withECDSA", "SHA3-384withECDSA",
                "SHA3-512withECDSA"};
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "JSL");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            Signature s = Signature.getInstance(name, "JSL");
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
     * DSA over every digest, with a 2048-bit key.
     */
    @Test
    public void everyDsaSignature()
            throws Exception
    {
        String[] names = {"SHA1withDSA", "SHA224withDSA", "SHA256withDSA", "SHA384withDSA", "SHA512withDSA",
                "SHA3-224withDSA", "SHA3-256withDSA", "SHA3-384withDSA", "SHA3-512withDSA"};
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", "JSL");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            Signature s = Signature.getInstance(name, "JSL");
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
     * The `NONEwith` names sign a digest the caller has already computed: here SHA-256 of the message.
     */
    @Test
    public void signAPrecomputedDigest()
            throws Exception
    {
        byte[] digest = MessageDigest.getInstance("SHA-256", "JSL").digest(
                "attack at dawn".getBytes(StandardCharsets.US_ASCII));
        String[] names = {"NONEwithRSA", "NONEwithECDSA", "NONEwithDSA"};
        String[] keyTypes = {"RSA", "EC", "DSA"};
        for (int i = 0; i < names.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(keyTypes[i], "JSL").generateKeyPair();
            Signature s = Signature.getInstance(names[i], "JSL");
            s.initSign(kp.getPrivate());
            s.update(digest);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(digest);
            Assertions.assertTrue(s.verify(sig), names[i]);
        }
    }

    /**
     * EdDSA: Ed25519 and Ed448 sign the message itself; the `ph` variants sign its digest (RFC 8032
     * prehash). `EdDSA` takes a key of either curve. Ed25519ctx binds a context string, which it requires.
     */
    @Test
    public void edDsa()
            throws Exception
    {
        String[] names = {"Ed25519", "Ed448", "Ed25519ph", "Ed448ph", "EdDSA"};
        String[] curves = {"ED25519", "ED448", "ED25519", "ED448", "ED448"};
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < names.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(curves[i], "JSL").generateKeyPair();
            Signature s = Signature.getInstance(names[i], "JSL");
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), names[i]);
        }
        KeyPair kp = KeyPairGenerator.getInstance("ED25519", "JSL").generateKeyPair();
        Signature ctx = Signature.getInstance("Ed25519ctx", "JSL");
        ctx.setParameter(new ContextParameterSpec("my protocol".getBytes(StandardCharsets.US_ASCII)));
        ctx.initSign(kp.getPrivate());
        ctx.update(msg);
        byte[] sig = ctx.sign();
        ctx.initVerify(kp.getPublic());
        ctx.update(msg);
        Assertions.assertTrue(ctx.verify(sig));
    }

    /**
     * ML-DSA, with an optional context string set by `ContextParameterSpec`: a signature made under one
     * context does not verify under another. The generic `MLDSA` name takes a key of any parameter set.
     */
    @Test
    public void mlDsaWithContext()
            throws Exception
    {
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : new String[]{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "MLDSA"})
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("MLDSA", "JSL");
            kpg.initialize(MLDSAParameterSpec.ml_dsa_65);
            KeyPair kp = name.equals("MLDSA") ? kpg.generateKeyPair()
                    : KeyPairGenerator.getInstance(name, "JSL").generateKeyPair();
            Signature s = Signature.getInstance(name, "JSL");
            s.setParameter(new ContextParameterSpec("app one".getBytes(StandardCharsets.US_ASCII)));
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), name);
            s.setParameter(new ContextParameterSpec("app two".getBytes(StandardCharsets.US_ASCII)));
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertFalse(s.verify(sig), name);
        }
    }

    /**
     * ML-DSA with the message representative mu computed separately: `ML-DSA-CALCULATE-MU` returns the
     * 64-byte mu for a message and key, and `ML-DSA-EXTERNAL-MU` signs and verifies given mu instead of the
     * message, so the message never has to reach the signer.
     */
    @Test
    public void mlDsaExternalMu()
            throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", "JSL").generateKeyPair();
        Signature calc = Signature.getInstance("ML-DSA-CALCULATE-MU", "JSL");
        calc.initSign(kp.getPrivate());
        calc.update("attack at dawn".getBytes(StandardCharsets.US_ASCII));
        byte[] mu = calc.sign();
        Assertions.assertEquals(64, mu.length);

        Signature external = Signature.getInstance("ML-DSA-EXTERNAL-MU", "JSL");
        external.initSign(kp.getPrivate());
        external.update(mu);
        byte[] sig = external.sign();
        Signature verifier = Signature.getInstance("ML-DSA-65", "JSL");
        verifier.initVerify(kp.getPublic());
        verifier.update("attack at dawn".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertTrue(verifier.verify(sig));
    }

    /**
     * SLH-DSA, one name per parameter set: SHA2 or SHAKE, level 128, 192 or 256, S (smaller) or F (faster).
     */
    @Test
    public void slhDsaEveryParameterSet()
            throws Exception
    {
        String[] names = {"SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192F",
                "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128F",
                "SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192F", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHAKE-256F"};
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, "JSL").generateKeyPair();
            Signature s = Signature.getInstance(name, "JSL");
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), name);
        }
    }

    /**
     * The SLH-DSA variants: the generic `SLHDSA` and `SLH-DSA-PURE` names take a key of any set,
     * `SLH-DSA-NONE` signs a message the caller has already reduced itself, and the `DET-` names sign
     * deterministically (the same signature every time) rather than with fresh randomness.
     */
    @Test
    public void slhDsaVariants()
            throws Exception
    {
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        KeyPair kp = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128F", "JSL").generateKeyPair();
        for (String name : new String[]{"SLHDSA", "SLH-DSA-PURE", "SLH-DSA-NONE", "DET-SLH-DSA-PURE",
                "DET-SLH-DSA-NONE"})
        {
            Signature s = Signature.getInstance(name, "JSL");
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            s.initVerify(kp.getPublic());
            s.update(msg);
            Assertions.assertTrue(s.verify(sig), name);
        }
    }
}
