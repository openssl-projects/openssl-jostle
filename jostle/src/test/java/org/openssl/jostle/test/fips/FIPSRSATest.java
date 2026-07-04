/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA through the FIPS provider ("JSLFIPS"): keygen from the module, PKCS#1
 * v1.5 and PSS signatures and OAEP/PKCS#1 encryption agree with BouncyCastle
 * in both directions, keys round-trip through BC encodings, the module's
 * 2048-bit generation floor holds, and MD5withRSA is rejected. Gated on
 * JOSTLE_TEST_FIPS_DIR; skipped when unset.
 */
public class FIPSRSATest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static KeyPair fipsKeyPair;

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static synchronized KeyPair keyPair()
        throws Exception
    {
        if (fipsKeyPair == null)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
            kpg.initialize(2048);
            fipsKeyPair = kpg.generateKeyPair();
        }
        return fipsKeyPair;
    }

    @Test
    public void pkcs1SignaturesAgreeWithBouncyCastle()
        throws Exception
    {
        ensureProviders();
        KeyPair kp = keyPair();

        byte[] message = new byte[1 + RANDOM.nextInt(1024)];
        RANDOM.nextBytes(message);

        Signature signer = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        Signature bcVerifier = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(kp.getPublic());
        bcVerifier.update(message);
        Assertions.assertTrue(bcVerifier.verify(sig), "JSLFIPS sign -> BC verify");

        // Tampered message must fail through JSLFIPS.
        byte[] tampered = message.clone();
        tampered[RANDOM.nextInt(tampered.length)] ^= 0x01;
        Signature fipsVerifier = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsVerifier.initVerify(kp.getPublic());
        fipsVerifier.update(tampered);
        Assertions.assertFalse(fipsVerifier.verify(sig), "tampered message must not verify");

        // BC sign -> JSLFIPS verify.
        Signature bcSigner = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.initSign(kp.getPrivate());
        bcSigner.update(message);
        byte[] bcSig = bcSigner.sign();
        fipsVerifier.initVerify(kp.getPublic());
        fipsVerifier.update(message);
        Assertions.assertTrue(fipsVerifier.verify(bcSig), "BC sign -> JSLFIPS verify");
    }

    @Test
    public void pssSignaturesAgreeWithBouncyCastle()
        throws Exception
    {
        ensureProviders();
        KeyPair kp = keyPair();

        byte[] message = new byte[1 + RANDOM.nextInt(1024)];
        RANDOM.nextBytes(message);

        // Explicit params: Jostle's PSS default digest is SHA-256, BC's is
        // SHA-1, so cross-provider tests must pin the spec.
        PSSParameterSpec spec = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

        Signature signer = Signature.getInstance("RSASSA-PSS", JostleFIPSProvider.PROVIDER_NAME);
        signer.setParameter(spec);
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        Signature bcVerifier = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.setParameter(spec);
        bcVerifier.initVerify(kp.getPublic());
        bcVerifier.update(message);
        Assertions.assertTrue(bcVerifier.verify(sig), "JSLFIPS PSS sign -> BC verify");

        Signature bcSigner = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
        bcSigner.setParameter(spec);
        bcSigner.initSign(kp.getPrivate());
        bcSigner.update(message);
        byte[] bcSig = bcSigner.sign();

        Signature fipsVerifier = Signature.getInstance("RSASSA-PSS", JostleFIPSProvider.PROVIDER_NAME);
        fipsVerifier.setParameter(spec);
        fipsVerifier.initVerify(kp.getPublic());
        fipsVerifier.update(message);
        Assertions.assertTrue(fipsVerifier.verify(bcSig), "BC PSS sign -> JSLFIPS verify");
    }

    @Test
    public void oaepAndPkcs1EncryptionAgreeWithBouncyCastle()
        throws Exception
    {
        ensureProviders();
        KeyPair kp = keyPair();

        byte[] message = new byte[1 + RANDOM.nextInt(100)];
        RANDOM.nextBytes(message);

        // OAEP with explicit params (Jostle's default digest is SHA-256,
        // BC's OAEP default is SHA-1).
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher fipsEnc = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
        byte[] ct = fipsEnc.doFinal(message);

        Cipher bcDec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", BouncyCastleProvider.PROVIDER_NAME);
        bcDec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), oaep);
        Assertions.assertArrayEquals(message, bcDec.doFinal(ct), "JSLFIPS OAEP -> BC");

        Cipher bcEnc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", BouncyCastleProvider.PROVIDER_NAME);
        bcEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
        byte[] bcCt = bcEnc.doFinal(message);
        Cipher fipsDec = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsDec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), oaep);
        Assertions.assertArrayEquals(message, fipsDec.doFinal(bcCt), "BC OAEP -> JSLFIPS");

        // PKCS#1 v1.5 encryption.
        Cipher fipsP1 = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleFIPSProvider.PROVIDER_NAME);
        fipsP1.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] p1Ct = fipsP1.doFinal(message);
        Cipher bcP1 = Cipher.getInstance("RSA/ECB/PKCS1Padding", BouncyCastleProvider.PROVIDER_NAME);
        bcP1.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        Assertions.assertArrayEquals(message, bcP1.doFinal(p1Ct), "JSLFIPS PKCS1 -> BC");

        bcP1.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] bcP1Ct = bcP1.doFinal(message);
        Cipher fipsP1Dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleFIPSProvider.PROVIDER_NAME);
        fipsP1Dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        Assertions.assertArrayEquals(message, fipsP1Dec.doFinal(bcP1Ct), "BC PKCS1 -> JSLFIPS");
    }

    @Test
    public void keysRoundTripThroughBouncyCastleEncodings()
        throws Exception
    {
        ensureProviders();
        KeyPair kp = keyPair();

        // JSLFIPS encodings decode through BC and verify a JSLFIPS signature.
        KeyFactory bcKf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        byte[] message = new byte[128];
        RANDOM.nextBytes(message);
        Signature signer = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();
        Signature bcVer = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVer.initVerify(bcPub);
        bcVer.update(message);
        Assertions.assertTrue(bcVer.verify(sig), "BC-decoded public key verifies");

        // BC encodings decode through the JSLFIPS KeyFactory and sign/verify.
        KeyFactory fipsKf = KeyFactory.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        PublicKey fipsPub = fipsKf.generatePublic(new X509EncodedKeySpec(bcPub.getEncoded()));
        PrivateKey fipsPriv = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(bcPriv.getEncoded()));

        Signature fipsSigner = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsSigner.initSign(fipsPriv);
        fipsSigner.update(message);
        byte[] sig2 = fipsSigner.sign();
        Signature fipsVer = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        fipsVer.initVerify(fipsPub);
        fipsVer.update(message);
        Assertions.assertTrue(fipsVer.verify(sig2), "JSLFIPS-decoded BC keys round-trip");
    }

    @Test
    public void moduleKeySizeFloorAndUnapprovedGate()
        throws Exception
    {
        ensureProviders();

        // The FIPS module's RSA generation floor is 2048 bits, enforced at
        // the JCE boundary with a typed exception and a clear message.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        java.security.InvalidParameterException ipe = Assertions.assertThrows(
                java.security.InvalidParameterException.class, () -> kpg.initialize(1024),
                "1024-bit RSA generation must be rejected at initialize");
        Assertions.assertTrue(ipe.getMessage().contains("[2048, 16384]"),
                "message must name the JSLFIPS range, got: " + ipe.getMessage());

        // MD5withRSA is not registered by JSLFIPS...
        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> Signature.getInstance("MD5withRSA", JostleFIPSProvider.PROVIDER_NAME));
        // ... while the non-FIPS provider still serves it in the same JVM.
        Assertions.assertNotNull(Signature.getInstance("MD5withRSA", JostleProvider.PROVIDER_NAME));
    }
}
