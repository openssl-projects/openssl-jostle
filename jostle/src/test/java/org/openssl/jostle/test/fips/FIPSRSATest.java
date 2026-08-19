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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA through the FIPS provider ("JSLFIPS"): keygen from the module, PKCS#1
 * v1.5 and PSS signatures and OAEP/PKCS#1 encryption agree with BouncyCastle
 * in both directions, keys round-trip through BC encodings, the module's
 * 2048-bit generation floor holds, and MD5withRSA is rejected. Gated on
 * TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSRSATest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static KeyPair fipsKeyPair;

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        ensureProviders();
    }

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
    public void oaepEncryptionAgreesWithBouncyCastle()
        throws Exception
    {
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
    }

    @Test
    public void keysRoundTripThroughBouncyCastleEncodings()
        throws Exception
    {
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

        // PKCS#1 v1.5 ENCRYPTION is not an approved RSA key-transport scheme in
        // the 3.1.2 module (OAEP only, KTS-4 / SP 800-56Br2 — cert #4985), so
        // JSLFIPS does not register it. JSLFIPS registers only the bare "RSA"
        // (OAEP) primary, so the transformation resolves via JCE form-4 fallback
        // to that OAEP SPI, whose engineSetPadding rejects "PKCS1Padding" with
        // NoSuchPaddingException — i.e. PKCS#1 v1.5 encryption is unobtainable.
        // (Common supertype since form-4 rejection surfaces as NoSuchPadding,
        // not NoSuchAlgorithm.) The non-FIPS provider still serves it.
        Assertions.assertThrows(java.security.GeneralSecurityException.class,
                () -> Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleFIPSProvider.PROVIDER_NAME),
                "PKCS#1 v1.5 RSA encryption must be absent from JSLFIPS (non-approved)");
        Assertions.assertNotNull(Cipher.getInstance("RSA/ECB/PKCS1Padding", JostleProvider.PROVIDER_NAME),
                "the non-FIPS provider still serves PKCS#1 v1.5 RSA encryption");
        // OAEP (the approved scheme) remains available through the bare "RSA".
        Assertions.assertNotNull(Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME),
                "OAEP (bare RSA) must remain available in JSLFIPS");
    }


    // -----------------------------------------------------------------
    // Wrong-key-type / wrong-direction rejection (provider-fallback contract)
    // -----------------------------------------------------------------

    /**
     * Mirrors RSATest.testInitSign_rejectsNonRSAKey / testInitVerify_rejectsNonRSAKey:
     * a non-RSA key handed to the RSA Signature SPI must surface as
     * InvalidKeyException (the type the JCE keys provider-chain fallback on),
     * not ProviderException / ClassCastException / NPE.
     */
    @Test
    public void signatureRejectsNonRsaKey()
        throws Exception
    {
        // A clearly-foreign (EC) key from the SAME FIPS provider.
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", JostleFIPSProvider.PROVIDER_NAME);
        ec.initialize(256);
        KeyPair ecKp = ec.generateKeyPair();

        Signature signer = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> signer.initSign(ecKp.getPrivate()),
                "non-RSA private key must be rejected with InvalidKeyException");

        Signature verifier = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> verifier.initVerify(ecKp.getPublic()),
                "non-RSA public key must be rejected with InvalidKeyException");
    }

    /**
     * Mirrors RSAOAEPCipherTest.testOAEP_Decrypt_rejectsPublicKey /
     * testOAEP_Encrypt_rejectsPrivateKey: initialising the OAEP Cipher with a
     * key of the wrong direction must throw InvalidKeyException.
     */
    @Test
    public void oaepCipherRejectsWrongDirectionKey()
        throws Exception
    {
        KeyPair kp = keyPair();

        Cipher dec = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> dec.init(Cipher.DECRYPT_MODE, kp.getPublic()),
                "decrypt with a public key must be rejected");

        Cipher enc = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> enc.init(Cipher.ENCRYPT_MODE, kp.getPrivate()),
                "encrypt with a private key must be rejected");
    }

    /**
     * Mirrors RSAOAEPCipherTest.testOAEP_WrapUnwrap_AESSecretKey_roundTrip /
     * testOAEP_Unwrap_VandalisedCiphertext_throwsInvalidKey: OAEP wrap/unwrap of
     * an AES key round-trips, and a tampered wrapped blob fails engineUnwrap with
     * InvalidKeyException (NOT BadPaddingException) — the Bleichenbacher-channel
     * collapse rule.
     */
    @Test
    public void oaepUnwrapVandalisedCiphertextThrowsInvalidKey()
        throws Exception
    {
        KeyPair kp = keyPair();

        KeyGenerator kg = KeyGenerator.getInstance("AES", JostleFIPSProvider.PROVIDER_NAME);
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        OAEPParameterSpec oaep = oaepSpec("SHA-256");

        Cipher wrapper = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        wrapper.init(Cipher.WRAP_MODE, kp.getPublic(), oaep);
        byte[] wrapped = wrapper.wrap(aesKey);
        Assertions.assertEquals(256, wrapped.length, "wrapped key sized to modulus");

        Cipher unwrapper = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        unwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate(), oaep);
        Key unwrapped = unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertEquals("AES", unwrapped.getAlgorithm());
        Assertions.assertTrue(Arrays.areEqual(aesKey.getEncoded(), unwrapped.getEncoded()),
                "unwrapped AES key must match original");

        // Vandalised wrapped blob → InvalidKeyException, never BadPaddingException.
        byte[] tampered = Arrays.clone(wrapped);
        tampered[5] ^= 0x01;
        Cipher badUnwrapper = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        badUnwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate(), oaep);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> badUnwrapper.unwrap(tampered, "AES", Cipher.SECRET_KEY),
                "tampered wrapped key must surface as InvalidKeyException");
    }


    // -----------------------------------------------------------------
    // engineSetParameter validation (OAEP / PSS)
    // -----------------------------------------------------------------

    /**
     * Mirrors RSAOAEPCipherTest.testOAEP_RejectsNonMGF1 /
     * testOAEP_RejectsNonOAEPParameterSpec.
     */
    @Test
    public void oaepSetParameterRejectsBadSpecs()
        throws Exception
    {
        KeyPair kp = keyPair();

        // Non-MGF1 mask generation function.
        OAEPParameterSpec badMgf = new OAEPParameterSpec(
                "SHA-256", "MGF2", new MGF1ParameterSpec("SHA-256"),
                PSource.PSpecified.DEFAULT);
        Cipher enc = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException e1 = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> enc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), badMgf));
        Assertions.assertTrue(e1.getMessage().contains("MGF1"),
                "expected MGF1 rejection, got: " + e1.getMessage());

        // Unrelated AlgorithmParameterSpec.
        Cipher enc2 = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> enc2.init(Cipher.ENCRYPT_MODE, kp.getPublic(),
                        new AlgorithmParameterSpec() {}),
                "unrelated AlgorithmParameterSpec must be rejected");
    }

    /**
     * Mirrors RSATest.testPss_RejectsNonMGF1 / testPss_RejectsTrailerOtherThan1 /
     * testPss_RejectsForeignAlgorithmParameterSpec.
     */
    @Test
    public void pssSetParameterRejectsBadSpecs()
        throws Exception
    {
        // Non-MGF1.
        Signature s1 = Signature.getInstance("RSASSA-PSS", JostleFIPSProvider.PROVIDER_NAME);
        PSSParameterSpec nonMgf1 = new PSSParameterSpec(
                "SHA-256", "MGF2", new MGF1ParameterSpec("SHA-256"), 32, 1);
        InvalidAlgorithmParameterException e1 = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> s1.setParameter(nonMgf1));
        Assertions.assertTrue(e1.getMessage().contains("MGF1"),
                "expected MGF1 rejection, got: " + e1.getMessage());

        // Trailer field other than 1.
        Signature s2 = Signature.getInstance("RSASSA-PSS", JostleFIPSProvider.PROVIDER_NAME);
        PSSParameterSpec badTrailer = new PSSParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 7);
        InvalidAlgorithmParameterException e2 = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> s2.setParameter(badTrailer));
        Assertions.assertEquals("trailer field must be 1 (got 7)", e2.getMessage());

        // Foreign AlgorithmParameterSpec.
        Signature s3 = Signature.getInstance("RSASSA-PSS", JostleFIPSProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException e3 = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> s3.setParameter(new AlgorithmParameterSpec() {}));
        Assertions.assertEquals("expected PSSParameterSpec", e3.getMessage());
    }


    // -----------------------------------------------------------------
    // SPI state-machine guards: operations before init
    // -----------------------------------------------------------------

    /**
     * Mirrors RSATest.testSignature_SignWithoutInit_throwsIllegalState (+ Update /
     * Verify / PSS variants): pre-init misuse surfaces as IllegalStateException
     * (which the JCE may translate into SignatureException), never an NPE from a
     * null native handle.
     */
    @Test
    public void signatureOperationsBeforeInitThrowIllegalState()
        throws Exception
    {
        // The JCE may translate the SPI's IllegalStateException into a
        // SignatureException for the Signature API; either is acceptable, as
        // long as no NPE from the null native handle escapes.
        for (String alg : new String[]{"SHA256withRSA", "RSASSA-PSS"})
        {
            Signature s1 = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            try
            {
                s1.update(new byte[]{1, 2, 3});
                Assertions.fail(alg + ": update before init must throw");
            }
            catch (IllegalStateException | SignatureException expected)
            {
            }

            Signature s2 = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            try
            {
                s2.sign();
                Assertions.fail(alg + ": sign before init must throw");
            }
            catch (IllegalStateException | SignatureException expected)
            {
            }

            Signature s3 = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            try
            {
                s3.verify(new byte[]{1, 2, 3});
                Assertions.fail(alg + ": verify before init must throw");
            }
            catch (IllegalStateException | SignatureException expected)
            {
            }
        }
    }

    /**
     * Mirrors RSAOAEPCipherTest.testOAEP_DoFinalWithoutInit_throwsIllegalState
     * (+ Update / Wrap / Unwrap): OAEP Cipher operations before init throw
     * IllegalStateException.
     */
    @Test
    public void oaepCipherOperationsBeforeInitThrowIllegalState()
        throws Exception
    {
        Cipher c1 = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertThrows(IllegalStateException.class,
                () -> c1.update(new byte[]{1, 2, 3}),
                "update before init must throw IllegalStateException");

        Cipher c2 = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertThrows(IllegalStateException.class,
                () -> c2.doFinal(new byte[]{1, 2, 3}),
                "doFinal before init must throw IllegalStateException");

        Cipher c3 = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        SecretKey aes = new javax.crypto.spec.SecretKeySpec(new byte[16], "AES");
        Assertions.assertThrows(IllegalStateException.class,
                () -> c3.wrap(aes),
                "wrap before init must throw IllegalStateException");

        Cipher c4 = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertThrows(IllegalStateException.class,
                () -> c4.unwrap(new byte[256], "AES", Cipher.SECRET_KEY),
                "unwrap before init must throw IllegalStateException");
    }


    // -----------------------------------------------------------------
    // KeyPairGenerator parameter validation (upper bound / exponent / spec)
    // -----------------------------------------------------------------

    /**
     * Mirrors RSATest.testKeyPairGenerator_rejectsKeySizeAboveMax /
     * _rejectsEvenPublicExponent / _rejectsExponentBelow3 /
     * _rejectsForeignParameterSpec. (The below-min floor is already covered by
     * {@link #moduleKeySizeFloorAndUnapprovedGate()}.)
     */
    @Test
    public void keyPairGeneratorRejectsInvalidParameters()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);

        // Above the ceiling on the int-only surface.
        InvalidParameterException ipe = Assertions.assertThrows(
                InvalidParameterException.class, () -> kpg.initialize(20000),
                "size above the ceiling must be rejected");
        Assertions.assertTrue(ipe.getMessage().contains("[2048, 16384]"),
                "message must name the JSLFIPS range, got: " + ipe.getMessage());

        // Even public exponent.
        for (BigInteger evenE : new BigInteger[]{
                BigInteger.valueOf(4), BigInteger.valueOf(6), BigInteger.valueOf(65536)})
        {
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> kpg.initialize(new RSAKeyGenParameterSpec(2048, evenE)),
                    "even exponent " + evenE + " must be rejected");
            Assertions.assertTrue(e.getMessage().contains("must be odd"),
                    "expected 'must be odd', got: " + e.getMessage());
        }

        // Public exponent below 3.
        for (BigInteger bad : new BigInteger[]{
                BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), BigInteger.valueOf(-1)})
        {
            InvalidAlgorithmParameterException e = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> kpg.initialize(new RSAKeyGenParameterSpec(2048, bad)),
                    "exponent " + bad + " must be rejected");
            Assertions.assertEquals("public exponent must be >= 3", e.getMessage());
        }

        // Foreign parameter spec.
        InvalidAlgorithmParameterException fe = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> kpg.initialize(new AlgorithmParameterSpec() {}));
        Assertions.assertEquals("expected instance of RSAKeyGenParameterSpec", fe.getMessage());
    }


    // -----------------------------------------------------------------
    // OID alias resolution
    // -----------------------------------------------------------------

    /**
     * Mirrors RSATest.testOidAliases_resolveToRegisteredAlgorithms, broadened to
     * every OID ProvFIPSRSA registers. The SHA-1 signature OID resolves but its
     * sign path is module-gated, so it is asserted resolvable only.
     */
    @Test
    public void oidAliasesResolveToRegisteredAlgorithms()
        throws Exception
    {
        KeyPair kp = keyPair();

        // Key services under the rsaEncryption OID.
        Assertions.assertNotNull(KeyPairGenerator.getInstance(
                "1.2.840.113549.1.1.1", JostleFIPSProvider.PROVIDER_NAME));
        Assertions.assertNotNull(KeyFactory.getInstance(
                "1.2.840.113549.1.1.1", JostleFIPSProvider.PROVIDER_NAME));
        Assertions.assertNotNull(Cipher.getInstance(
                "1.2.840.113549.1.1.1", JostleFIPSProvider.PROVIDER_NAME));

        // PSS OID: resolve, sign+verify (default digest SHA-256 is approved).
        Signature pss = Signature.getInstance(
                "1.2.840.113549.1.1.10", JostleFIPSProvider.PROVIDER_NAME);
        pss.initSign(kp.getPrivate());
        pss.update(new byte[]{1, 2, 3});
        Assertions.assertTrue(pss.sign().length > 0, "PSS OID must sign");

        // SHA-1 PKCS#1 signature OID resolves but signing is gated.
        Assertions.assertNotNull(Signature.getInstance(
                "1.2.840.113549.1.1.5", JostleFIPSProvider.PROVIDER_NAME),
                "SHA-1 signature OID must resolve");

        // Approved PKCS#1 signature OIDs: resolve, sign+verify.
        String[] approvedSigOids = {
                "1.2.840.113549.1.1.14",   // SHA224withRSA
                "1.2.840.113549.1.1.11",   // SHA256withRSA
                "1.2.840.113549.1.1.12",   // SHA384withRSA
                "1.2.840.113549.1.1.13",   // SHA512withRSA
                "2.16.840.1.101.3.4.3.13", // SHA3-224withRSA
                "2.16.840.1.101.3.4.3.14", // SHA3-256withRSA
                "2.16.840.1.101.3.4.3.15", // SHA3-384withRSA
                "2.16.840.1.101.3.4.3.16"  // SHA3-512withRSA
        };
        byte[] msg = randomMessage(64);
        for (String oid : approvedSigOids)
        {
            Signature signer = Signature.getInstance(oid, JostleFIPSProvider.PROVIDER_NAME);
            signer.initSign(kp.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(oid, JostleFIPSProvider.PROVIDER_NAME);
            verifier.initVerify(kp.getPublic());
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig), oid + ": signature must self-verify");
        }
    }


    // -----------------------------------------------------------------
    // Approved PKCS#1 v1.5 signature digests
    // -----------------------------------------------------------------

    /**
     * Mirrors RSATest.testPkcs1_AllRegisteredDigests_roundTrip: every approved
     * PKCS#1 v1.5 digest signs+verifies, with a tampered-message differentiator
     * per digest. SHA1withRSA sign is module-gated, so it is excluded.
     */
    @Test
    public void allRegisteredPkcs1DigestsRoundTrip()
        throws Exception
    {
        KeyPair kp = keyPair();

        String[] algs = {
                "SHA224withRSA",
                "SHA256withRSA",
                "SHA384withRSA",
                "SHA512withRSA",
                "SHA3-224withRSA",
                "SHA3-256withRSA",
                "SHA3-384withRSA",
                "SHA3-512withRSA"
        };
        for (String alg : algs)
        {
            byte[] msg = randomMessage(1 + RANDOM.nextInt(256));

            Signature signer = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            signer.initSign(kp.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();
            Assertions.assertTrue(sig.length > 0, alg + ": empty signature");

            Signature verifier = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            verifier.initVerify(kp.getPublic());
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig), alg + ": failed self-verification");

            // Tampered-message differentiator.
            byte[] tampered = Arrays.clone(msg);
            tampered[RANDOM.nextInt(tampered.length)] ^= 0x01;
            Signature verifier2 = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            verifier2.initVerify(kp.getPublic());
            verifier2.update(tampered);
            Assertions.assertFalse(verifier2.verify(sig), alg + ": tampered message must not verify");
        }
    }


    // -----------------------------------------------------------------
    // Signer reset / reuse / role-flip on one instance
    // -----------------------------------------------------------------

    /**
     * Mirrors RSATest.testPkcs1_SignerResetAfterSign /
     * _RoleFlip_SignThenVerifyOnSameInstance / _VerifierReuseAfterVerify:
     * a single instance signs two distinct messages, flips role, and survives a
     * negative-then-positive sequence without state leak.
     */
    @Test
    public void pkcs1SignatureResetAndRoleFlip()
        throws Exception
    {
        KeyPair kp = keyPair();

        byte[] msgA = randomMessage(64);
        byte[] msgB = randomMessage(96);

        // Two distinct messages through one signer; PKCS#1 v1.5 is deterministic.
        Signature signer = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msgA);
        byte[] sigA = signer.sign();
        signer.update(msgB);
        byte[] sigB = signer.sign();

        Signature signerAgain = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        signerAgain.initSign(kp.getPrivate());
        signerAgain.update(msgA);
        Assertions.assertTrue(Arrays.areEqual(sigA, signerAgain.sign()),
                "PKCS#1 v1.5 signatures over the same message must be deterministic");

        // Verifier reuse with a negative-then-positive sequence on one instance.
        Signature verifier = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msgA);
        Assertions.assertTrue(verifier.verify(sigA), "first verify should pass");

        byte[] tampered = Arrays.clone(sigB);
        tampered[0] ^= 0x01;
        verifier.update(msgB);
        Assertions.assertFalse(verifier.verify(tampered),
                "tampered signature must fail even after a previous-pass verify");

        verifier.update(msgB);
        Assertions.assertTrue(verifier.verify(sigB),
                "good signature must verify even after a previous-fail verify");

        // Role flip on a single instance: sign → verify → sign.
        Signature flip = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        flip.initSign(kp.getPrivate());
        flip.update(msgA);
        byte[] s = flip.sign();

        flip.initVerify(kp.getPublic());
        flip.update(msgA);
        Assertions.assertTrue(flip.verify(s),
                "verify on a Signature previously used to sign must succeed");

        flip.initSign(kp.getPrivate());
        flip.update(msgA);
        Assertions.assertTrue(Arrays.areEqual(s, flip.sign()),
                "role-flip round-trip on the same instance must agree (deterministic PKCS#1 v1.5)");
    }


    // -----------------------------------------------------------------
    // KeyFactory: component specs and rejections
    // -----------------------------------------------------------------

    /**
     * Mirrors RSATest.testKeyFactory_RSAPublicKeySpec_roundTrip /
     * _RSAPrivateCrtKeySpec_roundTrip / _RSAPrivateKeySpec_isRejected /
     * testRsaKeyFactory_malformedEncoding_throwsInvalidKeySpec.
     */
    @Test
    public void keyFactorySpecFormatsAndRejections()
        throws Exception
    {
        KeyPair kp = keyPair();
        KeyFactory kf = KeyFactory.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);

        byte[] msg = randomMessage(64);

        // RSAPublicKeySpec round-trip: reborn public verifies a signature over msg.
        RSAPublicKey original = (RSAPublicKey) kp.getPublic();
        PublicKey rebornPub = kf.generatePublic(new RSAPublicKeySpec(
                original.getModulus(), original.getPublicExponent()));
        Assertions.assertEquals(original.getModulus(), ((RSAPublicKey) rebornPub).getModulus());
        Assertions.assertEquals(original.getPublicExponent(),
                ((RSAPublicKey) rebornPub).getPublicExponent());

        Signature signer = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        verifier.initVerify(rebornPub);
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig), "reborn public key must verify");

        // RSAPrivateCrtKeySpec round-trip: reborn private signs, original public verifies.
        RSAPrivateCrtKeySpec crtSpec = kf.getKeySpec(kp.getPrivate(), RSAPrivateCrtKeySpec.class);
        Assertions.assertNotNull(crtSpec.getPrimeP());
        Assertions.assertNotNull(crtSpec.getPrimeQ());
        Assertions.assertNotNull(crtSpec.getCrtCoefficient());
        PrivateKey rebornPriv = kf.generatePrivate(crtSpec);

        Signature signer2 = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        signer2.initSign(rebornPriv);
        signer2.update(msg);
        byte[] sig2 = signer2.sign();
        Signature verifier2 = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        verifier2.initVerify(kp.getPublic());
        verifier2.update(msg);
        Assertions.assertTrue(verifier2.verify(sig2), "reborn CRT private key must sign");

        // Non-CRT RSAPrivateKeySpec is rejected on generatePrivate.
        RSAPrivateKeySpec basic = kf.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
        InvalidKeySpecException nonCrt = Assertions.assertThrows(
                InvalidKeySpecException.class, () -> kf.generatePrivate(basic));
        Assertions.assertTrue(nonCrt.getMessage().contains("RSAPrivateKeySpec"),
                "expected RSAPrivateKeySpec rejection, got: " + nonCrt.getMessage());

        // Malformed encodings surface as InvalidKeySpecException.
        byte[] garbage = {(byte) 0x30, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x2A};
        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generatePublic(new X509EncodedKeySpec(garbage)),
                "malformed X.509 must throw InvalidKeySpecException");
        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generatePrivate(new PKCS8EncodedKeySpec(garbage)),
                "malformed PKCS#8 must throw InvalidKeySpecException");
    }


    // -----------------------------------------------------------------
    // OAEP input-length boundary and label/digest application
    // -----------------------------------------------------------------

    /**
     * Mirrors RSAOAEPCipherTest.testOAEP_SHA256_MaxInputLength_acceptsAtLimit /
     * _rejectsAboveLimit: for OAEP-SHA256 on a 2048-bit key, max plaintext is
     * 256 - 2*32 - 2 = 190 bytes. The limit encrypts+decrypts; one byte over is
     * rejected with IllegalBlockSizeException.
     */
    @Test
    public void oaepMaxInputLengthBoundary()
        throws Exception
    {
        KeyPair kp = keyPair();
        OAEPParameterSpec oaep = oaepSpec("SHA-256");

        // At the limit: round-trips.
        byte[] atLimit = randomMessage(190);
        Cipher enc = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
        byte[] ct = enc.doFinal(atLimit);
        Cipher dec = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), oaep);
        Assertions.assertTrue(Arrays.areEqual(atLimit, dec.doFinal(ct)),
                "190-byte plaintext must round-trip at the OAEP-SHA256 limit");

        // One byte over: rejected.
        byte[] overLimit = randomMessage(191);
        Cipher encOver = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        encOver.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
        Assertions.assertThrows(IllegalBlockSizeException.class,
                () -> encOver.doFinal(overLimit),
                "191-byte plaintext (max + 1) must be rejected");
    }

    /**
     * Mirrors RSAOAEPCipherTest.testOAEP_LabelMatters /
     * _DigestActuallyApplied_crossDigestFails: OAEP ciphertext produced under one
     * label (or digest) fails to decrypt under a different label (or digest),
     * proving the SPI honours both rather than defaulting silently.
     */
    @Test
    public void oaepLabelAndDigestAreApplied()
        throws Exception
    {
        KeyPair kp = keyPair();

        // Label matters.
        byte[] labelA = "label-A".getBytes(StandardCharsets.UTF_8);
        byte[] labelB = "label-B".getBytes(StandardCharsets.UTF_8);
        OAEPParameterSpec specA = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), new PSource.PSpecified(labelA));
        OAEPParameterSpec specB = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), new PSource.PSpecified(labelB));

        byte[] msg = randomMessage(32);
        Cipher enc = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), specA);
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), specA);
        Assertions.assertTrue(Arrays.areEqual(msg, dec.doFinal(ct)),
                "matching label must decrypt");

        Cipher decBad = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        decBad.init(Cipher.DECRYPT_MODE, kp.getPrivate(), specB);
        Assertions.assertThrows(BadPaddingException.class,
                () -> decBad.doFinal(ct),
                "mismatched label must fail as BadPaddingException");

        // Digest matters: encrypt SHA-256, decrypt SHA-384.
        OAEPParameterSpec sha256 = oaepSpec("SHA-256");
        OAEPParameterSpec sha384 = oaepSpec("SHA-384");
        Cipher enc2 = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        enc2.init(Cipher.ENCRYPT_MODE, kp.getPublic(), sha256);
        byte[] ct2 = enc2.doFinal(randomMessage(32));

        Cipher dec2 = Cipher.getInstance("RSA", JostleFIPSProvider.PROVIDER_NAME);
        dec2.init(Cipher.DECRYPT_MODE, kp.getPrivate(), sha384);
        Assertions.assertThrows(BadPaddingException.class,
                () -> dec2.doFinal(ct2),
                "OAEP-SHA256 ciphertext must NOT decrypt as OAEP-SHA384");
    }


    // -----------------------------------------------------------------
    // PKCS#1 chunking matrix (deterministic → byte-identical)
    // -----------------------------------------------------------------

    /**
     * Mirrors RSATest.testPkcs1_SHA256_ChunkingMatrix_byteIdentical: the same
     * message signed one-shot, byte-by-byte, at adversarial offsets, and at
     * random splits must yield byte-identical signatures (PKCS#1 v1.5 is
     * deterministic), exercising the streaming buffer path.
     */
    @Test
    public void pkcs1SignatureChunkingByteIdentical()
        throws Exception
    {
        KeyPair kp = keyPair();

        byte[] msg = randomMessage(1024);
        byte[] reference = signWithChunking(kp, msg, msg.length);

        Assertions.assertTrue(Arrays.areEqual(reference, signWithChunking(kp, msg, 1)),
                "byte-by-byte signature diverged from one-shot");

        for (int chunk : new int[]{63, 64, 65})
        {
            Assertions.assertTrue(Arrays.areEqual(reference, signWithChunking(kp, msg, chunk)),
                    "chunk=" + chunk + ": signature diverged from one-shot");
        }

        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertTrue(Arrays.areEqual(reference, signWithRandomSplits(kp, msg)),
                    "random-split signature diverged from one-shot");
        }
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static OAEPParameterSpec oaepSpec(String digest)
    {
        return new OAEPParameterSpec(
                digest, "MGF1", new MGF1ParameterSpec(digest), PSource.PSpecified.DEFAULT);
    }

    private static byte[] randomMessage(int len)
    {
        byte[] m = new byte[len];
        RANDOM.nextBytes(m);
        return m;
    }

    private static byte[] signWithChunking(KeyPair kp, byte[] msg, int chunk)
        throws Exception
    {
        Signature signer = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            signer.update(msg, off, len);
        }
        return signer.sign();
    }

    private static byte[] signWithRandomSplits(KeyPair kp, byte[] msg)
        throws Exception
    {
        Signature signer = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        int pos = 0;
        while (pos < msg.length)
        {
            int remaining = msg.length - pos;
            int chunk = 1 + RANDOM.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            signer.update(msg, pos, chunk);
            pos += chunk;
        }
        return signer.sign();
    }
}
