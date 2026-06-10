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

package org.openssl.jostle.test.rsa;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

/**
 * Regression for the RSA-Cipher foreign-key gap: the PKCS#1 and OAEP Cipher
 * SPIs must accept any {@code java.security.interfaces.RSAPublicKey} /
 * {@code RSAPrivateKey}, not only JSL's own key objects — notably the
 * {@code sun.security.rsa.*} keys returned by {@code X509Certificate.getPublicKey()}
 * and by the JDK's default {@code KeyFactory}, which is what CMS RSA key
 * transport hands the cipher.
 */
public class RSAForeignKeyCipherTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String[] TRANSFORMATIONS = {
            "RSA/ECB/PKCS1Padding",
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    };

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static KeyPair jslRsa() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    /** Re-decode JSL key encodings through the JDK default RSA KeyFactory,
     *  yielding sun.security.rsa.* keys — foreign to JSL. */
    private static PublicKey foreignPublic(PublicKey jslPub) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(jslPub.getEncoded()));
    }

    private static PrivateKey foreignPrivate(PrivateKey jslPriv) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(jslPriv.getEncoded()));
    }

    @Test
    public void foreignKeys_wrapUnwrap_roundTrip() throws Exception
    {
        KeyPair kp = jslRsa();
        PublicKey fPub = foreignPublic(kp.getPublic());
        PrivateKey fPriv = foreignPrivate(kp.getPrivate());
        Assertions.assertFalse(fPub.getClass().getName().startsWith("org.openssl.jostle"),
                "test precondition: public key must be foreign to JSL");

        for (String xf : TRANSFORMATIONS)
        {
            byte[] keyBytes = new byte[32];
            RANDOM.nextBytes(keyBytes);
            SecretKey cek = new SecretKeySpec(keyBytes, "AES");

            Cipher wrap = Cipher.getInstance(xf, JSL);
            wrap.init(Cipher.WRAP_MODE, fPub);          // foreign public key
            byte[] wrapped = wrap.wrap(cek);

            Cipher unwrap = Cipher.getInstance(xf, JSL);
            unwrap.init(Cipher.UNWRAP_MODE, fPriv);     // foreign private key
            Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded(),
                    xf + ": wrap/unwrap with foreign keys did not round-trip");
        }
    }

    @Test
    public void foreignKeys_encryptDecrypt_roundTrip() throws Exception
    {
        KeyPair kp = jslRsa();
        PublicKey fPub = foreignPublic(kp.getPublic());
        PrivateKey fPriv = foreignPrivate(kp.getPrivate());

        for (String xf : TRANSFORMATIONS)
        {
            byte[] msg = new byte[1 + RANDOM.nextInt(60)];
            RANDOM.nextBytes(msg);

            Cipher enc = Cipher.getInstance(xf, JSL);
            enc.init(Cipher.ENCRYPT_MODE, fPub);
            byte[] ct = enc.doFinal(msg);

            Cipher dec = Cipher.getInstance(xf, JSL);
            dec.init(Cipher.DECRYPT_MODE, fPriv);
            Assertions.assertArrayEquals(msg, dec.doFinal(ct),
                    xf + ": encrypt/decrypt with foreign keys did not round-trip");
        }
    }

    @Test
    public void certificatePublicKey_wrapInitSucceeds() throws Exception
    {
        // The exact scenario from the gap doc: a key straight off a certificate.
        KeyPair kp = jslRsa();
        X509Certificate cert = selfSignedCert(kp);
        PublicKey certPub = cert.getPublicKey();
        Assertions.assertFalse(certPub.getClass().getName().startsWith("org.openssl.jostle"),
                "test precondition: cert.getPublicKey() must be foreign to JSL");

        byte[] keyBytes = new byte[16];
        RANDOM.nextBytes(keyBytes);
        SecretKey cek = new SecretKeySpec(keyBytes, "AES");

        Cipher wrap = Cipher.getInstance("RSA/ECB/PKCS1Padding", JSL);
        wrap.init(Cipher.WRAP_MODE, certPub);            // previously threw InvalidKeyException
        byte[] wrapped = wrap.wrap(cek);

        Cipher unwrap = Cipher.getInstance("RSA/ECB/PKCS1Padding", JSL);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded());
    }

    @Test
    public void nonRsaKey_stillRejected() throws Exception
    {
        // A foreign but non-RSA key must still be rejected with the typed
        // exception and the operation-specific message.
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", JSL);
        ec.initialize(new java.security.spec.ECGenParameterSpec("P-256"));
        PublicKey ecPub = ec.generateKeyPair().getPublic();

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", JSL);
        try
        {
            enc.init(Cipher.WRAP_MODE, ecPub);
            Assertions.fail("expected InvalidKeyException for a non-RSA key");
        }
        catch (java.security.InvalidKeyException e)
        {
            Assertions.assertEquals("encrypt/wrap requires an RSAPublicKey", e.getMessage());
        }
    }

    private static X509Certificate selfSignedCert(KeyPair kp) throws Exception
    {
        X500Name dn = new X500Name("CN=Jostle RSA Foreign Key Test");
        Date from = new Date(System.currentTimeMillis() - 3600_000L);
        Date to = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(1), from, to, dn, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate());
        // No provider on the converter → JDK default CertificateFactory, whose
        // getPublicKey() returns a sun.security.rsa.RSAPublicKeyImpl.
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
