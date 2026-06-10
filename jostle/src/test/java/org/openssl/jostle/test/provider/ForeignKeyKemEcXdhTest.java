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

package org.openssl.jostle.test.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

/**
 * Regression for CMS_FOREIGN_KEY_KEM_EC_GAP.md: the ML-KEM KTS cipher and the
 * EC/XDH {@code KeyAgreement} SPIs must accept foreign keys — the
 * {@code sun.security.*} instances returned by
 * {@code X509Certificate.getPublicKey()} and the JDK's default KeyFactories —
 * by translating them to JSL keys, as the RSA cipher SPIs already do via
 * {@code RSAKeyImport}.
 */
public class ForeignKeyKemEcXdhTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String JSL = JostleProvider.PROVIDER_NAME;

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

    /** Self-signed cert over {@code subjectPub}, signed with a JSL RSA key. */
    private static X509Certificate certOver(PublicKey subjectPub) throws Exception
    {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JSL);
        rsaKpg.initialize(2048);
        KeyPair signerKp = rsaKpg.generateKeyPair();

        X500Name dn = new X500Name("CN=Jostle Foreign Key Test");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - 3600_000L),
                new Date(System.currentTimeMillis() + 3600_000L),
                dn, subjectPub);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signerKp.getPrivate());
        // No provider on the converter → the JDK default CertificateFactory,
        // whose getPublicKey() returns sun.security.* key objects.
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static void assertForeign(Key key)
    {
        Assertions.assertFalse(key.getClass().getName().startsWith("org.openssl.jostle"),
                "test precondition: key must be foreign to JSL, got " + key.getClass().getName());
    }

    // ----- ML-KEM KTS -----

    private static KTSParameterSpec ktsKdf3Spec(int keyBits, byte[] otherInfo, ASN1ObjectIdentifier digestOid)
    {
        return new KTSParameterSpec.Builder("AES", keyBits, otherInfo)
                .withKdfAlgorithm(new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(digestOid)))
                .build();
    }

    @Test
    public void mlkemKts_certPublicKey_wrapUnwrapRoundTrips() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", JSL);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey certPub = certOver(kp.getPublic()).getPublicKey();
        assertForeign(certPub);

        byte[] otherInfo = new byte[16];
        RANDOM.nextBytes(otherInfo);
        KTSParameterSpec spec = ktsKdf3Spec(256, otherInfo, NISTObjectIdentifiers.id_sha256);
        byte[] cekBytes = new byte[32];
        RANDOM.nextBytes(cekBytes);
        SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");

        Cipher wrap = Cipher.getInstance("ML-KEM", JSL);
        wrap.init(Cipher.WRAP_MODE, certPub, spec);     // previously: "not a JSL ML-KEM key"
        byte[] wrapped = wrap.wrap(cek);

        Cipher unwrap = Cipher.getInstance("ML-KEM", JSL);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded(),
                "ML-KEM KTS wrap with a cert public key did not round-trip");
    }

    @Test
    public void mlkemKts_nonMlkemKey_stillRejected() throws Exception
    {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JSL);
        rsaKpg.initialize(2048);
        PublicKey rsaPub = rsaKpg.generateKeyPair().getPublic();

        KTSParameterSpec spec = ktsKdf3Spec(256, new byte[8], NISTObjectIdentifiers.id_sha256);
        Cipher wrap = Cipher.getInstance("ML-KEM", JSL);
        try
        {
            wrap.init(Cipher.WRAP_MODE, rsaPub, spec);
            Assertions.fail("expected InvalidKeyException for a non-ML-KEM key");
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("not an ML-KEM key:"),
                    "unexpected message: " + e.getMessage());
        }
    }

    // ----- ECDH -----

    @Test
    public void ecdh_certPublicKeyAndForeignPrivate_agree() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair a = kpg.generateKeyPair();
        KeyPair b = kpg.generateKeyPair();

        // Reference secret with JSL-native keys.
        KeyAgreement kaNative = KeyAgreement.getInstance("ECDH", JSL);
        kaNative.init(a.getPrivate());
        kaNative.doPhase(b.getPublic(), true);
        byte[] expected = kaNative.generateSecret();

        // Peer public key from a certificate (sun.security.ec.*).
        PublicKey certPubB = certOver(b.getPublic()).getPublicKey();
        assertForeign(certPubB);
        // Private key re-decoded through the JDK's default EC KeyFactory.
        PrivateKey foreignPrivA = KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(a.getPrivate().getEncoded()));
        assertForeign(foreignPrivA);

        KeyAgreement kaForeign = KeyAgreement.getInstance("ECDH", JSL);
        kaForeign.init(foreignPrivA);                  // previously rejected
        kaForeign.doPhase(certPubB, true);             // previously rejected
        Assertions.assertArrayEquals(expected, kaForeign.generateSecret(),
                "ECDH with foreign keys diverged from the JSL-native secret");
    }

    // ----- XDH -----

    @Test
    public void xdh_foreignKeys_agree() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", JSL);
        KeyPair a = kpg.generateKeyPair();
        KeyPair b = kpg.generateKeyPair();

        KeyAgreement kaNative = KeyAgreement.getInstance("X25519", JSL);
        kaNative.init(a.getPrivate());
        kaNative.doPhase(b.getPublic(), true);
        byte[] expected = kaNative.generateSecret();

        // Re-decode both halves through the JDK's XDH KeyFactory.
        KeyFactory jdkXdh = KeyFactory.getInstance("XDH");
        PrivateKey foreignPrivA = jdkXdh.generatePrivate(
                new PKCS8EncodedKeySpec(a.getPrivate().getEncoded()));
        PublicKey foreignPubB = jdkXdh.generatePublic(
                new X509EncodedKeySpec(b.getPublic().getEncoded()));
        assertForeign(foreignPrivA);
        assertForeign(foreignPubB);

        KeyAgreement kaForeign = KeyAgreement.getInstance("X25519", JSL);
        kaForeign.init(foreignPrivA);                  // previously rejected
        kaForeign.doPhase(foreignPubB, true);          // previously rejected
        Assertions.assertArrayEquals(expected, kaForeign.generateSecret(),
                "XDH with foreign keys diverged from the JSL-native secret");
    }
}
