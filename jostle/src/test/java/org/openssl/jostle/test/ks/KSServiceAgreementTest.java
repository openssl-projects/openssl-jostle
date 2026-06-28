//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

package org.openssl.jostle.test.ks;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Cross-validates Jostle's PKCS#12 KeyStore against BouncyCastle: for every
 * BC-parity profile, a keystore written by one provider must load (key + chain)
 * in the other. This catches wrong-but-self-consistent output that a Jostle-only
 * round-trip cannot. Random RSA keys + fresh self-signed certs per trial.
 *
 * <p>Only profiles whose algorithms live in OpenSSL's default provider are
 * exercised both ways. BouncyCastle's bare {@code PKCS12} default encrypts certs
 * with 40-bit RC2 (legacy-provider only), so a BC-written bare keystore is not
 * Jostle-readable and is therefore excluded from the BC&rarr;Jostle direction.
 */
public class KSServiceAgreementTest
{
    private static final int TRIALS = 4;

    @BeforeAll
    public static void setUp()
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

    @ParameterizedTest
    @ValueSource(strings = {"PKCS12", "PKCS12-3DES-3DES", "PKCS12-AES256-AES128", "PKCS12-PBMAC1"})
    public void jostleWritesBouncyCastleReads(String type)
        throws Exception
    {
        for (int trial = 0; trial < TRIALS; trial++)
        {
            char[] password = ("agree-jostle-" + trial).toCharArray();
            KeyPair keyPair = newRsaKeyPair(JostleProvider.PROVIDER_NAME);
            X509Certificate cert = selfSignedCertificate(keyPair,
                    "CN=Jostle Agreement " + type + " " + trial,
                    BigInteger.valueOf(trial + 1L));

            KeyStore jostle = KeyStore.getInstance(type, JostleProvider.PROVIDER_NAME);
            jostle.load(null, null);
            jostle.setKeyEntry("key", keyPair.getPrivate(), password,
                    new Certificate[] {cert});
            byte[] encoded = store(jostle, password);

            // BC's PKCS12 reader is algorithm-agnostic; read whatever Jostle wrote.
            KeyStore bc = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            bc.load(new ByteArrayInputStream(encoded), password);
            assertKeyAndChain(bc, keyPair.getPrivate(), cert, password);
        }
    }

    // PKCS12-PBMAC1 is intentionally excluded from this direction: BouncyCastle's
    // PBMAC1 derives a 256-octet PBKDF2 MAC key, but OpenSSL's PKCS12_verify_mac
    // rejects a PBMAC1 key longer than EVP_MAX_MD_SIZE (64 bytes), so Jostle
    // cannot verify a BC-written PBMAC1 keystore. The reverse works -- Jostle's
    // 64-octet PBMAC1 output is read by BouncyCastle (see the test above).
    @ParameterizedTest
    @ValueSource(strings = {"PKCS12-3DES-3DES", "PKCS12-AES256-AES128"})
    public void bouncyCastleWritesJostleReads(String type)
        throws Exception
    {
        for (int trial = 0; trial < TRIALS; trial++)
        {
            char[] password = ("agree-bc-" + trial).toCharArray();
            KeyPair keyPair = newRsaKeyPair(BouncyCastleProvider.PROVIDER_NAME);
            X509Certificate cert = selfSignedCertificate(keyPair,
                    "CN=BC Agreement " + type + " " + trial,
                    BigInteger.valueOf(trial + 1L));

            KeyStore bc = KeyStore.getInstance(type, BouncyCastleProvider.PROVIDER_NAME);
            bc.load(null, null);
            bc.setKeyEntry("key", keyPair.getPrivate(), password,
                    new Certificate[] {cert});
            byte[] encoded = store(bc, password);

            KeyStore jostle = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
            jostle.load(new ByteArrayInputStream(encoded), password);
            assertKeyAndChain(jostle, keyPair.getPrivate(), cert, password);
        }
    }

    /**
     * A BouncyCastle-built PKCS#12 where the certificate carries a DIFFERENT
     * friendlyName than the key's alias but the SAME localKeyId. Jostle must
     * associate the cert to the key by localKeyId (the convention strict readers
     * use), not by friendlyName. friendlyName-only grouping -- the behaviour
     * before the read-side fix -- would orphan the cert under its own name and
     * leave getCertificateChain(keyAlias) null. This isolates the localKeyId
     * precedence that the standard agreement tests cannot (there the two always
     * agree, so a broken localKeyId path is masked by the friendlyName fallback).
     */
    @Test
    public void bouncyCastleLocalKeyIdAssociatesCertWhenFriendlyNameDiffers()
        throws Exception
    {
        char[] password = "agree-localkeyid".toCharArray();
        KeyPair keyPair = newRsaKeyPair(JostleProvider.PROVIDER_NAME);
        X509Certificate cert = selfSignedCertificate(keyPair,
                "CN=Jostle localKeyId Agreement", BigInteger.valueOf(99));

        byte[] keyId = new byte[20];
        new java.security.SecureRandom().nextBytes(keyId);

        OutputEncryptor keyEncryptor = new JcePKCSPBEOutputEncryptorBuilder(
                NISTObjectIdentifiers.id_aes256_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(password);

        PKCS12SafeBagBuilder keyBag =
                new JcaPKCS12SafeBagBuilder(keyPair.getPrivate(), keyEncryptor);
        keyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("the-key-alias"));
        keyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                new DEROctetString(keyId));

        PKCS12SafeBagBuilder certBag = new JcaPKCS12SafeBagBuilder(cert);
        certBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("a-different-cert-name"));
        certBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                new DEROctetString(keyId));

        PKCS12PfxPduBuilder pfxBuilder = new PKCS12PfxPduBuilder();
        pfxBuilder.addData(keyBag.build());
        pfxBuilder.addData(certBag.build());
        PKCS12PfxPdu pfx = pfxBuilder.build(
                new JcePKCS12MacCalculatorBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME), password);
        byte[] encoded = pfx.getEncoded();

        KeyStore jostle = KeyStore.getInstance("PKCS12", JostleProvider.PROVIDER_NAME);
        jostle.load(new ByteArrayInputStream(encoded), password);

        Assertions.assertEquals(1, jostle.size());
        Assertions.assertTrue(jostle.isKeyEntry("the-key-alias"));
        Assertions.assertFalse(jostle.containsAlias("a-different-cert-name"));
        Assertions.assertNotNull(jostle.getKey("the-key-alias", password));

        Certificate[] chain = jostle.getCertificateChain("the-key-alias");
        Assertions.assertNotNull(chain);
        Assertions.assertEquals(1, chain.length);
        Assertions.assertArrayEquals(cert.getEncoded(), chain[0].getEncoded());
    }

    private static void assertKeyAndChain(KeyStore ks, PrivateKey expectedKey,
                                          X509Certificate expectedCert, char[] password)
        throws Exception
    {
        Assertions.assertTrue(ks.containsAlias("key"));
        Assertions.assertTrue(ks.isKeyEntry("key"));

        PrivateKey key = (PrivateKey) ks.getKey("key", password);
        Assertions.assertNotNull(key);
        Assertions.assertArrayEquals(expectedKey.getEncoded(), key.getEncoded());

        Certificate[] chain = ks.getCertificateChain("key");
        Assertions.assertNotNull(chain);
        Assertions.assertEquals(1, chain.length);
        Assertions.assertArrayEquals(expectedCert.getEncoded(), chain[0].getEncoded());
    }

    private static byte[] store(KeyStore ks, char[] password)
        throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, password);
        return out.toByteArray();
    }

    private static KeyPair newRsaKeyPair(String provider)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate selfSignedCertificate(KeyPair keyPair, String dn,
                                                         BigInteger serial)
        throws Exception
    {
        X500Name name = new X500Name(dn);
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
