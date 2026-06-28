//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

package org.openssl.jostle.test.ks;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
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
