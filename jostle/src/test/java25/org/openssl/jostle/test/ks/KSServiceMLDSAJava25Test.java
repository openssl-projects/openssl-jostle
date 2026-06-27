/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.ks;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.NamedParameterSpec;
import java.util.Date;

public class KSServiceMLDSAJava25Test
{
    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void storedJostleGeneratedMLDSACertificateLoadsWithJostleProvider()
        throws Exception
    {
        char[] password = "changeit".toCharArray();
        KeyPair keyPair = generateMLDSAKeyPair();
        X509Certificate certificate = selfSignedMLDSACertificate(keyPair);

        KeyStore keyStore = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        keyStore.setKeyEntry("mldsa-key", keyPair.getPrivate(), password,
                new Certificate[] {certificate});
        keyStore.setCertificateEntry("mldsa-cert", certificate);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, password);

        KeyStore loaded = KeyStore.getInstance("PKCS12",
                JostleProvider.PROVIDER_NAME);
        loaded.load(new ByteArrayInputStream(out.toByteArray()), password);

        Assertions.assertEquals(2, loaded.size());
        Assertions.assertTrue(loaded.isKeyEntry("mldsa-key"));
        Assertions.assertTrue(loaded.isCertificateEntry("mldsa-cert"));

        Key loadedKey = loaded.getKey("mldsa-key", password);
        Assertions.assertNotNull(loadedKey);
        Assertions.assertTrue(loadedKey.getAlgorithm().startsWith("ML-DSA"));

        Assertions.assertArrayEquals(certificate.getEncoded(),
                loaded.getCertificate("mldsa-cert").getEncoded());
        assertCertificateChain(loaded, "mldsa-key", certificate);
        assertLoadedMLDSAKeyCanSign((PrivateKey)loadedKey,
                loaded.getCertificate("mldsa-key").getPublicKey());
    }

    private static KeyPair generateMLDSAKeyPair()
        throws Exception
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                "ML-DSA", JostleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new NamedParameterSpec("ML-DSA-44"));
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate selfSignedMLDSACertificate(KeyPair keyPair)
        throws Exception
    {
        X500Name name = new X500Name("CN=Jostle ML-DSA PKCS12 Interop Test");
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, notBefore, notAfter, name,
                keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA-44")
                .setProvider(JostleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
    }

    private static void assertCertificateChain(KeyStore keyStore, String alias,
                                               X509Certificate certificate)
        throws Exception
    {
        Certificate[] chain = keyStore.getCertificateChain(alias);
        Assertions.assertNotNull(chain);
        Assertions.assertEquals(1, chain.length);
        Assertions.assertArrayEquals(certificate.getEncoded(),
                chain[0].getEncoded());
    }

    private static void assertLoadedMLDSAKeyCanSign(PrivateKey privateKey,
                                                    PublicKey publicKey)
        throws Exception
    {
        byte[] message = "jostle mldsa pkcs12 interop"
                .getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("ML-DSA-44",
                JostleProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("ML-DSA-44",
                JostleProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(signature));
    }
}
