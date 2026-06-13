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

package org.openssl.jostle.test.cms;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * CMS {@code EnvelopedData} ML-KEM {@code KEMRecipientInfo} (RFC 9629)
 * round-trips with a <em>certificate</em> recipient — the consumer scenario
 * from CMS_FOREIGN_KEY_KEM_EC_GAP.md. BC's CMS layer hands the JSL ML-KEM KTS
 * cipher the certificate's public key (a {@code sun.security.x509.NamedX509Key},
 * foreign to JSL), exercising the KeyFactory translation end-to-end.
 */
public class CMSKemEnvelopedTest
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

    private static X509Certificate certOver(java.security.PublicKey subjectPub) throws Exception
    {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JSL);
        rsaKpg.initialize(2048);
        KeyPair signerKp = rsaKpg.generateKeyPair();
        X500Name dn = new X500Name("CN=Jostle CMS KEM Test");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - 3600_000L),
                new Date(System.currentTimeMillis() + 3600_000L),
                dn, subjectPub);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signerKp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    public void mlkemKemRecipient_certKey_roundTrips() throws Exception
    {
        for (String paramSet : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(paramSet, JSL).generateKeyPair();
            X509Certificate cert = certOver(kp.getPublic());

            byte[] data = new byte[1 + RANDOM.nextInt(256)];
            RANDOM.nextBytes(data);

            CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
            gen.addRecipientInfoGenerator(
                    new JceKEMRecipientInfoGenerator(cert, CMSAlgorithm.AES256_WRAP)
                            .setProvider(JSL));
            CMSEnvelopedData ed = gen.generate(
                    new CMSProcessableByteArray(data),
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                            .setProvider(JSL).build());

            ed = new CMSEnvelopedData(ed.getEncoded());
            RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();
            byte[] dec = ri.getContent(
                    new JceKEMEnvelopedRecipient(kp.getPrivate()).setProvider(JSL));
            Assertions.assertArrayEquals(data, dec,
                    paramSet + ": CMS KEM round-trip with cert recipient failed");
        }
    }

    @Test
    public void mlkemKemRecipient_wrongPrivateKey_failsToDecrypt() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", JSL).generateKeyPair();
        KeyPair wrong = KeyPairGenerator.getInstance("ML-KEM-768", JSL).generateKeyPair();
        X509Certificate cert = certOver(kp.getPublic());

        byte[] data = new byte[64];
        RANDOM.nextBytes(data);

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(
                new JceKEMRecipientInfoGenerator(cert, CMSAlgorithm.AES256_WRAP)
                        .setProvider(JSL));
        CMSEnvelopedData ed = gen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                        .setProvider(JSL).build());
        ed = new CMSEnvelopedData(ed.getEncoded());

        RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();
        try
        {
            ri.getContent(new JceKEMEnvelopedRecipient(wrong.getPrivate()).setProvider(JSL));
            Assertions.fail("decrypt with the wrong ML-KEM private key must not succeed");
        }
        catch (CMSException e)
        {
            // expected — implicit-rejection decapsulation yields a wrong KEK,
            // so the AES key-unwrap (or content auth) fails
        }
    }
}
