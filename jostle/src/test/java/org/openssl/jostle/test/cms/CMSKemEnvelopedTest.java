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
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * CMS {@code EnvelopedData} ML-KEM {@code KEMRecipientInfo} (RFC 9629): stock
 * bcpkix's {@code JceKEMRecipientInfoGenerator}, pointed at JSL, builds BC's
 * own {@code KTSParameterSpec} internally; only Jostle spec types are
 * accepted, so it is refused typed — see
 * {@link #stockBouncyCastleKemRecipientOnJslIsRefusedTyped}.
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
    public void stockBouncyCastleKemRecipientOnJslIsRefusedTyped() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", JSL).generateKeyPair();
        X509Certificate cert = certOver(kp.getPublic());

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(
                new JceKEMRecipientInfoGenerator(cert, CMSAlgorithm.AES256_WRAP)
                        .setProvider(JSL));

        byte[] data = new byte[1 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(data);

        CMSException failure = Assertions.assertThrows(CMSException.class, () ->
                        gen.generate(new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                                        .setProvider(JSL).build()),
                "stock bcpkix's KEM recipient generator must fail when pointed at JSL");
        assertCauseNamesJostleKtsSpec(failure);
    }

    /** Unwraps BC's wrapper exceptions to find the typed refusal underneath. */
    private static void assertCauseNamesJostleKtsSpec(Throwable t)
    {
        for (Throwable cur = t; cur != null; cur = cur.getCause())
        {
            if (cur instanceof InvalidAlgorithmParameterException
                    && cur.getMessage() != null
                    && cur.getMessage().contains("org.bouncycastle.jcajce.spec.KTSParameterSpec")
                    && cur.getMessage().contains("org.openssl.jostle.jcajce.spec.KTSParameterSpec"))
            {
                return;
            }
        }
        Assertions.fail("expected an InvalidAlgorithmParameterException naming both "
                + "org.bouncycastle.jcajce.spec.KTSParameterSpec and "
                + "org.openssl.jostle.jcajce.spec.KTSParameterSpec in the cause chain of: " + t);
    }
}
