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
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
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
 * Full CMS {@code EnvelopedData} RSA key-transport round-trips — the
 * {@code KeyTransRecipientInfo} consumer scenario. BC's CMS layer wraps the
 * content-encryption key to the recipient <em>certificate's</em> public key
 * (a {@code sun.security.rsa.*} key, foreign to JSL) via the JSL RSA Cipher,
 * exercising the foreign-key path end-to-end. Both directions, AES-128-GCM
 * content, PKCS#1 v1.5 key transport.
 */
public class CMSKeyTransEnvelopedTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BC) == null)
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

    private static X509Certificate selfSignedCert(KeyPair kp) throws Exception
    {
        X500Name dn = new X500Name("CN=Jostle CMS KeyTrans Test");
        Date from = new Date(System.currentTimeMillis() - 3600_000L);
        Date to = new Date(System.currentTimeMillis() + 3600_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(1), from, to, dn, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BC).build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private void roundTrip(String encProv, String decProv) throws Exception
    {
        KeyPair kp = jslRsa();
        X509Certificate cert = selfSignedCert(kp);

        byte[] data = new byte[1 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(data);

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(
                new JceKeyTransRecipientInfoGenerator(cert).setProvider(encProv));

        CMSEnvelopedData ed = gen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                        .setProvider(encProv).build());

        ed = new CMSEnvelopedData(ed.getEncoded());

        RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();
        byte[] dec = ri.getContent(
                new JceKeyTransEnvelopedRecipient(kp.getPrivate()).setProvider(decProv));

        Assertions.assertArrayEquals(data, dec,
                "CMS KeyTrans round-trip failed: enc=" + encProv + " dec=" + decProv);
    }

    @Test
    public void keyTrans_jslEncrypt_bcDecrypt() throws Exception
    {
        roundTrip(JSL, BC);
    }

    @Test
    public void keyTrans_bcEncrypt_jslDecrypt() throws Exception
    {
        roundTrip(BC, JSL);
    }

    @Test
    public void keyTrans_jslBothDirections() throws Exception
    {
        roundTrip(JSL, JSL);
    }

    @Test
    public void keyTrans_cbcContent_nonAlignedLength_roundTrips() throws Exception
    {
        // CBC_DECRYPT_UPDATE_BUFFERING_GAP regression: CMS drives the content
        // cipher via update()/doFinal() across reads, which corrupted any
        // AES-CBC content whose length is not a block multiple. 30 bytes is
        // the doc's repro length; both directions through JSL.
        KeyPair kp = jslRsa();
        X509Certificate cert = selfSignedCert(kp);
        byte[] data = new byte[30];
        RANDOM.nextBytes(data);

        for (String[] provs : new String[][]{{JSL, JSL}, {JSL, BC}, {BC, JSL}})
        {
            CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
            gen.addRecipientInfoGenerator(
                    new JceKeyTransRecipientInfoGenerator(cert).setProvider(provs[0]));
            CMSEnvelopedData ed = gen.generate(
                    new CMSProcessableByteArray(data),
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
                            .setProvider(provs[0]).build());
            ed = new CMSEnvelopedData(ed.getEncoded());
            RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();
            byte[] dec = ri.getContent(
                    new JceKeyTransEnvelopedRecipient(kp.getPrivate()).setProvider(provs[1]));
            Assertions.assertArrayEquals(data, dec,
                    "CMS AES-CBC non-aligned content corrupted: enc=" + provs[0] + " dec=" + provs[1]);
        }
    }

    @Test
    public void keyTrans_desEdeContent_roundTrips() throws Exception
    {
        // DESEDE_AUTO_IV_GAP regression: the CMS content encryptor inits the
        // content cipher with null AlgorithmParameters (auto-IV), which NPE'd
        // in DESedeBlockCipherSpi. DES-EDE3-CBC is the classic CMS default
        // content algorithm; 30-byte (non-block-aligned) content also keeps
        // the CBC decrypt buffering fix honest for the 8-byte block size.
        KeyPair kp = jslRsa();
        X509Certificate cert = selfSignedCert(kp);
        byte[] data = new byte[30];
        RANDOM.nextBytes(data);

        for (String[] provs : new String[][]{{JSL, JSL}, {JSL, BC}, {BC, JSL}})
        {
            CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
            gen.addRecipientInfoGenerator(
                    new JceKeyTransRecipientInfoGenerator(cert).setProvider(provs[0]));
            CMSEnvelopedData ed = gen.generate(
                    new CMSProcessableByteArray(data),
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
                            .setProvider(provs[0]).build());
            ed = new CMSEnvelopedData(ed.getEncoded());
            RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();
            byte[] dec = ri.getContent(
                    new JceKeyTransEnvelopedRecipient(kp.getPrivate()).setProvider(provs[1]));
            Assertions.assertArrayEquals(data, dec,
                    "CMS DES-EDE3-CBC content round-trip failed: enc=" + provs[0] + " dec=" + provs[1]);
        }
    }

    @Test
    public void keyTrans_wrongPrivateKey_failsToDecrypt() throws Exception
    {
        // Negative path: the envelope is addressed to one keypair; a JSL
        // decrypt with a different private key must fail rather than hand
        // back content. PKCS#1 implicit rejection turns the bad RSA decrypt
        // into a wrong CEK, so the failure surfaces from the content
        // decryption — either way getContent must throw.
        KeyPair kp = jslRsa();
        KeyPair wrongKp = jslRsa();
        X509Certificate cert = selfSignedCert(kp);

        byte[] data = new byte[64];
        RANDOM.nextBytes(data);

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(
                new JceKeyTransRecipientInfoGenerator(cert).setProvider(JSL));
        CMSEnvelopedData ed = gen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                        .setProvider(JSL).build());
        ed = new CMSEnvelopedData(ed.getEncoded());

        RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();
        try
        {
            ri.getContent(new JceKeyTransEnvelopedRecipient(wrongKp.getPrivate()).setProvider(JSL));
            Assertions.fail("decrypt with the wrong private key must not succeed");
        }
        catch (org.bouncycastle.cms.CMSException e)
        {
            // expected — wrong key cannot recover the CEK / content
        }
    }
}
