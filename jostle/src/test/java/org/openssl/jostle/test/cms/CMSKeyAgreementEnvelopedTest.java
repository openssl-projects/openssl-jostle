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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

/**
 * Full CMS {@code EnvelopedData} key-agreement round-trips exercising the
 * actual consumer scenario: BouncyCastle's CMS layer drives the Jostle
 * {@code KeyAgreement} SPIs through the standard JCE API, both producing and
 * consuming the {@code KeyAgreeRecipientInfo}.
 *
 * <ul>
 *   <li>DH: {@code id-alg-ESDH} and {@code id-alg-SSDH} (X9.42 SHA-1 KDF).</li>
 *   <li>EC: {@code dhSinglePass-stdDH-sha1/256kdf-scheme} (X9.63 KDF).</li>
 * </ul>
 *
 * Each is run in both directions — JSL encrypts / BC decrypts and the reverse —
 * with AES-128/256 key wrap, AES-128-GCM content, and a random UKM, so a
 * divergence pinpoints which side is wrong.
 */
public class CMSKeyAgreementEnvelopedTest
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

    private static KeyPair dhKeyPair() throws Exception
    {
        // RFC 7919 ffdhe2048 named group — fixed, so both keypairs share it.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JSL);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static KeyPair ecKeyPair(String curve) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    /**
     * One CMS EnvelopedData key-agreement round-trip. The originator/recipient
     * keypairs share a group/curve; {@code encProv} produces the envelope (key
     * agreement + AES wrap + content encryption) and {@code decProv} recovers
     * it. Asserts the recovered content matches.
     */
    private void roundTrip(ASN1ObjectIdentifier kaOid,
                           KeyPair origKp, KeyPair recipKp,
                           ASN1ObjectIdentifier wrapOid, byte[] ukm,
                           String encProv, String decProv) throws Exception
    {
        byte[] data = new byte[1 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(data);
        byte[] kid = new byte[8];
        RANDOM.nextBytes(kid);

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        JceKeyAgreeRecipientInfoGenerator rig = new JceKeyAgreeRecipientInfoGenerator(
                kaOid, origKp.getPrivate(), origKp.getPublic(), wrapOid);
        if (ukm != null)
        {
            rig.setUserKeyingMaterial(ukm);
        }
        rig.addRecipient(kid, recipKp.getPublic());
        rig.setProvider(encProv);
        gen.addRecipientInfoGenerator(rig);

        CMSEnvelopedData ed = gen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                        .setProvider(encProv).build());

        // Serialise/parse to exercise the real wire encoding path.
        ed = new CMSEnvelopedData(ed.getEncoded());

        RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();
        byte[] dec = ri.getContent(
                new JceKeyAgreeEnvelopedRecipient(recipKp.getPrivate()).setProvider(decProv));

        Assertions.assertArrayEquals(data, dec,
                "CMS key-agree round-trip failed: ka=" + kaOid + " wrap=" + wrapOid
                        + " enc=" + encProv + " dec=" + decProv
                        + " ukm=" + (ukm == null ? "none" : ukm.length));
    }

    private static byte[] randomUkm(int len)
    {
        byte[] ukm = new byte[len];
        RANDOM.nextBytes(ukm);
        return ukm;
    }

    // ----- DH (X9.42 / RFC 2631 KDF) -----

    @Test
    public void dhEsdh_jslEncrypt_bcDecrypt() throws Exception
    {
        KeyPair orig = dhKeyPair();
        KeyPair recip = dhKeyPair();
        roundTrip(PKCSObjectIdentifiers.id_alg_ESDH, orig, recip,
                CMSAlgorithm.AES256_WRAP, randomUkm(16), JSL, BC);
    }

    @Test
    public void dhEsdh_bcEncrypt_jslDecrypt() throws Exception
    {
        KeyPair orig = dhKeyPair();
        KeyPair recip = dhKeyPair();
        roundTrip(PKCSObjectIdentifiers.id_alg_ESDH, orig, recip,
                CMSAlgorithm.AES256_WRAP, randomUkm(16), BC, JSL);
    }

    @Test
    public void dhEsdh_jslBothDirections_noUkm() throws Exception
    {
        KeyPair orig = dhKeyPair();
        KeyPair recip = dhKeyPair();
        roundTrip(PKCSObjectIdentifiers.id_alg_ESDH, orig, recip,
                CMSAlgorithm.AES128_WRAP, null, JSL, JSL);
    }

    @Test
    public void dhSsdh_jslEncrypt_bcDecrypt() throws Exception
    {
        KeyPair orig = dhKeyPair();
        KeyPair recip = dhKeyPair();
        roundTrip(PKCSObjectIdentifiers.id_alg_SSDH, orig, recip,
                CMSAlgorithm.AES128_WRAP, randomUkm(20), JSL, BC);
    }

    @Test
    public void dhSsdh_bcEncrypt_jslDecrypt() throws Exception
    {
        KeyPair orig = dhKeyPair();
        KeyPair recip = dhKeyPair();
        roundTrip(PKCSObjectIdentifiers.id_alg_SSDH, orig, recip,
                CMSAlgorithm.AES128_WRAP, randomUkm(20), BC, JSL);
    }

    // ----- EC (X9.63 KDF) -----

    @Test
    public void ecdhSha256_jslEncrypt_bcDecrypt() throws Exception
    {
        KeyPair orig = ecKeyPair("P-256");
        KeyPair recip = ecKeyPair("P-256");
        roundTrip(CMSAlgorithm.ECDH_SHA256KDF, orig, recip,
                CMSAlgorithm.AES256_WRAP, randomUkm(16), JSL, BC);
    }

    @Test
    public void ecdhSha256_bcEncrypt_jslDecrypt() throws Exception
    {
        KeyPair orig = ecKeyPair("P-256");
        KeyPair recip = ecKeyPair("P-256");
        roundTrip(CMSAlgorithm.ECDH_SHA256KDF, orig, recip,
                CMSAlgorithm.AES256_WRAP, randomUkm(16), BC, JSL);
    }

    @Test
    public void ecdhSha1_jslEncrypt_bcDecrypt() throws Exception
    {
        KeyPair orig = ecKeyPair("P-384");
        KeyPair recip = ecKeyPair("P-384");
        roundTrip(CMSAlgorithm.ECDH_SHA1KDF, orig, recip,
                CMSAlgorithm.AES128_WRAP, null, JSL, BC);
    }

    @Test
    public void ecdhSha1_bcEncrypt_jslDecrypt() throws Exception
    {
        KeyPair orig = ecKeyPair("P-384");
        KeyPair recip = ecKeyPair("P-384");
        roundTrip(CMSAlgorithm.ECDH_SHA1KDF, orig, recip,
                CMSAlgorithm.AES128_WRAP, null, BC, JSL);
    }

    @Test
    public void ecdh_certificateRecipient_roundTrips() throws Exception
    {
        // CMS_FOREIGN_KEY_KEM_EC_GAP regression: addRecipient(cert) hands the
        // JSL ECDH SPI the certificate's public key (sun.security.ec.*) —
        // previously rejected with "expected a Jostle-provider ECPublicKey".
        KeyPair orig = ecKeyPair("P-256");
        KeyPair recip = ecKeyPair("P-256");

        java.security.KeyPair signerKp;
        java.security.KeyPairGenerator rsaKpg =
                java.security.KeyPairGenerator.getInstance("RSA", JSL);
        rsaKpg.initialize(2048);
        signerKp = rsaKpg.generateKeyPair();
        org.bouncycastle.asn1.x500.X500Name dn =
                new org.bouncycastle.asn1.x500.X500Name("CN=Jostle EC KeyAgree Cert");
        org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder builder =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                        dn, java.math.BigInteger.valueOf(1),
                        new java.util.Date(System.currentTimeMillis() - 3600_000L),
                        new java.util.Date(System.currentTimeMillis() + 3600_000L),
                        dn, recip.getPublic());
        org.bouncycastle.operator.ContentSigner signer =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider(BC).build(signerKp.getPrivate());
        java.security.cert.X509Certificate cert =
                new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                        .getCertificate(builder.build(signer));

        byte[] data = new byte[64];
        RANDOM.nextBytes(data);

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        JceKeyAgreeRecipientInfoGenerator rig = new JceKeyAgreeRecipientInfoGenerator(
                CMSAlgorithm.ECDH_SHA256KDF, orig.getPrivate(), orig.getPublic(),
                CMSAlgorithm.AES128_WRAP);
        rig.addRecipient(cert);
        rig.setProvider(JSL);
        gen.addRecipientInfoGenerator(rig);

        CMSEnvelopedData ed = gen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                        .setProvider(JSL).build());
        ed = new CMSEnvelopedData(ed.getEncoded());

        RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();
        byte[] dec = ri.getContent(
                new JceKeyAgreeEnvelopedRecipient(recip.getPrivate()).setProvider(JSL));
        Assertions.assertArrayEquals(data, dec,
                "CMS EC key-agree round-trip with certificate recipient failed");
    }

    @Test
    public void ecdh_wrongPrivateKey_failsToDecrypt() throws Exception
    {
        // Negative path: a different recipient private key derives a
        // different KEK, so the AES key-unwrap fails. Proves the agreement
        // and KDF actually depend on the key — a stub KDF returning a
        // constant KEK would pass every positive round-trip above.
        KeyPair orig = ecKeyPair("P-256");
        KeyPair recip = ecKeyPair("P-256");
        KeyPair wrong = ecKeyPair("P-256");

        byte[] data = new byte[64];
        RANDOM.nextBytes(data);
        byte[] kid = new byte[8];
        RANDOM.nextBytes(kid);

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        JceKeyAgreeRecipientInfoGenerator rig = new JceKeyAgreeRecipientInfoGenerator(
                CMSAlgorithm.ECDH_SHA256KDF, orig.getPrivate(), orig.getPublic(),
                CMSAlgorithm.AES128_WRAP);
        rig.addRecipient(kid, recip.getPublic());
        rig.setProvider(JSL);
        gen.addRecipientInfoGenerator(rig);

        CMSEnvelopedData ed = gen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                        .setProvider(JSL).build());
        ed = new CMSEnvelopedData(ed.getEncoded());

        RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();
        try
        {
            ri.getContent(new JceKeyAgreeEnvelopedRecipient(wrong.getPrivate()).setProvider(JSL));
            Assertions.fail("decrypt with the wrong private key must not succeed");
        }
        catch (org.bouncycastle.cms.CMSException e)
        {
            // expected — wrong key derives a wrong KEK, unwrap fails
        }
    }
}
