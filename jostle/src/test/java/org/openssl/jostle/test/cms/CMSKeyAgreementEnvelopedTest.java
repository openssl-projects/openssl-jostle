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

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

/**
 * CMS {@code EnvelopedData} key-agreement {@code KeyAgreeRecipientInfo}: BC's
 * own {@code JceKeyAgreeRecipientInfoGenerator} / {@code JceKeyAgreeRecipient},
 * pointed at JSL, build BC's own {@code UserKeyingMaterialSpec} internally
 * (always for EC, for DH whenever a UKM is set) and are refused typed; only
 * Jostle spec types are accepted. {@link #dhEsdh_jslBothDirections_noUkm} is
 * the one shape that still round-trips: DH with no UKM at all, so BC passes
 * no spec.
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

    private static byte[] randomUkm(int len)
    {
        byte[] ukm = new byte[len];
        RANDOM.nextBytes(ukm);
        return ukm;
    }

    private static byte[] randomKid()
    {
        byte[] kid = new byte[8];
        RANDOM.nextBytes(kid);
        return kid;
    }

    private static byte[] randomData()
    {
        byte[] data = new byte[1 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(data);
        return data;
    }

    /**
     * One CMS EnvelopedData key-agreement round-trip. The originator/recipient
     * keypairs share a group/curve; {@code encProv} produces the envelope (key
     * agreement + AES wrap + content encryption) and {@code decProv} recovers
     * it. Asserts the recovered content matches.
     */
    private void roundTrip(org.bouncycastle.asn1.ASN1ObjectIdentifier kaOid,
                           KeyPair origKp, KeyPair recipKp,
                           org.bouncycastle.asn1.ASN1ObjectIdentifier wrapOid, byte[] ukm,
                           String encProv, String decProv) throws Exception
    {
        byte[] data = randomData();

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        JceKeyAgreeRecipientInfoGenerator rig = new JceKeyAgreeRecipientInfoGenerator(
                kaOid, origKp.getPrivate(), origKp.getPublic(), wrapOid);
        if (ukm != null)
        {
            rig.setUserKeyingMaterial(ukm);
        }
        rig.addRecipient(randomKid(), recipKp.getPublic());
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

    @Test
    public void dhEsdh_jslBothDirections_noUkm() throws Exception
    {
        KeyPair orig = dhKeyPair();
        KeyPair recip = dhKeyPair();
        roundTrip(PKCSObjectIdentifiers.id_alg_ESDH, orig, recip,
                CMSAlgorithm.AES128_WRAP, null, JSL, JSL);
    }

    @Test
    public void ecdhOnJslIsRefusedTypedEvenWithoutUkm() throws Exception
    {
        // BC's generator builds a UserKeyingMaterialSpec for every EC scheme
        // regardless of whether setUserKeyingMaterial was ever called.
        KeyPair orig = ecKeyPair("P-256");
        KeyPair recip = ecKeyPair("P-256");

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        JceKeyAgreeRecipientInfoGenerator rig = new JceKeyAgreeRecipientInfoGenerator(
                CMSAlgorithm.ECDH_SHA256KDF, orig.getPrivate(), orig.getPublic(),
                CMSAlgorithm.AES128_WRAP);
        rig.addRecipient(randomKid(), recip.getPublic());
        rig.setProvider(JSL);
        gen.addRecipientInfoGenerator(rig);

        byte[] data = randomData();
        CMSException failure = Assertions.assertThrows(CMSException.class, () ->
                        gen.generate(new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                                        .setProvider(JSL).build()),
                "stock bcpkix's EC key-agreement generator must fail when pointed at JSL, "
                        + "even without an explicit UKM");
        assertCauseNamesJostleUkmSpec(failure);
    }

    @Test
    public void dhWithUkmOnJslIsRefusedTyped() throws Exception
    {
        KeyPair orig = dhKeyPair();
        KeyPair recip = dhKeyPair();

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        JceKeyAgreeRecipientInfoGenerator rig = new JceKeyAgreeRecipientInfoGenerator(
                PKCSObjectIdentifiers.id_alg_ESDH, orig.getPrivate(), orig.getPublic(),
                CMSAlgorithm.AES256_WRAP);
        rig.setUserKeyingMaterial(randomUkm(16));
        rig.addRecipient(randomKid(), recip.getPublic());
        rig.setProvider(JSL);
        gen.addRecipientInfoGenerator(rig);

        byte[] data = randomData();
        CMSException failure = Assertions.assertThrows(CMSException.class, () ->
                        gen.generate(new CMSProcessableByteArray(data),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM)
                                        .setProvider(JSL).build()),
                "stock bcpkix's DH ESDH generator with a UKM must fail when pointed at JSL");
        assertCauseNamesJostleUkmSpec(failure);
    }

    @Test
    public void bcEncryptedEcdhIsRefusedTypedOnJslDecrypt() throws Exception
    {
        KeyPair orig = ecKeyPair("P-256");
        KeyPair recip = ecKeyPair("P-256");

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        JceKeyAgreeRecipientInfoGenerator rig = new JceKeyAgreeRecipientInfoGenerator(
                CMSAlgorithm.ECDH_SHA256KDF, orig.getPrivate(), orig.getPublic(),
                CMSAlgorithm.AES256_WRAP);
        rig.addRecipient(randomKid(), recip.getPublic());
        rig.setProvider(BC);
        gen.addRecipientInfoGenerator(rig);

        CMSEnvelopedData ed = gen.generate(new CMSProcessableByteArray(randomData()),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider(BC).build());
        ed = new CMSEnvelopedData(ed.getEncoded());
        RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();

        CMSException failure = Assertions.assertThrows(CMSException.class, () ->
                        ri.getContent(new JceKeyAgreeEnvelopedRecipient(recip.getPrivate()).setProvider(JSL)),
                "JSL recipient must refuse BC's UserKeyingMaterialSpec on the decrypt side");
        Assertions.assertEquals("originator key invalid.", failure.getMessage());
        assertCauseNamesJostleUkmSpec(failure);
    }

    @Test
    public void bcEncryptedSsdhIsRefusedTypedOnJslDecrypt() throws Exception
    {
        KeyPair orig = dhKeyPair();
        KeyPair recip = dhKeyPair();

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        JceKeyAgreeRecipientInfoGenerator rig = new JceKeyAgreeRecipientInfoGenerator(
                PKCSObjectIdentifiers.id_alg_SSDH, orig.getPrivate(), orig.getPublic(),
                CMSAlgorithm.AES128_WRAP);
        rig.setUserKeyingMaterial(randomUkm(20));
        rig.addRecipient(randomKid(), recip.getPublic());
        rig.setProvider(BC);
        gen.addRecipientInfoGenerator(rig);

        CMSEnvelopedData ed = gen.generate(new CMSProcessableByteArray(randomData()),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider(BC).build());
        ed = new CMSEnvelopedData(ed.getEncoded());
        RecipientInformation ri = ed.getRecipientInfos().getRecipients().iterator().next();

        CMSException failure = Assertions.assertThrows(CMSException.class, () ->
                        ri.getContent(new JceKeyAgreeEnvelopedRecipient(recip.getPrivate()).setProvider(JSL)),
                "JSL recipient must refuse BC's UserKeyingMaterialSpec on the decrypt side (SSDH)");
        Assertions.assertEquals("originator key invalid.", failure.getMessage());
        assertCauseNamesJostleUkmSpec(failure);
    }

    /** Unwraps BC's wrapper exceptions to find the typed refusal underneath. */
    private static void assertCauseNamesJostleUkmSpec(Throwable t)
    {
        for (Throwable cur = t; cur != null; cur = cur.getCause())
        {
            if (cur instanceof InvalidAlgorithmParameterException
                    && cur.getMessage() != null
                    && cur.getMessage().contains("org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec"))
            {
                return;
            }
        }
        Assertions.fail("expected an InvalidAlgorithmParameterException naming "
                + "org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec in the cause chain of: " + t);
    }
}
