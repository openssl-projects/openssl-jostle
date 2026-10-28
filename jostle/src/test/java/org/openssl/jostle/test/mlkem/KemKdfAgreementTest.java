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

package org.openssl.jostle.test.mlkem;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.spec.KemKdfCases;

import javax.crypto.KeyGenerator;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * JSL's KEM {@code KeyGenerator} derives the key as BouncyCastle does, byte for byte in both directions: with
 * the default KDF at several sizes, with each accepted KDF family and an {@code otherInfo}, and with no KDF at
 * sizes up to the shared secret's. The hybrids, which BouncyCastle does not serve, are checked against the
 * specification's KDF3 over the raw secret of the same encapsulation.
 */
public class KemKdfAgreementTest
{
    private static Provider jsl;
    private static Provider bc;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        bc = Security.getProvider("BC") != null ? Security.getProvider("BC") : new BouncyCastleProvider();
    }

    @Test
    public void theDefaultKdfAgreesWithBouncyCastleAtEverySize() throws Exception
    {
        List<String> rows = new ArrayList<String>();
        for (String name : KemKdfCases.ML_KEM)
        {
            for (int bits : new int[]{128, 256, 512})
            {
                rows.add(agreeWithBc(jsl, bc, name, bits, KemKdfCases.KDF3_SHA256, null));
            }
        }
        Assertions.assertEquals(9, rows.size());
    }

    @Test
    public void everyKdfFamilyAgreesWithBouncyCastle() throws Exception
    {
        byte[] otherInfo = {1, 2, 3, 4};
        for (AlgorithmIdentifier kdf : KemKdfCases.KDFS)
        {
            agreeWithBc(jsl, bc, "ML-KEM-768", 256, kdf, otherInfo);
            agreeWithBc(jsl, bc, "ML-KEM-768", 384, kdf, otherInfo);
        }
    }

    /** Without a KDF, a size up to the secret's is the secret's prefix, as BouncyCastle cuts it. */
    @Test
    public void noKdfAgreesWithBouncyCastleUpToTheSecretLength() throws Exception
    {
        for (String name : KemKdfCases.ML_KEM)
        {
            for (int bits : new int[]{8, 128, 248, 256})
            {
                agreeWithBc(jsl, bc, name, bits, null, null);
            }
        }
    }

    /** otherInfo reaches the KDF: the same encapsulation derives a different key under a different one. */
    @Test
    public void otherInfoChangesTheKey() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        byte[] a = KemKdfCases.bothHalves(jsl, kp, "ML-KEM-768", 256, KemKdfCases.KDF3_SHA256, new byte[]{1});
        byte[] b = KemKdfCases.bothHalves(jsl, kp, "ML-KEM-768", 256, KemKdfCases.KDF3_SHA256, new byte[]{2});
        Assertions.assertFalse(Arrays.equals(a, b));
    }

    @Test
    public void everyHybridDefaultIsKdf3OverItsSecret() throws Exception
    {
        List<String> rows = new ArrayList<String>();
        for (String name : KemKdfCases.HYBRIDS)
        {
            for (int bits : new int[]{128, 256, 512, 1024})
            {
                rows.add(KemKdfCases.hybridDefaultIsKdf3(jsl, name, bits, new byte[]{9}));
            }
        }
        System.out.println("[kem-kdf] JSL hybrids\n  " + String.join("\n  ", rows));
        Assertions.assertEquals(16, rows.size());
    }

    /**
     * No KDF and more than the secret: BouncyCastle accepts the spec and throws an unchecked
     * IllegalArgumentException at generateKey; this refuses at init with InvalidAlgorithmParameterException,
     * the exception init declares, since the spec is fully known there.
     */
    @Test
    public void aSizeOverTheSecretWithNoKdfDivergesFromBouncyCastleOnPurpose() throws Exception
    {
        KeyPair bcPair = KeyPairGenerator.getInstance("ML-KEM-768", bc).generateKeyPair();
        KeyGenerator g = KeyGenerator.getInstance("ML-KEM-768", bc);
        g.init(new KEMGenerateSpec.Builder(bcPair.getPublic(), "AES", 512)
                .withNoKdf().build());
        IllegalArgumentException theirs = Assertions.assertThrows(IllegalArgumentException.class, g::generateKey);
        Assertions.assertEquals("no KDF specified and the shared secret is 256 bits, 512 requested",
                theirs.getMessage());

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        KemKdfCases.refusedAtInit(jsl, "ML-KEM-768", kp, 512, null,
                "KEM key size 512 bits is larger than the 256-bit shared secret, and no KDF is set");
    }

    /** A zero size: BouncyCastle refuses at generateKey, unchecked; this refuses at init. */
    @Test
    public void aZeroSizeDivergesFromBouncyCastleOnPurpose() throws Exception
    {
        KeyPair bcPair = KeyPairGenerator.getInstance("ML-KEM-768", bc).generateKeyPair();
        KeyGenerator g = KeyGenerator.getInstance("ML-KEM-768", bc);
        g.init(new KEMGenerateSpec.Builder(bcPair.getPublic(), "AES", 0).build());
        IllegalArgumentException theirs = Assertions.assertThrows(IllegalArgumentException.class, g::generateKey);
        Assertions.assertEquals("len must be > 0", theirs.getMessage());

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        KemKdfCases.refusedAtInit(jsl, "ML-KEM-768", kp, 0, KemKdfCases.KDF3_SHA256,
                "KEM key size in bits out of range [1, 32768]: 0");
    }

    /**
     * SHAKE256 alone derives at most the provider's SHAKE-256 output, and a larger size is refused at init.
     * BouncyCastle, an XOF of any length, derives it; the divergence is pinned on both sides.
     */
    @Test
    public void shake256AloneIsBoundedByTheDigestItRunsOn() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        AlgorithmIdentifier shake = new AlgorithmIdentifier(
                NISTObjectIdentifiers.id_shake256);
        KeyPair bcPair = KeyPairGenerator.getInstance("ML-KEM-768", bc).generateKeyPair();
        KeyGenerator g = KeyGenerator.getInstance("ML-KEM-768", bc);
        g.init(new KEMGenerateSpec.Builder(bcPair.getPublic(), "AES", 520)
                .withKdfAlgorithm(shake).build());
        Assertions.assertEquals(65, g.generateKey().getEncoded().length, "BouncyCastle derives 520 bits");
        Assertions.assertEquals(64, KemKdfCases.bothHalves(jsl, kp, "ML-KEM-768", 512, shake, null).length);
        KemKdfCases.refusedAtInit(jsl, "ML-KEM-768", kp, 520, shake,
                "KEM key size 520 bits is larger than the 512 bits SHAKE-256 derives here");
    }

    private static KEMGenerateSpec bcGenerate(PublicKey pub, int bits, AlgorithmIdentifier kdf, byte[] other)
    {
        KEMGenerateSpec.Builder b =
                new KEMGenerateSpec.Builder(pub, "AES", bits).withOtherInfo(other);
        return (kdf == null ? b.withNoKdf() : b.withKdfAlgorithm(kdf)).build();
    }

    private static KEMExtractSpec bcExtract(PrivateKey priv, byte[] enc, int bits, AlgorithmIdentifier kdf,
                                            byte[] other)
    {
        KEMExtractSpec.Builder b =
                new KEMExtractSpec.Builder(priv, enc, "AES", bits).withOtherInfo(other);
        return (kdf == null ? b.withNoKdf() : b.withKdfAlgorithm(kdf)).build();
    }

    /**
     * One ML-KEM cell against BouncyCastle, both directions: ours encapsulates and BouncyCastle extracts, then
     * the reverse, on keys carried across as encodings.
     *
     * @return a line for the log.
     */
    public static String agreeWithBc(Provider ours, Provider bc, String name, int bits, AlgorithmIdentifier kdf,
                                     byte[] otherInfo)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(name, ours).generateKeyPair();
        KeyFactory bcKf = KeyFactory.getInstance(name, bc);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        String what = name + " " + bits + " bits, kdf " + (kdf == null ? "none" : kdf.getAlgorithm().getId());

        KeyGenerator g = KeyGenerator.getInstance(name, ours);
        g.init(KemKdfCases.ourGenerate(kp.getPublic(), bits, kdf, otherInfo));
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) g.generateKey();
        KeyGenerator x = KeyGenerator.getInstance(name, bc);
        x.init(bcExtract(bcPriv, sent.getEncapsulation(), bits, kdf, otherInfo));
        Assertions.assertArrayEquals(sent.getEncoded(), x.generateKey().getEncoded(), what + ": ours to BC");
        Assertions.assertEquals((bits + 7) / 8, sent.getEncoded().length, what + ": key length");

        KeyGenerator bg = KeyGenerator.getInstance(name, bc);
        bg.init(bcGenerate(bcPub, bits, kdf, otherInfo));
        // SecretKeyWithEncapsulation is qualified where BouncyCastle's is meant: jostle's of that name is used through
        // KemKdfCases
        org.bouncycastle.jcajce.SecretKeyWithEncapsulation bcSent =
                (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bg.generateKey();
        KeyGenerator ox = KeyGenerator.getInstance(name, ours);
        ox.init(KemKdfCases.ourExtract(kp.getPrivate(), bcSent.getEncapsulation(), bits, kdf, otherInfo));
        Assertions.assertArrayEquals(bcSent.getEncoded(), ox.generateKey().getEncoded(), what + ": BC to ours");
        return what;
    }

    /**
     * With no KDF named, BouncyCastle's spec derives through its default KDF3-SHA256, so its 128-bit key is not the
     * secret's prefix that ours gives with no KDF; with KDF3-SHA256 named on our side the two agree. Both halves.
     */
    @Test
    public void bouncyCastlesDefaultKdfIsNotOurNoKdfPrefix() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        PublicKey bcPub = KeyFactory.getInstance("ML-KEM-768", bc)
                .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        KeyGenerator bg = KeyGenerator.getInstance("ML-KEM-768", bc);
        bg.init(new KEMGenerateSpec.Builder(bcPub, "AES", 128).build());
        // SecretKeyWithEncapsulation is qualified where BouncyCastle's is meant: jostle's of that name is imported
        org.bouncycastle.jcajce.SecretKeyWithEncapsulation sent =
                (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bg.generateKey();

        KeyGenerator noKdf = KeyGenerator.getInstance("ML-KEM-768", jsl);
        noKdf.init(KemKdfCases.ourExtract(kp.getPrivate(), sent.getEncapsulation(), 128, null, null));
        KeyGenerator kdf3 = KeyGenerator.getInstance("ML-KEM-768", jsl);
        kdf3.init(KemKdfCases.ourExtract(kp.getPrivate(), sent.getEncapsulation(), 128, KemKdfCases.KDF3_SHA256,
                null));

        Assertions.assertFalse(MessageDigest.isEqual(sent.getEncoded(), noKdf.generateKey().getEncoded()));
        Assertions.assertArrayEquals(sent.getEncoded(), kdf3.generateKey().getEncoded());
    }
}
