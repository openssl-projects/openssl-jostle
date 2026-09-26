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

package org.openssl.jostle.test.spec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * The secret-producer sizing rows for JSL's KEM {@code KeyGenerator}s, on every ML-KEM parameter set and every
 * hybrid, on both spec types: the held size, more and less than it, zero and negative, and sizes that are not a
 * whole number of bytes. Also the two places this deliberately refuses earlier and typed where BouncyCastle
 * refuses late and unchecked, each pinned in both halves.
 */
public class KemKdfSizingLimitTest
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
    public void everyKemAnswersEverySizingRow() throws Exception
    {
        List<String> table = new ArrayList<String>();
        List<String> names = new ArrayList<String>(java.util.Arrays.asList(KemKdfCases.ML_KEM));
        names.addAll(java.util.Arrays.asList(KemKdfCases.HYBRIDS));
        for (String name : names)
        {
            int held = KemKdfCases.secretBits(jsl, name);
            table.add(name + " (held " + held + " bits)");
            for (String row : KemKdfCases.sizingRows(jsl, name, held))
            {
                table.add("  " + row);
            }
        }
        System.out.println("[kem-sizing] JSL\n" + String.join("\n", table));
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
        g.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(bcPair.getPublic(), "AES", 512)
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
        g.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(bcPair.getPublic(), "AES", 0).build());
        IllegalArgumentException theirs = Assertions.assertThrows(IllegalArgumentException.class, g::generateKey);
        Assertions.assertEquals("len must be > 0", theirs.getMessage());

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        KemKdfCases.refusedAtInit(jsl, "ML-KEM-768", kp, 0, KemKdfCases.KDF3_SHA256,
                "KEM key size in bits out of range [1, 32768]: 0");
    }

    @Test
    public void anUnsupportedKdfIsRefusedAtInitNamingIt() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        KemKdfCases.refusedAtInit(jsl, "ML-KEM-768", kp, 256,
                KemKdfCases.kdf(org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_kdf_kdf3,
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha384),
                "unsupported KDF digest 2.16.840.1.101.3.4.2.2; supported: SHA-256, SHA-512, SHAKE128, SHAKE256");
        KemKdfCases.refusedAtInit(jsl, "ML-KEM-768", kp, 256,
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_shake128),
                "unsupported KDF 2.16.840.1.101.3.4.2.11; supported: KDF2, KDF3, HKDF-SHA256/384/512, SHAKE256");
    }

    /**
     * SHAKE256 alone derives at most the provider's SHAKE-256 output, and a larger size is refused at init.
     * BouncyCastle, an XOF of any length, derives it; the divergence is pinned on both sides.
     */
    @Test
    public void shake256AloneIsBoundedByTheDigestItRunsOn() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        org.bouncycastle.asn1.x509.AlgorithmIdentifier shake = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_shake256);
        KeyPair bcPair = KeyPairGenerator.getInstance("ML-KEM-768", bc).generateKeyPair();
        KeyGenerator g = KeyGenerator.getInstance("ML-KEM-768", bc);
        g.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(bcPair.getPublic(), "AES", 520)
                .withKdfAlgorithm(shake).build());
        Assertions.assertEquals(65, g.generateKey().getEncoded().length, "BouncyCastle derives 520 bits");
        Assertions.assertEquals(64, KemKdfCases.bothHalves(jsl, kp, "ML-KEM-768", 512, shake, null).length);
        KemKdfCases.refusedAtInit(jsl, "ML-KEM-768", kp, 520, shake,
                "KEM key size 520 bits is larger than the 512 bits SHAKE-256 derives here");
    }
}
