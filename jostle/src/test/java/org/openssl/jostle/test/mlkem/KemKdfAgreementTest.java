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

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.spec.KemKdfCases;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
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
                rows.add(KemKdfCases.agreeWithBc(jsl, bc, name, bits, KemKdfCases.KDF3_SHA256, null));
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
            KemKdfCases.agreeWithBc(jsl, bc, "ML-KEM-768", 256, kdf, otherInfo);
            KemKdfCases.agreeWithBc(jsl, bc, "ML-KEM-768", 384, kdf, otherInfo);
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
                KemKdfCases.agreeWithBc(jsl, bc, name, bits, null, null);
            }
        }
    }

    /** otherInfo reaches the KDF: the same encapsulation derives a different key under a different one. */
    @Test
    public void otherInfoChangesTheKey() throws Exception
    {
        java.security.KeyPair kp = java.security.KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        byte[] a = KemKdfCases.bothHalves(jsl, kp, "ML-KEM-768", 256, KemKdfCases.KDF3_SHA256, new byte[]{1});
        byte[] b = KemKdfCases.bothHalves(jsl, kp, "ML-KEM-768", 256, KemKdfCases.KDF3_SHA256, new byte[]{2});
        Assertions.assertFalse(java.util.Arrays.equals(a, b));
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
}
