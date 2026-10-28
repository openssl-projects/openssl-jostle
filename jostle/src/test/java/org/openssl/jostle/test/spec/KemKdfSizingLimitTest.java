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

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

/**
 * The secret-producer sizing rows for JSL's KEM {@code KeyGenerator}s, on every ML-KEM parameter set and every
 * hybrid, on both spec types: the held size, more and less than it, zero and negative, and sizes that are not a
 * whole number of bytes. Where this refuses earlier and typed than BouncyCastle, KemKdfAgreementTest pins both
 * halves.
 */
public class KemKdfSizingLimitTest
{
    private static Provider jsl;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void everyKemAnswersEverySizingRow() throws Exception
    {
        List<String> table = new ArrayList<String>();
        List<String> names = new ArrayList<String>(Arrays.asList(KemKdfCases.ML_KEM));
        names.addAll(Arrays.asList(KemKdfCases.HYBRIDS));
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

    @Test
    public void anUnsupportedKdfIsRefusedAtInitNamingIt() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        KemKdfCases.refusedAtInit(jsl, "ML-KEM-768", kp, 256,
                KemKdfCases.kdf(X9ObjectIdentifiers.id_kdf_kdf3,
                        NISTObjectIdentifiers.id_sha384),
                "unsupported KDF digest 2.16.840.1.101.3.4.2.2; supported: SHA-256, SHA-512, SHAKE128, SHAKE256");
        KemKdfCases.refusedAtInit(jsl, "ML-KEM-768", kp, 256,
                new AlgorithmIdentifier(
                        NISTObjectIdentifiers.id_shake128),
                "unsupported KDF 2.16.840.1.101.3.4.2.11; supported: KDF2, KDF3, HKDF-SHA256/384/512, SHAKE256");
    }

}
