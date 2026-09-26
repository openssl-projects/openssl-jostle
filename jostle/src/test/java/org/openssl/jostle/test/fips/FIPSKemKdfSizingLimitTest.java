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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.spec.KemKdfCases;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;

/**
 * The JSLFIPS twin of {@code KemKdfSizingLimitTest}: the secret-producer sizing rows on every KEM the module
 * serves, on both spec types.
 */
public class FIPSKemKdfSizingLimitTest
{
    private static JostleFIPSProvider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void everyServedKemAnswersEverySizingRow() throws Exception
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
        List<String> table = new ArrayList<String>();
        List<String> names = new ArrayList<String>(java.util.Arrays.asList(KemKdfCases.ML_KEM));
        names.addAll(java.util.Arrays.asList(KemKdfCases.HYBRIDS));
        for (String name : names)
        {
            if (fips.getService("KeyGenerator", name) == null)
            {
                table.add(name + ": not served");
                continue;
            }
            int held = KemKdfCases.secretBits(fips, name);
            table.add(name + " (held " + held + " bits)");
            for (String row : KemKdfCases.sizingRows(fips, name, held))
            {
                table.add("  " + row);
            }
        }
        System.out.println("[kem-sizing] JSLFIPS\n" + String.join("\n", table));
    }

    @Test
    public void anUnsupportedKdfIsRefusedAtInitNamingIt() throws Exception
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", fips).generateKeyPair();
        KemKdfCases.refusedAtInit(fips, "ML-KEM-768", kp, 256,
                KemKdfCases.kdf(org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_kdf_kdf3,
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha384),
                "unsupported KDF digest 2.16.840.1.101.3.4.2.2; supported: SHA-256, SHA-512, SHAKE128, SHAKE256");
    }
}
