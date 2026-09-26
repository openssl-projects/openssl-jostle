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

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.spec.KemKdfCases;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * The JSLFIPS twin of {@code KemKdfAgreementTest}: the module's KEM {@code KeyGenerator} derives keys as
 * BouncyCastle does, through the KDF primitives JSLFIPS itself serves.
 */
public class FIPSKemKdfAgreementTest
{
    private static JostleFIPSProvider fips;
    private static Provider bc;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        bc = Security.getProvider("BC") != null ? Security.getProvider("BC") : new BouncyCastleProvider();
    }

    private static void assumeMlKem()
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768"),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
    }

    @Test
    public void theDefaultKdfAgreesWithBouncyCastleAtEverySize() throws Exception
    {
        assumeMlKem();
        for (String name : KemKdfCases.ML_KEM)
        {
            for (int bits : new int[]{128, 256, 512})
            {
                KemKdfCases.agreeWithBc(fips, bc, name, bits, KemKdfCases.KDF3_SHA256, null);
            }
        }
    }

    @Test
    public void everyKdfFamilyAgreesWithBouncyCastle() throws Exception
    {
        assumeMlKem();
        for (AlgorithmIdentifier kdf : KemKdfCases.KDFS)
        {
            KemKdfCases.agreeWithBc(fips, bc, "ML-KEM-768", 256, kdf, new byte[]{1, 2, 3, 4});
        }
    }

    @Test
    public void noKdfAgreesWithBouncyCastleUpToTheSecretLength() throws Exception
    {
        assumeMlKem();
        for (int bits : new int[]{8, 128, 248, 256})
        {
            KemKdfCases.agreeWithBc(fips, bc, "ML-KEM-768", bits, null, null);
        }
    }

    @Test
    public void everyServedHybridDefaultIsKdf3OverItsSecret() throws Exception
    {
        assumeMlKem();
        List<String> rows = new ArrayList<String>();
        for (String name : KemKdfCases.HYBRIDS)
        {
            if (fips.getService("KeyGenerator", name) == null)
            {
                rows.add(name + ": not served");
                continue;
            }
            for (int bits : new int[]{256, 1024})
            {
                rows.add(KemKdfCases.hybridDefaultIsKdf3(fips, name, bits, new byte[]{9}));
            }
        }
        System.out.println("[kem-kdf] JSLFIPS hybrids\n  " + String.join("\n  ", rows));
        Assertions.assertTrue(rows.size() >= 6, "expected three served hybrids at two sizes");
    }
}
