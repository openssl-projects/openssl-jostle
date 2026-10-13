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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.eddsa.Rfc8032VectorCells;
import org.openssl.jostle.test.eddsa.Rfc8032Vectors;

import java.security.Provider;
import java.util.Locale;

/**
 * The RFC 8032 known answers through the FIPS provider. A name is run exactly when the module serves it, and
 * its registration is required to agree with the module.
 */
public class FIPSRfc8032VectorTest
{
    private static Provider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    /** Runs on every module: each vector's signature name is registered exactly when the module serves it. */
    @Test
    public void registrationMatchesTheModule()
    {
        for (Rfc8032Vectors.Vector v : Rfc8032Vectors.ALL)
        {
            Assertions.assertEquals(moduleServes(v), fips.getService("Signature", v.algorithm) != null, v.algorithm);
        }
    }

    @Test
    public void everyServedVectorMatches() throws Exception
    {
        int served = 0;
        for (Rfc8032Vectors.Vector v : Rfc8032Vectors.ALL)
        {
            if (moduleServes(v))
            {
                Rfc8032VectorCells.check(JostleFIPSProvider.PROVIDER_NAME, v);
                served++;
            }
        }
        System.out.println("[fips-rfc8032] served " + served + " of " + Rfc8032Vectors.ALL.length);
        Assumptions.assumeTrue(served > 0, "the module serves no EdDSA signature");
    }

    /** The registrar serves an Ed signature only when the module serves the Ed25519 key type too. */
    private static boolean moduleServes(Rfc8032Vectors.Vector v)
    {
        return FIPSTestUtil.moduleServesKeyMgmt("ED25519")
                && FIPSTestUtil.moduleServesSignature(v.algorithm.toUpperCase(Locale.ROOT));
    }
}
