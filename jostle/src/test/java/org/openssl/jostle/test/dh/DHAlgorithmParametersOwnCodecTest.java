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

package org.openssl.jostle.test.dh;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.dh.DHAlgorithmParameters;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;

/**
 * {@code DHAlgorithmParameters} is its own PKCS#3 / X9.42 codec, with no platform delegate: registered under a
 * provider that is not "JSL" and placed first, it constructs and round-trips. This is the JSLFIPS-first ordering
 * without the FIPS module.
 */
public class DHAlgorithmParametersOwnCodecTest
{
    private static final String PSEUDO = "JOSTLE_PSEUDO_DH";

    @Test
    public void constructsAndRoundTripsUnderAnotherProviderPlacedFirst() throws Exception
    {
        Provider pseudo = new Provider(PSEUDO, 1.0, "DH parameters under another provider")
        {
        };
        pseudo.put("AlgorithmParameters.DH", DHAlgorithmParameters.class.getName());

        Security.removeProvider(PSEUDO);
        Security.insertProviderAt(pseudo, 1);
        try
        {
            AlgorithmParameters params = AlgorithmParameters.getInstance("DH", PSEUDO);
            DHParameterSpec in = new DHParameterSpec(BigInteger.valueOf(23), BigInteger.valueOf(5));
            params.init(in);
            AlgorithmParameters decoded = AlgorithmParameters.getInstance("DH", PSEUDO);
            decoded.init(params.getEncoded());
            DHParameterSpec out = decoded.getParameterSpec(DHParameterSpec.class);
            Assertions.assertEquals(in.getP(), out.getP());
            Assertions.assertEquals(in.getG(), out.getG());
        }
        finally
        {
            Security.removeProvider(PSEUDO);
        }
    }
}
