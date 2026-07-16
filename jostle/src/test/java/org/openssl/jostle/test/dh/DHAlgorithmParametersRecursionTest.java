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
 * Regression guard for the {@code DHAlgorithmParameters} delegate-resolution
 * recursion.
 *
 * <p>The SPI is registered under BOTH {@code "JSL"} and {@code "JSLFIPS"};
 * its {@code resolveDelegate()} must skip EVERY Jostle-provided
 * {@code AlgorithmParameters("DH")} — matched by SPI package, not by the
 * single provider name {@code "JSL"}. A deployment where a Jostle-derived
 * provider precedes the platform DH provider (the canonical FIPS setup,
 * {@code insertProviderAt(new JostleFIPSProvider(), 1)}) would otherwise
 * resolve {@code getInstance("DH")} back into this class and recurse to a
 * {@code StackOverflowError}.
 *
 * <p>This reproduces the JSLFIPS-first ordering without the FIPS native
 * module: a pseudo provider mapping {@code AlgorithmParameters("DH")} to
 * the real Jostle SPI class is inserted ahead of the platform, then the
 * SPI is constructed through it. Before the fix this recursed; after it,
 * {@code resolveDelegate} skips the Jostle SPI (matched by package) and
 * delegates to the platform codec. The DSA / EC / GCM {@code
 * AlgorithmParameters} classes share the identical guard.
 */
public class DHAlgorithmParametersRecursionTest
{
    private static final String PSEUDO = "JOSTLE_PSEUDO_FIPS_DH";

    @Test
    public void resolveDelegate_skipsJostleSpiByPackage_noRecursion() throws Exception
    {
        // A second provider (name is NOT "JSL") registering this exact
        // SPI class — the shape a JSLFIPS-first deployment presents.
        Provider pseudo = new Provider(PSEUDO, 1.0, "DH resolveDelegate recursion regression")
        {
        };
        pseudo.put("AlgorithmParameters.DH", DHAlgorithmParameters.class.getName());

        Security.removeProvider(PSEUDO);
        Security.insertProviderAt(pseudo, 1);
        try
        {
            // Construction runs resolveDelegate(); before the fix this
            // StackOverflowErrors because the pseudo provider (not named
            // "JSL") was chosen as its own delegate and re-instantiated.
            AlgorithmParameters params = AlgorithmParameters.getInstance("DH", PSEUDO);
            Assertions.assertNotNull(params);

            // The resolved delegate must be a real platform codec, so a
            // round-trip through it works.
            params.init(new DHParameterSpec(BigInteger.valueOf(23), BigInteger.valueOf(5)));
            Assertions.assertNotNull(params.getEncoded());
        }
        finally
        {
            Security.removeProvider(PSEUDO);
        }
    }
}
