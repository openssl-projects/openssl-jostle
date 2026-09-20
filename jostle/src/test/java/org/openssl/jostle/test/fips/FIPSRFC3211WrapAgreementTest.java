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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;

import java.security.Provider;
import java.security.Security;
import java.util.Locale;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * The FIPS half of RFC 3211 key wrap: JSLFIPS registers none of it.
 *
 * <p>The base twin is {@code RFC3211WrapAgreementTest}. There is nothing to
 * compare here, and that is the point — the absence is asserted rather than
 * left to be inferred from the base class saying nothing about it.
 */
public class FIPSRFC3211WrapAgreementTest
{
    private static final String WRAP_PREFIX = "org.openssl.jostle.jcajce.provider.wrap.";

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();

        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * Two witnesses. Nothing under the wrap package, and no Cipher service
     * anywhere on JSLFIPS whose name says RFC3211 — the second catches a move
     * to another package, which a prefix alone would miss.
     */
    @Test
    public void jslFipsRegistersNoRfc3211Wrap()
    {
        Provider fips = Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);

        Assertions.assertTrue(
                ProviderSurfaceGuard.registeredSurface(
                        fips, WRAP_PREFIX, new String[]{"Cipher"}).isEmpty(),
                "JSLFIPS registers a Cipher under the wrap package");

        // The provider's raw keys, not getServices(): that returns primaries
        // only, so an ALIAS naming RFC3211 and pointing outside the wrap
        // package would be invisible to both witnesses.
        SortedSet<String> named = new TreeSet<String>();
        for (Object key : fips.keySet())
        {
            String k = String.valueOf(key);
            if ((k.startsWith("Cipher.") || k.startsWith("Alg.Alias.Cipher."))
                    && k.toUpperCase(Locale.ROOT).contains("RFC3211"))
            {
                named.add(k);
            }
        }
        Assertions.assertTrue(named.isEmpty(),
                "JSLFIPS carries an RFC 3211 Cipher entry: " + named);
    }

    /**
     * The base provider DOES serve it, so the absence above is a statement
     * about JSLFIPS rather than about the prefix being wrong.
     */
    @Test
    public void theBaseProviderServesItSoTheAbsenceMeansSomething()
    {
        Assertions.assertFalse(
                ProviderSurfaceGuard.registeredSurface(
                        Security.getProvider(JostleProvider.PROVIDER_NAME),
                        WRAP_PREFIX, new String[]{"Cipher"}).isEmpty(),
                "JSL registers no RFC 3211 wrap either, so the prefix is wrong and the FIPS"
                        + " absence assertion proves nothing");
    }
}
