/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.test.provider.CipherProviderBindingSweepTest;

import java.security.Provider;

/**
 * MT-10 wiring sweep against JSLFIPS.
 *
 * <p>Not redundant with {@link CipherProviderBindingSweepTest}: the two
 * providers register different Cipher sets through different {@code Prov*}
 * files ({@code ProvAES} versus {@code ProvFIPSAES}, and so on), so a missed
 * {@code provider} argument in one tree is entirely invisible to the other.
 * That is precisely how MT-14's {@code ProvFIPSXDH} miss survived — the JSL
 * side was flipped and probed, the FIPS side was not.
 *
 * <p>The logic is shared rather than copied so the two cannot drift.
 */
public class FIPSCipherProviderBindingSweepTest
{
    private static Provider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void everyRegisteredUnwrappingCipherIsBoundToItsProvider() throws Exception
    {
        // Measured 25 / 24 against the 3.1.2 module, which serves no
        // Triple-DES; a module that does adds to both. Floors sit below the
        // smaller of the two supported modules.
        CipherProviderBindingSweepTest.sweep(fips, 20, 24);
    }
}
