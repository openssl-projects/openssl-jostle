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
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.provider.OidSpellingParityTest;

/**
 * The JSLFIPS twin of {@code OidSpellingParityTest}: every OID JSLFIPS answers
 * to must resolve under both the bare and the {@code "OID."}-prefixed
 * spelling.
 * <p>
 * Not redundant with the base class. The two providers build their surfaces
 * from separate {@code Prov*} trees — {@code ProvFIPSEC} is not
 * {@code ProvEC} — so a registration corrected in one says nothing about the
 * other, and JSLFIPS registers families the base provider does not gate the
 * same way. Measured before the fix: 75 of 114 OIDs on JSLFIPS resolved by the
 * bare spelling only.
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSOidSpellingParityTest
{
    /**
     * Non-vacuity floor, measured at 114. Lower than the base provider's
     * because JSLFIPS serves a smaller surface — a threshold shared with JSL
     * would pass here without asserting anything.
     */
    private static final int MIN_OIDS = 100;

    private static JostleFIPSProvider provider;

    @BeforeAll
    static void before()
    {
        provider = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void everyOidResolvesUnderBothSpellings()
    {
        OidSpellingParityTest.assertBothSpellings(provider, MIN_OIDS);
    }
}
