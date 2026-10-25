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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.rsa.RSAKEMAgreementTest;

import java.security.Security;

/**
 * RSA-KTS-KEM-KWS on JSLFIPS beside BouncyCastle: the whole {@link RSAKEMAgreementTest} re-run against the FIPS
 * interface library and lib ctx. Ungated, as {@link FIPSRSAKEMCipherTest}: RSASVE serves on both modules.
 */
public class FIPSRSAKEMAgreementTest
    extends RSAKEMAgreementTest
{
    @BeforeAll
    static void beforeFips()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Override
    protected String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }
}
