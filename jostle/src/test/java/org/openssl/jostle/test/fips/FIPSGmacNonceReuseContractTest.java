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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.mac.MacCells;

import java.security.Security;

/**
 * AESGMAC through the FIPS provider gives one tag per init, as BouncyCastle's does; each cell drives the same
 * sequence on BouncyCastle and requires the same outcome.
 */
public class FIPSGmacNonceReuseContractTest
{
    @BeforeAll
    public static void setUp()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void refusesAfterDoFinal() throws Exception
    {
        MacCells.gmacRefusesAfterDoFinal(JostleFIPSProvider.PROVIDER_NAME);
    }

    @Test
    public void refusesAfterReset() throws Exception
    {
        MacCells.gmacRefusesAfterReset(JostleFIPSProvider.PROVIDER_NAME);
    }

    @Test
    public void refusesTheSameKeyAndNonce() throws Exception
    {
        MacCells.gmacRefusesTheSameKeyAndNonce(JostleFIPSProvider.PROVIDER_NAME);
    }

    @Test
    public void keepsThePreviousStreamAfterARefusedReinit() throws Exception
    {
        MacCells.gmacKeepsThePreviousStreamAfterARefusedReinit(JostleFIPSProvider.PROVIDER_NAME);
    }

    @Test
    public void acceptsABANonces() throws Exception
    {
        MacCells.gmacAcceptsABANonces(JostleFIPSProvider.PROVIDER_NAME);
    }

    @Test
    public void acceptsTheSameNonceAfterARefusedBadKeyInit() throws Exception
    {
        MacCells.gmacAcceptsTheSameNonceAfterARefusedBadKeyInit(JostleFIPSProvider.PROVIDER_NAME);
    }

    @Test
    public void newNonceOrNewKeyEqualsAFreshInstance() throws Exception
    {
        MacCells.gmacNewNonceOrNewKeyEqualsAFreshInstance(JostleFIPSProvider.PROVIDER_NAME);
    }
}
