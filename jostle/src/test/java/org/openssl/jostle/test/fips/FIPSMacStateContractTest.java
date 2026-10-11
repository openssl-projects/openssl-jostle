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
 * Instance state across init, reset and doFinal through the FIPS provider, against BouncyCastle and SunJCE. The
 * FIPS provider serves no Poly1305.
 */
public class FIPSMacStateContractTest
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
    public void resetBeforeInitIsANoOp() throws Exception
    {
        MacCells.resetBeforeInitIsANoOp(JostleFIPSProvider.PROVIDER_NAME, "HmacSHA256", "AESCMAC", "AESGMAC",
                "KMAC128");
    }

    @Test
    public void refusedKmacSpecLeavesMacLengthUnchanged() throws Exception
    {
        MacCells.refusedKmacSpecLeavesMacLengthUnchanged(JostleFIPSProvider.PROVIDER_NAME);
    }
}
