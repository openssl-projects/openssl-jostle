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
package org.openssl.jostle.test.mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;

/**
 * Instance state across init, reset and doFinal, against BouncyCastle and SunJCE where they serve the algorithm.
 */
public class MacStateContractTest
{
    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void resetBeforeInitIsANoOp() throws Exception
    {
        MacCells.resetBeforeInitIsANoOp(JostleProvider.PROVIDER_NAME,
                "HmacSHA256", "AESCMAC", "AESGMAC", "POLY1305", "KMAC128");
    }

    @Test
    public void refusedKmacSpecLeavesMacLengthUnchanged() throws Exception
    {
        MacCells.refusedKmacSpecLeavesMacLengthUnchanged(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void poly1305SecondDoFinalEqualsBcAndFresh() throws Exception
    {
        MacCells.poly1305SecondDoFinalEqualsBcAndFresh(JostleProvider.PROVIDER_NAME);
    }
}
