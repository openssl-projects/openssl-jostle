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
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.Cipher;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The key wraps JSLFIPS registers report a block size of 0, as BouncyCastle does; the AES wraps are registered
 * exactly when the module fetches them.
 */
public class FIPSBlockSizeContractTest
{
    private static Provider fips;

    @BeforeAll
    public static void setUp()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        fips = TestUtil.addFipsProvider();
    }

    private static boolean isWrap(String name)
    {
        String upper = name.toUpperCase(Locale.ROOT);
        return upper.contains("WRAP") || upper.matches("2\\.16\\.840\\.1\\.101\\.3\\.4\\.1\\.(5|8|25|28|45|48)");
    }

    @Test
    public void everyRegisteredKeyWrapReportsZero() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        int wraps = 0;
        for (Provider.Service sv : fips.getServices())
        {
            if (!"Cipher".equals(sv.getType()) || !isWrap(sv.getAlgorithm()))
            {
                continue;
            }
            wraps++;
            int size = Cipher.getInstance(sv.getAlgorithm(), JostleFIPSProvider.PROVIDER_NAME).getBlockSize();
            if (size != 0)
            {
                failures.add(sv.getAlgorithm() + ": " + size);
            }
        }
        boolean fetchable = FIPSNISelector.BlockCipherNI.cipherFetchable(
                OSSLCipher.AES256.ordinal(), OSSLMode.WRAP.ordinal());
        Assertions.assertEquals(fetchable, fips.getService("Cipher", "AESWrap") != null,
                "AESWrap registered iff the module fetches AES-256-WRAP");
        if (fetchable)
        {
            Assertions.assertTrue(wraps > 0, "the module fetches AES key wrap but no wrap was driven");
        }
        Assertions.assertTrue(failures.isEmpty(), "key wraps not reporting 0: " + failures);
    }
}
