/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mac;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class MacLengthsTest
{
    @Test
    public void testKnownHmacLengths()
    {
        Assertions.assertEquals(20, MacLengths.getMacLength("HMAC", "SHA-1"));
        Assertions.assertEquals(20, MacLengths.getMacLength("HMAC", "SHA1"));
        Assertions.assertEquals(28, MacLengths.getMacLength("HMAC", "SHA2-224"));
        Assertions.assertEquals(32, MacLengths.getMacLength("HMAC", "SHA2-256"));
        Assertions.assertEquals(48, MacLengths.getMacLength("HMAC", "SHA2-384"));
        Assertions.assertEquals(64, MacLengths.getMacLength("HMAC", "SHA2-512"));
        Assertions.assertEquals(28, MacLengths.getMacLength("HMAC", "SHA2-512/224"));
        Assertions.assertEquals(32, MacLengths.getMacLength("HMAC", "SHA2-512/256"));
        Assertions.assertEquals(28, MacLengths.getMacLength("HMAC", "SHA3-224"));
        Assertions.assertEquals(32, MacLengths.getMacLength("HMAC", "SHA3-256"));
        Assertions.assertEquals(48, MacLengths.getMacLength("HMAC", "SHA3-384"));
        Assertions.assertEquals(64, MacLengths.getMacLength("HMAC", "SHA3-512"));
        Assertions.assertEquals(16, MacLengths.getMacLength("HMAC", "MD5"));
        Assertions.assertEquals(36, MacLengths.getMacLength("HMAC", "MD5-SHA1"));
        Assertions.assertEquals(32, MacLengths.getMacLength("HMAC", "SM3"));
        Assertions.assertEquals(20, MacLengths.getMacLength("HMAC", "RIPEMD-160"));
    }

    @Test
    public void testKnownCmacLengths()
    {
        Assertions.assertEquals(16, MacLengths.getMacLength("CMAC", "aes-cbc"));
    }

    @Test
    public void testUnknownMacLengthsUseNativeFallback()
    {
        Assertions.assertEquals(MacLengths.UNKNOWN_MAC_LENGTH, MacLengths.getMacLength("HMAC", null));
        Assertions.assertEquals(MacLengths.UNKNOWN_MAC_LENGTH, MacLengths.getMacLength("HMAC", "SHAKE-128"));
        Assertions.assertEquals(MacLengths.UNKNOWN_MAC_LENGTH, MacLengths.getMacLength("CMAC", "des-ede3-cbc"));
        Assertions.assertEquals(MacLengths.UNKNOWN_MAC_LENGTH, MacLengths.getMacLength("KMAC", "SHAKE-128"));
    }
}
