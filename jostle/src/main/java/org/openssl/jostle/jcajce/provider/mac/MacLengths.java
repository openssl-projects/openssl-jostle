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

final class MacLengths
{
    static final int UNKNOWN_MAC_LENGTH = -1;

    private MacLengths()
    {
    }

    static int getMacLength(String macName, String function)
    {
        if ("CMAC".equals(macName))
        {
            if ("aes-cbc".equals(function))
            {
                return 16;
            }
            return UNKNOWN_MAC_LENGTH;
        }

        if (!"HMAC".equals(macName) || function == null)
        {
            return UNKNOWN_MAC_LENGTH;
        }

        switch (function)
        {
            case "SHA-1":
            case "SHA1":
                return 20;
            case "SHA2-224":
                return 28;
            case "SHA2-256":
                return 32;
            case "SHA2-384":
                return 48;
            case "SHA2-512":
                return 64;
            case "SHA2-512/224":
                return 28;
            case "SHA2-512/256":
                return 32;
            case "SHA3-224":
                return 28;
            case "SHA3-256":
                return 32;
            case "SHA3-384":
                return 48;
            case "SHA3-512":
                return 64;
            case "MD5":
                return 16;
            case "MD5-SHA1":
                return 36;
            case "SM3":
                return 32;
            case "RIPEMD-160":
                return 20;
            default:
                return UNKNOWN_MAC_LENGTH;
        }
    }
}
