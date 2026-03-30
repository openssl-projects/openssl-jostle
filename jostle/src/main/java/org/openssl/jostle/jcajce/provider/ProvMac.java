/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.jcajce.provider.mac.MacServiceSPI;

import java.util.HashMap;
import java.util.Map;

class ProvMac
{
    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvMac.class.getPackage().getName() + ".mac.";

    public void configure(final JostleProvider provider)
    {
        addMac(provider, "HMACSHA1", "SHA-1", "HmacSHA1");
        addMac(provider, "HMACSHA224", "SHA-224", "HmacSHA224");
        addMac(provider, "HMACSHA256", "SHA-256", "HmacSHA256");
        addMac(provider, "HMACSHA384", "SHA-384", "HmacSHA384");
        addMac(provider, "HMACSHA512", "SHA-512", "HmacSHA512");
        addMac(provider, "HMACSHA512/224", "SHA-512/224", "HmacSHA512/224");
        addMac(provider, "HMACSHA512/256", "SHA-512/256", "HmacSHA512/256");
        addMac(provider, "HMACSHA3-224", "SHA3-224", "HmacSHA3-224");
        addMac(provider, "HMACSHA3-256", "SHA3-256", "HmacSHA3-256");
        addMac(provider, "HMACSHA3-384", "SHA3-384", "HmacSHA3-384");
        addMac(provider, "HMACSHA3-512", "SHA3-512", "HmacSHA3-512");
        addMac(provider, "HMACMD5", "MD5", "HmacMD5");
        addMac(provider, "HMACRIPEMD160", "RIPEMD-160", "HmacRIPEMD160");
        addMac(provider, "HMACSM3", "SM3", "HmacSM3");
    }

    private void addMac(final JostleProvider provider, final String name, final String digestName, final String... aliases)
    {
        String className = PREFIX + "MacServiceSPI$" + name.replace("-", "_").replace("/", "_");
        provider.addAlgorithmImplementation("Mac", name, className, generalAttributes, (arg) -> new MacServiceSPI("HMAC", digestName));
        provider.addAlias("Mac", name, aliases);
    }
}
