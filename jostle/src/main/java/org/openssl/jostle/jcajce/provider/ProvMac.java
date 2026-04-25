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
        addMac(provider, "HMAC", "SHA1", "SHA-1");
        addMac(provider, "HMAC", "SHA224", "SHA2-224");
        addMac(provider, "HMAC", "SHA256", "SHA2-256");
        addMac(provider, "HMAC", "SHA384", "SHA2-384");
        addMac(provider, "HMAC", "SHA512", "SHA2-512");
        addMac(provider, "HMAC", "SHA512/224", "SHA2-512/224");
        addMac(provider, "HMAC", "SHA512/256", "SHA2-512/256");

        addMac(provider, "HMAC", "SHA3-224", "SHA3-224");
        addMac(provider, "HMAC", "SHA3-256", "SHA3-256");
        addMac(provider, "HMAC", "SHA3-384", "SHA3-384");
        addMac(provider, "HMAC", "SHA3-512", "SHA3-512");

        addMac(provider, "HMAC", "SM3", "SM3");
        addMac(provider, "HMAC", "MD5", "MD5");
        addMac(provider, "HMAC", "MD5SHA1", "MD5-SHA1");

        addMac(provider, "HMAC", "RIPEMD160", "RIPEMD-160");

        // AES CMAC -- note function _AES is just a placeholder, actual function is selected based on key size
        provider.addAlgorithmImplementation("Mac", "AESCMAC", PREFIX + "MacServiceSPI$AESCMAC",
                generalAttributes, (arg) -> new MacServiceSPI("CMAC", "aes-cbc"));

    }

    private void addMac(JostleProvider provider, String type, String name, String function)
    {
        String mainName = type + name;
        String className = PREFIX + "MacServiceSPI$" + mainName.replace("-", "_").replace("/", "_");
        provider.addAlgorithmImplementation("Mac", mainName, className, generalAttributes, (arg) -> new MacServiceSPI(type, function));
        provider.addAlias("Mac", mainName, type + "-" + name, type + "/" + name);
    }
}
