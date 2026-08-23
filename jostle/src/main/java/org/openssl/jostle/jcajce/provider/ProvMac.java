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

        // AES GMAC (NIST SP 800-38D) -- GCM with no plaintext, so every input
        // byte is absorbed as AAD. Like AESCMAC, "aes-gcm" is a placeholder:
        // the C arm picks aes-128/192/256-gcm from the key length. Requires an
        // IvParameterSpec or GCMParameterSpec at init; see MacServiceSPI.
        //
        // Names match BouncyCastle's addGMacAlgorithm, which registers
        // "AES-GMAC" with an "AESGMAC" alias, so a caller resolves the same
        // spelling through either provider.
        //
        // The RFC 9044 OIDs BC also registers (id_aes128/192/256_GMAC) are
        // deliberately NOT registered here. Each names a key size, but the tag
        // and cipher variant follow the key the caller supplies, so an
        // OID-named service could not enforce the size its own name claims.
        provider.addAlgorithmImplementation("Mac", "AESGMAC", PREFIX + "MacServiceSPI$AESGMAC",
                generalAttributes, (arg) -> new MacServiceSPI("GMAC", "aes-gcm"));
        provider.addAlias("Mac", "AESGMAC", "AES-GMAC");

        // Poly1305 (RFC 8439) — a one-time-key MAC (32-byte key, 16-byte tag).
        // The function name is a placeholder (Poly1305 takes no cipher/digest);
        // the C POLY1305 branch ignores it. Uppercase "POLY1305" matches the
        // BouncyCastle registration name.
        provider.addAlgorithmImplementation("Mac", "POLY1305", PREFIX + "MacServiceSPI$POLY1305",
                generalAttributes, (arg) -> new MacServiceSPI("POLY1305", "POLY1305"));

    }

    private void addMac(JostleProvider provider, String type, String name, String function)
    {
        String mainName = type + name;
        String className = PREFIX + "MacServiceSPI$" + mainName.replace("-", "_").replace("/", "_");
        provider.addAlgorithmImplementation("Mac", mainName, className, generalAttributes, (arg) -> new MacServiceSPI(type, function));
        provider.addAlias("Mac", mainName, type + "-" + name, type + "/" + name);
    }
}
