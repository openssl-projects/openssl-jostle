/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.mac.MacServiceSPI;

import java.util.HashMap;
import java.util.Map;

/**
 * Mac registrations for the FIPS provider: the subset of ProvMac's MACs the
 * OpenSSL FIPS module serves as approved (fips=yes) - HMAC over the approved
 * digests, AES-CMAC and AES-GMAC. Deliberately absent: Poly1305 and the HMACs
 * over unapproved digests (MD5, MD5-SHA1, SM3, RIPEMD-160). Names and aliases
 * mirror ProvMac so approved MACs resolve identically through either
 * provider.
 */
class ProvFIPSMac
{
    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.mac.";

    public void configure(final JostleFIPSProvider provider)
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

        // AES CMAC -- the function name selects the cipher family; the actual
        // AES variant follows the key size (as in ProvMac).
        provider.addAlgorithmImplementation("Mac", "AESCMAC", PREFIX + "MacServiceSPI$AESCMAC",
                generalAttributes, (arg) -> new MacServiceSPI(FIPSNISelector.MacServiceNI, "CMAC", "aes-cbc"));

        // AES GMAC -- registered UNCONDITIONALLY, unlike the gated families:
        // EVP_MAC_fetch("GMAC") succeeds under fips=yes on BOTH supported
        // modules, and 3.1.2, 3.5.7 and mainline produce byte-identical tags
        // for identical inputs (fips-c-review/probes/gmac_probe.c Q1).
        //
        // The one place the two modules DISAGREE is Mac.clone(): 3.1.2 refuses
        // EVP_MAC_CTX_dup for GMAC ("not able to copy ctx") while serving the
        // MAC itself perfectly, and 3.5.7 allows it. The refusal is
        // GMAC-specific -- HMAC and CMAC dup fine on both. MacServiceSPI.clone
        // already reports a native copy failure as CloneNotSupportedException,
        // which is the JCE-correct answer, so nothing is gated here; see
        // FIPSMacTest for the contract test that pins both branches.
        provider.addAlgorithmImplementation("Mac", "AESGMAC", PREFIX + "MacServiceSPI$AESGMAC",
                generalAttributes, (arg) -> new MacServiceSPI(FIPSNISelector.MacServiceNI, "GMAC", "aes-gcm"));
        provider.addAlias("Mac", "AESGMAC", "AES-GMAC");
    }

    private void addMac(JostleFIPSProvider provider, String type, String name, String function)
    {
        String mainName = type + name;
        String className = PREFIX + "MacServiceSPI$" + mainName.replace("-", "_").replace("/", "_");
        provider.addAlgorithmImplementation("Mac", mainName, className, generalAttributes,
                (arg) -> new MacServiceSPI(FIPSNISelector.MacServiceNI, type, function));
        provider.addAlias("Mac", mainName, type + "-" + name, type + "/" + name);
    }
}
