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
 * digests, AES-CMAC, AES-GMAC and KMAC128/KMAC256. Deliberately absent:
 * Poly1305 and the HMACs over unapproved digests (MD5, MD5-SHA1, SM3,
 * RIPEMD-160). Names and aliases mirror ProvMac so approved MACs resolve
 * identically through either provider.
 */
class ProvFIPSMac
{
    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }


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
        provider.addAlgorithmImplementation("Mac", "AESCMAC", MacServiceSPI.class.getName(),
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
        provider.addAlgorithmImplementation("Mac", "AESGMAC", MacServiceSPI.class.getName(),
                generalAttributes, (arg) -> new MacServiceSPI(FIPSNISelector.MacServiceNI, "GMAC", "aes-gcm"));
        provider.addAlias("Mac", "AESGMAC", "AES-GMAC");

        addKmac(provider, "128");
        addKmac(provider, "256");
    }

    /**
     * KMAC128 / KMAC256 (NIST SP 800-185), registered UNCONDITIONALLY for the
     * same reason as AES-GMAC: {@code EVP_MAC_fetch} succeeds under
     * {@code fips=yes} on BOTH supported modules, and mainline 3.6.2, mainline
     * 3.5.7, FIPS 3.1.2 and FIPS 3.5.7 all produce byte-identical tags and all
     * match the SP 800-185 sample vectors
     * ({@code fips-c-review/probes/kmac_probe.c} Q1/Q13). Unlike GMAC, even
     * {@code EVP_MAC_CTX_dup} works on every one of them, so clone needs no
     * contract branch here.
     * <p>
     * Where the two modules DO disagree is on what they will accept, and both
     * differences are {@code fipsinstall} config rather than module version:
     * under {@code -pedantic} the {@code kmac-key-check} switch refuses keys
     * below 14 bytes (SP 800-131A's 112-bit floor) and {@code no-short-mac}
     * refuses outputs below 4 bytes, while a default-configured module accepts
     * keys from 4 bytes and outputs from 1. Neither bound is pre-checked in our
     * C — a hard-coded range would be wrong on whichever module it did not
     * match — so both surface as the module's own typed refusal. See
     * FIPSKMACTest for the probe-both-branches contract tests.
     * <p>
     * Approval status is not the registration filter (JSLFIPS serves what the
     * module serves). KMAC is an approved MAC under SP 800-185; the key-length
     * floor is a usage-scoped constraint the operator owns, and on a
     * {@code -pedantic} module the module enforces it directly.
     */
    private void addKmac(JostleFIPSProvider provider, String size)
    {
        String mainName = "KMAC" + size;
        String osslName = "KMAC-" + size;
        provider.addAlgorithmImplementation("Mac", mainName, MacServiceSPI.class.getName(),
                generalAttributes,
                (arg) -> new MacServiceSPI(FIPSNISelector.MacServiceNI, osslName, osslName));
        provider.addAlias("Mac", mainName, osslName);
        if ("128".equals(size))
        {
            provider.addAlias("Mac", mainName, "2.16.840.1.101.3.4.2.19", "2.16.840.1.101.3.4.2.21");
        }
        else
        {
            provider.addAlias("Mac", mainName, "2.16.840.1.101.3.4.2.20", "2.16.840.1.101.3.4.2.22");
        }
    }

    private void addMac(JostleFIPSProvider provider, String type, String name, String function)
    {
        String mainName = type + name;
        String className = MacServiceSPI.class.getName();
        provider.addAlgorithmImplementation("Mac", mainName, className, generalAttributes,
                (arg) -> new MacServiceSPI(FIPSNISelector.MacServiceNI, type, function));
        provider.addAlias("Mac", mainName, type + "-" + name, type + "/" + name);
    }
}
