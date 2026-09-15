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

import org.openssl.jostle.jcajce.provider.bcfks.BcFKSKeyStoreSpi;

import java.util.HashMap;
import java.util.Map;

/**
 * BCFKS keystore, registered on the FIPS provider too, generally available
 * even when no FIPS module is loaded — BCFKS needs only PBKDF2, HMAC,
 * AES-CCM/KWP, X.509 and KeyFactory, all of which JostleFIPSProvider already
 * serves. Also answers to FIPS/FIPS-DEF, matching BouncyCastle's own naming.
 * Read path only. Write support is not implemented yet.
 */
class ProvFIPSBCFKS
{
    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();

        // MemoryHardKdfNI is null: the FIPS module has no scrypt, so a store
        // whose KDF is id-scrypt is refused typed rather than routed into
        // the base library (see BcFKSKeyStoreSpi's constructor javadoc).
        provider.addAlgorithmImplementation("KeyStore", "BCFKS", BcFKSKeyStoreSpi.class.getName(), attr,
                (arg) -> new BcFKSKeyStoreSpi(provider, FIPSNISelector.KdfNI, null, FIPSNISelector.Asn1NI,
                        FIPSNISelector.SpecNI));
        provider.addAlias("KeyStore", "BCFKS", "FIPS", "FIPS-DEF", "BCFKS-DEF");
    }
}
