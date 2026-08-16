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

import org.openssl.jostle.jcajce.provider.kdf.Argon2SecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Argon2 (RFC 9106) registration for the non-FIPS provider.
 *
 * <p>One {@code ARGON2} SecretKeyFactory serves all three variants — the type
 * and version travel in {@code Argon2KeySpec}, matching BouncyCastle's
 * registration so specs and call sites are interchangeable between the two
 * providers. No OID aliases: the Argon2 OIDs under the PKCS#5 arc are not
 * assigned to a KDF the way scrypt's 1.3.6.1.4.1.11591.4.11 is.</p>
 *
 * <p>There is deliberately no ProvFIPS counterpart: Argon2 is not an approved
 * service of the validated module, and the FIPS lib ctx cannot fetch it.</p>
 */
class ProvArgon2KDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    private static final String PREFIX = ProvArgon2KDF.class.getName();

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "ARGON2", PREFIX + "Argon2",
                generalKDFAttributes, (arg) -> new Argon2SecretKeyFactory());
    }
}
