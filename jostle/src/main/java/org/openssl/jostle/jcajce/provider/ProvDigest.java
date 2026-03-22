/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.jcajce.provider.digest.SHA256Spi;
import org.openssl.jostle.jcajce.provider.digest.SHA384Spi;
import org.openssl.jostle.jcajce.provider.digest.SHA512Spi;
import org.openssl.jostle.jcajce.provider.digest.SHA3_224Spi;
import org.openssl.jostle.jcajce.provider.digest.SHA3_256Spi;
import org.openssl.jostle.jcajce.provider.digest.SHA3_384Spi;
import org.openssl.jostle.jcajce.provider.digest.SHA3_512Spi;
import org.openssl.jostle.jcajce.provider.digest.MD5Spi;

import java.util.HashMap;
import java.util.Map;

class ProvDigest implements NISTObjectIdentifiers
{
    private static final Map<String, String> generalAttributes = new HashMap<>();

    static
    {
        generalAttributes.put("ImplementedIn", "Software");
    }

    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.digest.";

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation(
                "MessageDigest",
                "SHA-256",
                PREFIX + "SHA256Spi",
                generalAttributes,
                (arg) -> new SHA256Spi()
        );

        provider.addAlias("MessageDigest", "SHA-256", id_sha256);
        provider.addAlias("MessageDigest", "SHA-256", "SHA256");

        provider.addAlgorithmImplementation(
                "MessageDigest",
                "SHA-384",
                PREFIX + "SHA384Spi",
                generalAttributes,
                (arg) -> new SHA384Spi()
        );

        provider.addAlias("MessageDigest", "SHA-384", id_sha384);
        provider.addAlias("MessageDigest", "SHA-384", "SHA384");

        provider.addAlgorithmImplementation(
                "MessageDigest",
                "SHA-512",
                PREFIX + "SHA512Spi",
                generalAttributes,
                (arg) -> new SHA512Spi()
        );

        provider.addAlias("MessageDigest", "SHA-512", id_sha512);
        provider.addAlias("MessageDigest", "SHA-512", "SHA512");

        // MD5 (non-cryptographic; provided for compatibility/testing only)
        provider.addAlgorithmImplementation(
                "MessageDigest",
                "MD5",
                PREFIX + "MD5Spi",
                generalAttributes,
                (arg) -> new MD5Spi()
        );
        // No MD5 OID alias added; available by name only.

        // SHA3 family
        provider.addAlgorithmImplementation(
                "MessageDigest",
                "SHA3-224",
                PREFIX + "SHA3_224Spi",
                generalAttributes,
                (arg) -> new SHA3_224Spi()
        );
        provider.addAlias("MessageDigest", "SHA3-224", id_sha3_224);

        provider.addAlgorithmImplementation(
                "MessageDigest",
                "SHA3-256",
                PREFIX + "SHA3_256Spi",
                generalAttributes,
                (arg) -> new SHA3_256Spi()
        );
        provider.addAlias("MessageDigest", "SHA3-256", id_sha3_256);

        provider.addAlgorithmImplementation(
                "MessageDigest",
                "SHA3-384",
                PREFIX + "SHA3_384Spi",
                generalAttributes,
                (arg) -> new SHA3_384Spi()
        );
        provider.addAlias("MessageDigest", "SHA3-384", id_sha3_384);

        provider.addAlgorithmImplementation(
                "MessageDigest",
                "SHA3-512",
                PREFIX + "SHA3_512Spi",
                generalAttributes,
                (arg) -> new SHA3_512Spi()
        );
        provider.addAlias("MessageDigest", "SHA3-512", id_sha3_512);
    }
}
