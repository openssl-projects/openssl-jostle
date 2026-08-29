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

import org.openssl.jostle.jcajce.provider.kdf.SSKDFSecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * SP 800-56C one-step KDF registrations, digest form only. Naming follows the
 * {@code HKDF-SHA256} precedent.
 */
class ProvSSKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }


    public void configure(final JostleProvider provider)
    {
        add(provider, "SHA1", "SHA-1");
        add(provider, "SHA224", "SHA-224");
        add(provider, "SHA256", "SHA-256");
        add(provider, "SHA384", "SHA-384");
        add(provider, "SHA512", "SHA-512");
    }

    private static void add(JostleProvider provider, String suffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "SSKDF-" + suffix,
                SSKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new SSKDFSecretKeyFactory(digest));
    }
}
