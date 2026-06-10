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

import org.openssl.jostle.jcajce.provider.kdf.HKDFSecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

class ProvHKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvHKDF.class.getName();

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF-SHA256", PREFIX + "SHA256", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF-SHA384", PREFIX + "SHA384", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF-SHA512", PREFIX + "SHA512", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-512"));
    }
}
