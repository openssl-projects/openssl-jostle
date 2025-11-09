/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.jcajce.provider.kdf.ScryptSecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

class ProvScryptKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();


    private static final String PREFIX = ProvScryptKDF.class.getName();

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "SCRYPT", PREFIX + "Scrypt", generalKDFAttributes, (arg) -> new ScryptSecretKeyFactory());
        provider.addAlgorithmImplementation("SecretKeyFactory", "1.3.6.1.4.1.11591.4.11", PREFIX + "ScryptOid", generalKDFAttributes, (arg) -> new ScryptSecretKeyFactory());

    }
}
