/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider;

import java.util.HashMap;
import java.util.Map;

class ProvSM4
{
    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvSM4.class.getName();

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "SM4", PREFIX + "Base", generalAttributes, (arg) -> new SM4BlockCipherSpi());


    }
}
