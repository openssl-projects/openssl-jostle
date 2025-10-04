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

import java.util.HashMap;
import java.util.Map;

class ProvARIA
{
    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvARIA.class.getName();

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "ARIA", PREFIX + "Base", generalAttributes, (arg) -> new ARIABlockCipherSpi());

        provider.addAlgorithmImplementation("Cipher", "ARIA128", PREFIX + "ARIA128", generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA128, OSSLMode.ECB));
        provider.addAlias("Cipher", "ARIA128", NSRIObjectIdentifiers.id_aria128_ecb    );
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_cbc, PREFIX + "ARIA128CBC", generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA128, OSSLMode.ECB));

        provider.addAlgorithmImplementation("Cipher", "ARIA192", PREFIX + "ARIA192", generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.AES192, OSSLMode.ECB));
        provider.addAlias("Cipher", "ARIA192", NSRIObjectIdentifiers.id_aria192_ecb );
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_cbc, PREFIX + "ARIA192CBC", generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA192, OSSLMode.CBC));

        provider.addAlgorithmImplementation("Cipher", "ARIA256", PREFIX + "ARIA256", generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA256, OSSLMode.ECB));
        provider.addAlias("Cipher", "ARIA256", NSRIObjectIdentifiers.id_aria256_ecb);
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_cbc, PREFIX + "ARIA256CBC", generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA256, OSSLMode.CBC));
    }
}
