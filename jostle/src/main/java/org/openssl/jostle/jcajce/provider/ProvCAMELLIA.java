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

class ProvCAMELLIA
{
    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvCAMELLIA.class.getName();

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "CAMELLIA", PREFIX + "Base", generalAttributes, (arg) -> new CAMELLIABlockCipherSpi());
        provider.addAlgorithmImplementation("Cipher", "CAMELLIA128", PREFIX + "CAMELLIA128", generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA128, OSSLMode.ECB));
        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia128_cbc, PREFIX + "CAMELLIA128CBC", generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA128, OSSLMode.ECB));

        provider.addAlgorithmImplementation("Cipher", "CAMELLIA192", PREFIX + "CAMELLIA192", generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA192, OSSLMode.ECB));
        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia192_cbc, PREFIX + "CAMELLIA192CBC", generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA192, OSSLMode.CBC));

        provider.addAlgorithmImplementation("Cipher", "CAMELLIA256", PREFIX + "CAMELLIA256", generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA256, OSSLMode.ECB));

        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia256_cbc, PREFIX + "CAMELLIA256CBC", generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA256, OSSLMode.CBC));
    }
}
