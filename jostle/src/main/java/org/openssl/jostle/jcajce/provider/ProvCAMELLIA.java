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

import org.openssl.jostle.jcajce.provider.blockcipher.IvAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.blockcipher.CAMELLIABlockCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.util.asn1.oids.NTTObjectIdentifiers;

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

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "CAMELLIA", CAMELLIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(provider));
        provider.addAlgorithmImplementation("Cipher", "CAMELLIA128", CAMELLIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA128, OSSLMode.ECB, provider));
        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia128_cbc, CAMELLIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA128, OSSLMode.CBC, provider));

        provider.addAlgorithmImplementation("Cipher", "CAMELLIA192", CAMELLIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA192, OSSLMode.ECB, provider));
        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia192_cbc, CAMELLIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA192, OSSLMode.CBC, provider));

        provider.addAlgorithmImplementation("Cipher", "CAMELLIA256", CAMELLIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA256, OSSLMode.ECB, provider));

        provider.addAlgorithmImplementation("Cipher", NTTObjectIdentifiers.id_camellia256_cbc, CAMELLIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new CAMELLIABlockCipherSpi(OSSLCipher.CAMELLIA256, OSSLMode.CBC, provider));

        // IV AlgorithmParameters under the bare family name — CAMELLIA had NONE
        // before MT-18, so getParameters() threw IllegalStateException.
        provider.addAlgorithmImplementation("AlgorithmParameters", "CAMELLIA",
                IvAlgorithmParameters.class.getName(), generalAttributes, (arg) -> new IvAlgorithmParameters());
    }
}
