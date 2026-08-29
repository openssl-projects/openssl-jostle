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
import org.openssl.jostle.jcajce.provider.blockcipher.ARIABlockCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.ARIACCMCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.util.asn1.oids.NSRIObjectIdentifiers;

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

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "ARIA", ARIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new ARIABlockCipherSpi(provider));

        provider.addAlgorithmImplementation("Cipher", "ARIA128", ARIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA128, OSSLMode.ECB, provider));
        provider.addAlias("Cipher", "ARIA128", NSRIObjectIdentifiers.id_aria128_ecb);
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria128_cbc, ARIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA128, OSSLMode.CBC, provider));

        provider.addAlgorithmImplementation("Cipher", "ARIA192", ARIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA192, OSSLMode.ECB, provider));
        provider.addAlias("Cipher", "ARIA192", NSRIObjectIdentifiers.id_aria192_ecb);
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria192_cbc, ARIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA192, OSSLMode.CBC, provider));

        provider.addAlgorithmImplementation("Cipher", "ARIA256", ARIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA256, OSSLMode.ECB, provider));
        provider.addAlias("Cipher", "ARIA256", NSRIObjectIdentifiers.id_aria256_ecb);
        provider.addAlgorithmImplementation("Cipher", NSRIObjectIdentifiers.id_aria256_cbc, ARIABlockCipherSpi.class.getName(), generalAttributes, (arg) -> new ARIABlockCipherSpi(OSSLCipher.ARIA256, OSSLMode.CBC, provider));

        // ARIA/CCM — see ProvAES note on the dedicated CCM SPI.
        provider.addAlgorithmImplementation("Cipher", "ARIA/CCM/NoPadding",
                ARIACCMCipherSpi.class.getName(), generalAttributes, (arg) -> new ARIACCMCipherSpi());

        // IV AlgorithmParameters under the bare family name — ARIA had NONE
        // before MT-18, so getParameters() threw IllegalStateException.
        provider.addAlgorithmImplementation("AlgorithmParameters", "ARIA",
                IvAlgorithmParameters.class.getName(), generalAttributes, (arg) -> new IvAlgorithmParameters());
    }
}
