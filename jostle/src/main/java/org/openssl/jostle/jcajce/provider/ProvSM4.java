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
import org.openssl.jostle.jcajce.provider.blockcipher.SM4BlockCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.SymmetricKeyGenerator;
import org.openssl.jostle.jcajce.provider.blockcipher.SM4CCMCipherSpi;

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

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "SM4", SM4BlockCipherSpi.class.getName(), generalAttributes, (arg) -> new SM4BlockCipherSpi(provider));

        // KeyGenerator for the bare name, matching BouncyCastle, which serves
        // SM4 with a 128-bit default. Without it a caller must build a
        // SecretKeySpec by hand to use a cipher this provider serves.
        provider.addAlgorithmImplementation("KeyGenerator", "SM4",
                SymmetricKeyGenerator.class.getName(), generalAttributes,
                (arg) -> new SymmetricKeyGenerator("SM4", 128, 128));

        // SM4/CCM — see ProvAES note on the dedicated CCM SPI.
        provider.addAlgorithmImplementation("Cipher", "SM4/CCM/NoPadding",
                SM4CCMCipherSpi.class.getName(), generalAttributes, (arg) -> new SM4CCMCipherSpi());

        // IV AlgorithmParameters under the bare family name — SM4 had NONE
        // before MT-18, so getParameters() threw IllegalStateException.
        provider.addAlgorithmImplementation("AlgorithmParameters", "SM4",
                IvAlgorithmParameters.class.getName(), generalAttributes, (arg) -> new IvAlgorithmParameters());
    }
}
