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

class ProvAES
{
    private static final Map<String, String> generalAesAttributes = new HashMap<String, String>();

    static
    {
        generalAesAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAesAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvAES.class.getName();

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "AES", PREFIX + "Base", generalAesAttributes, (arg) -> new AESBlockCipherSpi());
        provider.addAlgorithmImplementation("KeyGenerator", "AES", PREFIX + "AES", generalAesAttributes, (arg) -> new AESKeyGenerator());

        provider.addAlgorithmImplementation("Cipher", "AES128", PREFIX + "AES128", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.ECB));
        provider.addAlias("Cipher", "AES128", NISTObjectIdentifiers.id_aes128_ECB);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "AES128CBC", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.ECB));
        provider.addAlgorithmImplementation("KeyGenerator", "AES128", PREFIX + "AESKeyGen128", generalAesAttributes, (arg) -> new AESKeyGenerator(128));

        provider.addAlgorithmImplementation("Cipher", "AES192", PREFIX + "AES192", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.ECB));
        provider.addAlias("Cipher", "AES192", NISTObjectIdentifiers.id_aes192_ECB);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "AES192CBC", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.CBC));
        provider.addAlgorithmImplementation("KeyGenerator", "AES192", PREFIX + "AESKeyGen192", generalAesAttributes, (arg) -> new AESKeyGenerator(192));

        provider.addAlgorithmImplementation("Cipher", "AES256", PREFIX + "AES256", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.ECB));
        provider.addAlias("Cipher", "AES256", NISTObjectIdentifiers.id_aes256_ECB);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "AES256CBC", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.CBC));
        provider.addAlgorithmImplementation("KeyGenerator", "AES256", PREFIX + "AESKeyGen256", generalAesAttributes, (arg) -> new AESKeyGenerator(256));

    }
}
