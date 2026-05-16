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


import org.openssl.jostle.jcajce.provider.blockcipher.AESBlockCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.AESKeyGenerator;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;

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

        //
        // AES-KW (RFC 3394) and AES-KWP (RFC 5649). Key-size-agnostic
        // bare aliases plus key-size-specific variants and per-RFC OIDs.
        // The bare "AESWrap" / "AESWrapPad" detect the key size from
        // the supplied key (see AESBlockCipherSpi.determineOSSLCipher);
        // the *_128 / *_192 / *_256 variants pin the cipher so a wrongly
        // sized key fails fast at init time.
        //
        provider.addAlgorithmImplementation("Cipher", "AESWrap", PREFIX + "AESWrap", generalAesAttributes, (arg) -> new AESBlockCipherSpi(null, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", "AESWrap_128", PREFIX + "AESWrap128", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", "AESWrap_192", PREFIX + "AESWrap192", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", "AESWrap_256", PREFIX + "AESWrap256", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap, PREFIX + "AESWrap128OID", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap, PREFIX + "AESWrap192OID", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap, PREFIX + "AESWrap256OID", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.WRAP));

        provider.addAlgorithmImplementation("Cipher", "AESWrapPad", PREFIX + "AESWrapPad", generalAesAttributes, (arg) -> new AESBlockCipherSpi(null, OSSLMode.WRAP_PAD));
        provider.addAlgorithmImplementation("Cipher", "AESWrapPad_128", PREFIX + "AESWrapPad128", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.WRAP_PAD));
        provider.addAlgorithmImplementation("Cipher", "AESWrapPad_192", PREFIX + "AESWrapPad192", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.WRAP_PAD));
        provider.addAlgorithmImplementation("Cipher", "AESWrapPad_256", PREFIX + "AESWrapPad256", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.WRAP_PAD));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap_pad, PREFIX + "AESWrapPad128OID", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.WRAP_PAD));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap_pad, PREFIX + "AESWrapPad192OID", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.WRAP_PAD));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap_pad, PREFIX + "AESWrapPad256OID", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.WRAP_PAD));

    }
}
