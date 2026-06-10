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


import org.openssl.jostle.jcajce.provider.blockcipher.*;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

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

        // NIST AES OIDs are registered so that consumers which resolve algorithms by OID
        // (notably CMS, which looks up the content-encryption and key-wrap KeyGenerator
        // and Cipher by their algorithm OID) find the JSL implementations. ECB/CBC/GCM
        // and key-wrap (RFC 3394) / key-wrap-with-padding (RFC 5649) are all wired
        // through to OpenSSL.

        provider.addAlgorithmImplementation("Cipher", "AES128", PREFIX + "AES128", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.ECB));
        provider.addAlias("Cipher", "AES128", NISTObjectIdentifiers.id_aes128_ECB);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "AES128CBC", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.CBC));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_GCM, PREFIX + "AES128GCM", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.GCM));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap, PREFIX + "AES128WRAP", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap_pad, PREFIX + "AES128WRAPPAD", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.WRAP_PAD));
        provider.addAlgorithmImplementation("KeyGenerator", "AES128", PREFIX + "AESKeyGen128", generalAesAttributes, (arg) -> new AESKeyGenerator(128));
        provider.addAlias("KeyGenerator", "AES128", NISTObjectIdentifiers.id_aes128_ECB, NISTObjectIdentifiers.id_aes128_CBC, NISTObjectIdentifiers.id_aes128_GCM, NISTObjectIdentifiers.id_aes128_wrap, NISTObjectIdentifiers.id_aes128_wrap_pad);

        provider.addAlgorithmImplementation("Cipher", "AES192", PREFIX + "AES192", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.ECB));
        provider.addAlias("Cipher", "AES192", NISTObjectIdentifiers.id_aes192_ECB);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "AES192CBC", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.CBC));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_GCM, PREFIX + "AES192GCM", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.GCM));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap, PREFIX + "AES192WRAP", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap_pad, PREFIX + "AES192WRAPPAD", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.WRAP_PAD));
        provider.addAlgorithmImplementation("KeyGenerator", "AES192", PREFIX + "AESKeyGen192", generalAesAttributes, (arg) -> new AESKeyGenerator(192));
        provider.addAlias("KeyGenerator", "AES192", NISTObjectIdentifiers.id_aes192_ECB, NISTObjectIdentifiers.id_aes192_CBC, NISTObjectIdentifiers.id_aes192_GCM, NISTObjectIdentifiers.id_aes192_wrap, NISTObjectIdentifiers.id_aes192_wrap_pad);

        provider.addAlgorithmImplementation("Cipher", "AES256", PREFIX + "AES256", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.ECB));
        provider.addAlias("Cipher", "AES256", NISTObjectIdentifiers.id_aes256_ECB);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "AES256CBC", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.CBC));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_GCM, PREFIX + "AES256GCM", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.GCM));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap, PREFIX + "AES256WRAP", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap_pad, PREFIX + "AES256WRAPPAD", generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.WRAP_PAD));
        provider.addAlgorithmImplementation("KeyGenerator", "AES256", PREFIX + "AESKeyGen256", generalAesAttributes, (arg) -> new AESKeyGenerator(256));
        provider.addAlias("KeyGenerator", "AES256", NISTObjectIdentifiers.id_aes256_ECB, NISTObjectIdentifiers.id_aes256_CBC, NISTObjectIdentifiers.id_aes256_GCM, NISTObjectIdentifiers.id_aes256_wrap, NISTObjectIdentifiers.id_aes256_wrap_pad);

        // AES-GCM AlgorithmParameters, registered under the bare name "GCM" and
        // the GCM OIDs (see GCMAlgorithmParameters). Lets OID-driven callers —
        // notably CMS EnvelopedData decryption — parse the stored GCMParameters
        // (nonce/ICV) via AlgorithmParameters.getInstance(<aes-gcm-oid>, "JSL"),
        // and name-driven callers resolve it via getInstance("GCM", "JSL"). The
        // delegate is resolved from a non-Jostle provider so the bare name can't
        // recurse.
        provider.addAlgorithmImplementation("AlgorithmParameters", "GCM", PREFIX + "GCMParameters", generalAesAttributes, (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_GCM, PREFIX + "AES128GCMParameters", generalAesAttributes, (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_GCM, PREFIX + "AES192GCMParameters", generalAesAttributes, (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_GCM, PREFIX + "AES256GCMParameters", generalAesAttributes, (arg) -> new GCMAlgorithmParameters());

        // AES-CCM AlgorithmParameters, registered under the bare name "CCM" and
        // the CCM OIDs (see CCMAlgorithmParameters). No JDK provider ships a CCM
        // AlgorithmParameters, so this one is self-contained (RFC 5084 codec).
        provider.addAlgorithmImplementation("AlgorithmParameters", "CCM", PREFIX + "CCMParameters", generalAesAttributes, (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_CCM, PREFIX + "AES128CCMParameters", generalAesAttributes, (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_CCM, PREFIX + "AES192CCMParameters", generalAesAttributes, (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_CCM, PREFIX + "AES256CCMParameters", generalAesAttributes, (arg) -> new CCMAlgorithmParameters());

        // AES-CBC AlgorithmParameters, registered under the CBC OIDs only (see
        // CBCAlgorithmParameters). Lets OID-driven callers — notably BC's PBES2 /
        // PKCS#8 / PKCS#12 decryptors — recover the stored IV via
        // AlgorithmParameters.getInstance(<aes-cbc-oid>, "JSL").
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "AES128CBCParameters", generalAesAttributes, (arg) -> new CBCAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "AES192CBCParameters", generalAesAttributes, (arg) -> new CBCAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "AES256CBCParameters", generalAesAttributes, (arg) -> new CBCAlgorithmParameters());

        // AES/CCM — separate SPI because CCM is one-shot at the
        // OpenSSL layer (total plaintext length must be known up-front,
        // AAD must be passed in a single call). Registering with the
        // explicit "AES/CCM/NoPadding" form so JCE Cipher.getInstance
        // resolves directly to AESCCMCipherSpi rather than the generic
        // BlockCipherSpi.
        provider.addAlgorithmImplementation("Cipher", "AES/CCM/NoPadding",
                PREFIX + "AESCCM", generalAesAttributes, (arg) -> new AESCCMCipherSpi());

    }
}
