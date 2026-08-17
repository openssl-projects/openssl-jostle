/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.blockcipher.AESBlockCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.AESKeyGenerator;
import org.openssl.jostle.jcajce.provider.blockcipher.AESCCMCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.CBCAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.blockcipher.CCMAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.blockcipher.GCMAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

/**
 * AES registrations for the FIPS provider, mirroring ProvAES's Cipher and
 * AlgorithmParameters surface (names, OIDs) bound to the FIPS interface
 * library. AES is fips=yes across the module's registered modes; unapproved
 * mode requests through the bare "AES" primary (engineSetMode) fail at the
 * native fetch under the lib ctx's fips=yes default properties.
 *
 * <p>KeyGenerator key bytes are drawn from the module's own approved DRBG
 * (the provider's DEFAULT SecureRandom service) rather than a JDK
 * SecureRandom.
 */
class ProvFIPSAES
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.ProvAES";

    private static final Map<String, String> generalAesAttributes = new HashMap<String, String>();

    static
    {
        generalAesAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAesAttributes.put("SupportedKeyFormats", "RAW");
    }

    public void configure(final JostleFIPSProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "AES", PREFIX + "Base", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI));
        provider.addAlgorithmImplementation("KeyGenerator", "AES", PREFIX + "AES", generalAesAttributes,
                (arg) -> new AESKeyGenerator(provider.getDefaultSecureRandom()));


        provider.addAlgorithmImplementation("Cipher", "AESWrap", PREFIX + "AESWRAPNAME", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, null, OSSLMode.WRAP));
        provider.addAlias("Cipher", "AESWrap", "AESKW");
        provider.addAlgorithmImplementation("Cipher", "AESWrapPad", PREFIX + "AESWRAPPADNAME", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, null, OSSLMode.WRAP_PAD));
        provider.addAlias("Cipher", "AESWrapPad", "AESKWP");

        provider.addAlgorithmImplementation("Cipher", "AES128", PREFIX + "AES128", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.ECB));
        provider.addAlias("Cipher", "AES128", NISTObjectIdentifiers.id_aes128_ECB);
        provider.addAlgorithmImplementation("KeyGenerator", "AES128", PREFIX + "AESKeyGen128", generalAesAttributes,
                (arg) -> new AESKeyGenerator(128, provider.getDefaultSecureRandom()));
        provider.addAlias("KeyGenerator", "AES128", NISTObjectIdentifiers.id_aes128_ECB, NISTObjectIdentifiers.id_aes128_CBC, NISTObjectIdentifiers.id_aes128_GCM, NISTObjectIdentifiers.id_aes128_wrap, NISTObjectIdentifiers.id_aes128_wrap_pad);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "AES128CBC", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.CBC));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_GCM, PREFIX + "AES128GCM", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.GCM));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap, PREFIX + "AES128WRAP", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap_pad, PREFIX + "AES128WRAPPAD", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.WRAP_PAD));

        provider.addAlgorithmImplementation("Cipher", "AES192", PREFIX + "AES192", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.ECB));
        provider.addAlias("Cipher", "AES192", NISTObjectIdentifiers.id_aes192_ECB);
        provider.addAlgorithmImplementation("KeyGenerator", "AES192", PREFIX + "AESKeyGen192", generalAesAttributes,
                (arg) -> new AESKeyGenerator(192, provider.getDefaultSecureRandom()));
        provider.addAlias("KeyGenerator", "AES192", NISTObjectIdentifiers.id_aes192_ECB, NISTObjectIdentifiers.id_aes192_CBC, NISTObjectIdentifiers.id_aes192_GCM, NISTObjectIdentifiers.id_aes192_wrap, NISTObjectIdentifiers.id_aes192_wrap_pad);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "AES192CBC", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.CBC));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_GCM, PREFIX + "AES192GCM", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.GCM));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap, PREFIX + "AES192WRAP", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap_pad, PREFIX + "AES192WRAPPAD", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.WRAP_PAD));

        provider.addAlgorithmImplementation("Cipher", "AES256", PREFIX + "AES256", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.ECB));
        provider.addAlias("Cipher", "AES256", NISTObjectIdentifiers.id_aes256_ECB);
        provider.addAlgorithmImplementation("KeyGenerator", "AES256", PREFIX + "AESKeyGen256", generalAesAttributes,
                (arg) -> new AESKeyGenerator(256, provider.getDefaultSecureRandom()));
        provider.addAlias("KeyGenerator", "AES256", NISTObjectIdentifiers.id_aes256_ECB, NISTObjectIdentifiers.id_aes256_CBC, NISTObjectIdentifiers.id_aes256_GCM, NISTObjectIdentifiers.id_aes256_wrap, NISTObjectIdentifiers.id_aes256_wrap_pad);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "AES256CBC", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.CBC));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_GCM, PREFIX + "AES256GCM", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.GCM));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap, PREFIX + "AES256WRAP", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.WRAP));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap_pad, PREFIX + "AES256WRAPPAD", generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.WRAP_PAD));

        provider.addAlgorithmImplementation("Cipher", "AES/CCM/NoPadding", PREFIX + "AESCCM", generalAesAttributes,
                (arg) -> new AESCCMCipherSpi(FIPSNISelector.CCMCipherNI));

        //
        // AlgorithmParameters are pure-Java ASN.1 encodings - no NI binding.
        //
        provider.addAlgorithmImplementation("AlgorithmParameters", "GCM", PREFIX + "GCMParameters", generalAesAttributes,
                (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_GCM, PREFIX + "AES128GCMParameters", generalAesAttributes,
                (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_GCM, PREFIX + "AES192GCMParameters", generalAesAttributes,
                (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_GCM, PREFIX + "AES256GCMParameters", generalAesAttributes,
                (arg) -> new GCMAlgorithmParameters());

        provider.addAlgorithmImplementation("AlgorithmParameters", "CCM", PREFIX + "CCMParameters", generalAesAttributes,
                (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_CCM, PREFIX + "AES128CCMParameters", generalAesAttributes,
                (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_CCM, PREFIX + "AES192CCMParameters", generalAesAttributes,
                (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_CCM, PREFIX + "AES256CCMParameters", generalAesAttributes,
                (arg) -> new CCMAlgorithmParameters());

        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "AES128CBCParameters", generalAesAttributes,
                (arg) -> new CBCAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "AES192CBCParameters", generalAesAttributes,
                (arg) -> new CBCAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "AES256CBCParameters", generalAesAttributes,
                (arg) -> new CBCAlgorithmParameters());
    }
}
