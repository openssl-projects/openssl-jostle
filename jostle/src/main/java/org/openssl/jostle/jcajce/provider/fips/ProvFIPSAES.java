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

import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.blockcipher.IvAlgorithmParameters;
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

    private static final Map<String, String> generalAesAttributes = new HashMap<String, String>();

    static
    {
        generalAesAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAesAttributes.put("SupportedKeyFormats", "RAW");
    }

    /**
     * {@link JostleProvider#KEY_WRAP_ATTRIBUTE} on top of the general set —
     * the registration-site declaration of wrap-ness that
     * {@code CipherSurfaceDriver}'s cross-check reads.
     */
    private static final Map<String, String> wrapAesAttributes = new HashMap<String, String>();

    static
    {
        wrapAesAttributes.putAll(generalAesAttributes);
        wrapAesAttributes.put(JostleProvider.KEY_WRAP_ATTRIBUTE, "true");
    }

    public void configure(final JostleFIPSProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "AES", AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, provider));
        provider.addAlgorithmImplementation("KeyGenerator", "AES", AESKeyGenerator.class.getName(), generalAesAttributes,
                (arg) -> new AESKeyGenerator(provider.getDefaultSecureRandom()));


        provider.addAlgorithmImplementation("Cipher", "AESWrap", AESBlockCipherSpi.class.getName(), wrapAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, null, OSSLMode.WRAP, provider));
        provider.addAlias("Cipher", "AESWrap", "AESKW");
        provider.addAlgorithmImplementation("Cipher", "AESWrapPad", AESBlockCipherSpi.class.getName(), wrapAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, null, OSSLMode.WRAP_PAD, provider));
        provider.addAlias("Cipher", "AESWrapPad", "AESKWP");

        // AES key wrap on the INVERSE cipher function (SP 800-38F 5.1).
        // Ungated: measured fetchable at all three widths under fips=yes on
        // BOTH modules, default and -pedantic alike
        // (fips-c-review/probes/wrapinv_probe.c). See ProvAES for why the
        // name is Jostle-chosen, and for the aliases.
        //
        // Approval is NOT asserted, and here the policy does not settle it.
        // Checked against CMVP cert #4985 on 2026-08-26: SP 800-38F 5.1
        // permits the AES decryption function as the designated cipher
        // function, so the variant is within the standard; the certificate's
        // row reads "AES-KW  A3548  Direction - Decrypt, Encrypt / Key
        // Length - 128, 192, 256 / SP 800-38F" and records NOTHING about the
        // cipher function (the CAVP kwCipher property is absent); and neither
        // Table 8 nor Table 13 excludes the inverse form. Genuinely
        // ambiguous, deliberately left so - an operator needing the answer
        // should take it to the module owner. Registration is unchanged
        // either way: JSLFIPS serves what the module serves.
        provider.addAlgorithmImplementation("Cipher", "AESWrapInv", AESBlockCipherSpi.class.getName(), wrapAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, null, OSSLMode.WRAP_INV, provider));
        provider.addAlias("Cipher", "AESWrapInv", "AESKWINV");

        provider.addAlgorithmImplementation("Cipher", "AES128", AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.ECB, provider));
        provider.addAlias("Cipher", "AES128", NISTObjectIdentifiers.id_aes128_ECB);
        provider.addAlgorithmImplementation("KeyGenerator", "AES128", AESKeyGenerator.class.getName(), generalAesAttributes,
                (arg) -> new AESKeyGenerator(128, provider.getDefaultSecureRandom()));
        provider.addAlias("KeyGenerator", "AES128", NISTObjectIdentifiers.id_aes128_ECB, NISTObjectIdentifiers.id_aes128_CBC, NISTObjectIdentifiers.id_aes128_GCM, NISTObjectIdentifiers.id_aes128_wrap, NISTObjectIdentifiers.id_aes128_wrap_pad);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_CBC, AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.CBC, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_GCM, AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.GCM, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap, AESBlockCipherSpi.class.getName(), wrapAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.WRAP, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap_pad, AESBlockCipherSpi.class.getName(), wrapAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES128, OSSLMode.WRAP_PAD, provider));

        provider.addAlgorithmImplementation("Cipher", "AES192", AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.ECB, provider));
        provider.addAlias("Cipher", "AES192", NISTObjectIdentifiers.id_aes192_ECB);
        provider.addAlgorithmImplementation("KeyGenerator", "AES192", AESKeyGenerator.class.getName(), generalAesAttributes,
                (arg) -> new AESKeyGenerator(192, provider.getDefaultSecureRandom()));
        provider.addAlias("KeyGenerator", "AES192", NISTObjectIdentifiers.id_aes192_ECB, NISTObjectIdentifiers.id_aes192_CBC, NISTObjectIdentifiers.id_aes192_GCM, NISTObjectIdentifiers.id_aes192_wrap, NISTObjectIdentifiers.id_aes192_wrap_pad);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_CBC, AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.CBC, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_GCM, AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.GCM, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap, AESBlockCipherSpi.class.getName(), wrapAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.WRAP, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap_pad, AESBlockCipherSpi.class.getName(), wrapAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES192, OSSLMode.WRAP_PAD, provider));

        provider.addAlgorithmImplementation("Cipher", "AES256", AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.ECB, provider));
        provider.addAlias("Cipher", "AES256", NISTObjectIdentifiers.id_aes256_ECB);
        provider.addAlgorithmImplementation("KeyGenerator", "AES256", AESKeyGenerator.class.getName(), generalAesAttributes,
                (arg) -> new AESKeyGenerator(256, provider.getDefaultSecureRandom()));
        provider.addAlias("KeyGenerator", "AES256", NISTObjectIdentifiers.id_aes256_ECB, NISTObjectIdentifiers.id_aes256_CBC, NISTObjectIdentifiers.id_aes256_GCM, NISTObjectIdentifiers.id_aes256_wrap, NISTObjectIdentifiers.id_aes256_wrap_pad);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_CBC, AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.CBC, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_GCM, AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.GCM, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap, AESBlockCipherSpi.class.getName(), wrapAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.WRAP, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap_pad, AESBlockCipherSpi.class.getName(), wrapAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, OSSLCipher.AES256, OSSLMode.WRAP_PAD, provider));

        provider.addAlgorithmImplementation("Cipher", "AES/CCM/NoPadding", AESCCMCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESCCMCipherSpi(FIPSNISelector.CCMCipherNI));

        // XTS-AES (IEEE 1619 / SP 800-38E). Ungated: probed servable, with
        // identical behaviour, on both supported FIPS modules (3.1.2 and
        // 3.5.8) at their default and -pedantic fipsinstall configurations.
        // See the base ProvAES registration for why there are no per-key-size
        // variants.
        provider.addAlgorithmImplementation("Cipher", "AES/XTS/NoPadding", AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, null, OSSLMode.XTS, provider));

        // AES CBC-CTS. Ungated: all three key widths fetch under fips=yes on
        // both supported modules at both fipsinstall configurations, and
        // cts_mode is settable everywhere (probe:
        // fips-c-review/probes/cts_probe.c). Registered under both BC
        // spellings, as in ProvAES; the CS3 variant is pinned in C.
        provider.addAlgorithmImplementation("Cipher", "AES/CTS/NoPadding", AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, null, OSSLMode.CTS, provider));
        provider.addAlgorithmImplementation("Cipher", "AES/CBC/CS3Padding", AESBlockCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESBlockCipherSpi(FIPSNISelector.BlockCipherNI, null, OSSLMode.CTS, provider));

        //
        // AlgorithmParameters are pure-Java ASN.1 encodings - no NI binding.
        //
        provider.addAlgorithmImplementation("AlgorithmParameters", "GCM", GCMAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_GCM, GCMAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_GCM, GCMAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_GCM, GCMAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new GCMAlgorithmParameters());

        provider.addAlgorithmImplementation("AlgorithmParameters", "CCM", CCMAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_CCM, CCMAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_CCM, CCMAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_CCM, CCMAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new CCMAlgorithmParameters());

        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_CBC, CBCAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new CBCAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_CBC, CBCAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new CBCAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_CBC, CBCAlgorithmParameters.class.getName(), generalAesAttributes,
                (arg) -> new CBCAlgorithmParameters());
        // IV AlgorithmParameters under the bare family name; BlockCipherSpi
        // resolves it from THIS provider instance, so JSLFIPS serves its own.
        provider.addAlgorithmImplementation("AlgorithmParameters", "AES",
                IvAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new IvAlgorithmParameters());
    }
}
