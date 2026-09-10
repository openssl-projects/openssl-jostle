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
import org.openssl.jostle.jcajce.provider.wrap.RFC3211WrapCipherSpi;

class ProvAES
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

    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher", "AES", AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(provider));
        provider.addAlgorithmImplementation("KeyGenerator", "AES", AESKeyGenerator.class.getName(), generalAesAttributes, (arg) -> new AESKeyGenerator());


        // RFC 3211 password-based wrap for CMS PasswordRecipientInfo. Not an
        // SP 800-38F wrap and not an OpenSSL primitive, so it is Java over our
        // own CBC; JSL only (Megan, 2026-09-09).
        provider.addAlgorithmImplementation("Cipher", "AESRFC3211Wrap", RFC3211WrapCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new RFC3211WrapCipherSpi("AES", 16, new int[]{16, 24, 32}, provider));

        provider.addAlgorithmImplementation("Cipher", "AESWrap", AESBlockCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new AESBlockCipherSpi(null, OSSLMode.WRAP, provider));
        provider.addAlias("Cipher", "AESWrap", "AESKW");
        provider.addAlgorithmImplementation("Cipher", "AESWrapPad", AESBlockCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new AESBlockCipherSpi(null, OSSLMode.WRAP_PAD, provider));
        provider.addAlias("Cipher", "AESWrapPad", "AESKWP");

        // AES key wrap on the INVERSE cipher function (SP 800-38F 5.1), which
        // OpenSSL calls AES-<n>-WRAP-INV.
        //
        // "AESWrapInv" is JOSTLE-CHOSEN — no convention exists. The JDK
        // registers nothing for this direction; BC ships only the lightweight
        // AESWrapEngine(true); NIST assigns no OID. So: symmetry with
        // AESWrap / AESWrapPad, alias AESKWINV, and BlockCipherSpi also takes
        // the mode spellings KWINV and WRAP-INV. Interop is by construction,
        // not by name — BC's engine and OpenSSL's cipher were measured
        // byte-identical both ways.
        //
        // No per-width OID primaries: there are no OIDs, so the width comes
        // from the key length as it does for the bare AESWrap name.
        provider.addAlgorithmImplementation("Cipher", "AESWrapInv", AESBlockCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new AESBlockCipherSpi(null, OSSLMode.WRAP_INV, provider));
        provider.addAlias("Cipher", "AESWrapInv", "AESKWINV");

        // NIST AES OIDs are registered so that consumers which resolve algorithms by OID
        // (notably CMS, which looks up the content-encryption and key-wrap KeyGenerator
        // and Cipher by their algorithm OID) find the JSL implementations. ECB/CBC/GCM
        // and key-wrap (RFC 3394) / key-wrap-with-padding (RFC 5649) are all wired
        // through to OpenSSL.

        provider.addAlgorithmImplementation("Cipher", "AES128", AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.ECB, provider));
        provider.addAlias("Cipher", "AES128", NISTObjectIdentifiers.id_aes128_ECB);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_CBC, AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.CBC, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_GCM, AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.GCM, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap, AESBlockCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.WRAP, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_wrap_pad, AESBlockCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES128, OSSLMode.WRAP_PAD, provider));
        provider.addAlgorithmImplementation("KeyGenerator", "AES128", AESKeyGenerator.class.getName(), generalAesAttributes, (arg) -> new AESKeyGenerator(128));
        provider.addAlias("KeyGenerator", "AES128", NISTObjectIdentifiers.id_aes128_ECB, NISTObjectIdentifiers.id_aes128_CBC, NISTObjectIdentifiers.id_aes128_GCM, NISTObjectIdentifiers.id_aes128_wrap, NISTObjectIdentifiers.id_aes128_wrap_pad, NISTObjectIdentifiers.id_aes128_CCM);

        provider.addAlgorithmImplementation("Cipher", "AES192", AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.ECB, provider));
        provider.addAlias("Cipher", "AES192", NISTObjectIdentifiers.id_aes192_ECB);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_CBC, AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.CBC, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_GCM, AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.GCM, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap, AESBlockCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.WRAP, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_wrap_pad, AESBlockCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES192, OSSLMode.WRAP_PAD, provider));
        provider.addAlgorithmImplementation("KeyGenerator", "AES192", AESKeyGenerator.class.getName(), generalAesAttributes, (arg) -> new AESKeyGenerator(192));
        provider.addAlias("KeyGenerator", "AES192", NISTObjectIdentifiers.id_aes192_ECB, NISTObjectIdentifiers.id_aes192_CBC, NISTObjectIdentifiers.id_aes192_GCM, NISTObjectIdentifiers.id_aes192_wrap, NISTObjectIdentifiers.id_aes192_wrap_pad, NISTObjectIdentifiers.id_aes192_CCM);

        provider.addAlgorithmImplementation("Cipher", "AES256", AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.ECB, provider));
        provider.addAlias("Cipher", "AES256", NISTObjectIdentifiers.id_aes256_ECB);
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_CBC, AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.CBC, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_GCM, AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.GCM, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap, AESBlockCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.WRAP, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_wrap_pad, AESBlockCipherSpi.class.getName(), wrapAesAttributes, (arg) -> new AESBlockCipherSpi(OSSLCipher.AES256, OSSLMode.WRAP_PAD, provider));
        provider.addAlgorithmImplementation("KeyGenerator", "AES256", AESKeyGenerator.class.getName(), generalAesAttributes, (arg) -> new AESKeyGenerator(256));
        provider.addAlias("KeyGenerator", "AES256", NISTObjectIdentifiers.id_aes256_ECB, NISTObjectIdentifiers.id_aes256_CBC, NISTObjectIdentifiers.id_aes256_GCM, NISTObjectIdentifiers.id_aes256_wrap, NISTObjectIdentifiers.id_aes256_wrap_pad, NISTObjectIdentifiers.id_aes256_CCM);

        // AES-GCM AlgorithmParameters, registered under the bare name "GCM" and
        // the GCM OIDs (see GCMAlgorithmParameters). Lets OID-driven callers —
        // notably CMS EnvelopedData decryption — parse the stored GCMParameters
        // (nonce/ICV) via AlgorithmParameters.getInstance(<aes-gcm-oid>, "JSL"),
        // and name-driven callers resolve it via getInstance("GCM", "JSL"). The
        // delegate is resolved from a non-Jostle provider so the bare name can't
        // recurse.
        provider.addAlgorithmImplementation("AlgorithmParameters", "GCM", GCMAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_GCM, GCMAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_GCM, GCMAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new GCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_GCM, GCMAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new GCMAlgorithmParameters());

        // AES-CCM AlgorithmParameters, registered under the bare name "CCM" and
        // the CCM OIDs (see CCMAlgorithmParameters). No JDK provider ships a CCM
        // AlgorithmParameters, so this one is self-contained (RFC 5084 codec).
        provider.addAlgorithmImplementation("AlgorithmParameters", "CCM", CCMAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_CCM, CCMAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_CCM, CCMAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new CCMAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_CCM, CCMAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new CCMAlgorithmParameters());

        // IV AlgorithmParameters under the bare family name. BlockCipherSpi's
        // non-AEAD getParameters() resolves this from its own provider instance;
        // before MT-18 it resolved "AES" from whichever provider answered first.
        provider.addAlgorithmImplementation("AlgorithmParameters", "AES",
                IvAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new IvAlgorithmParameters());

        // AES-CBC AlgorithmParameters, registered under the CBC OIDs only (see
        // CBCAlgorithmParameters). Lets OID-driven callers — notably BC's PBES2 /
        // PKCS#8 / PKCS#12 decryptors — recover the stored IV via
        // AlgorithmParameters.getInstance(<aes-cbc-oid>, "JSL").
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes128_CBC, CBCAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new CBCAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes192_CBC, CBCAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new CBCAlgorithmParameters());
        provider.addAlgorithmImplementation("AlgorithmParameters", NISTObjectIdentifiers.id_aes256_CBC, CBCAlgorithmParameters.class.getName(), generalAesAttributes, (arg) -> new CBCAlgorithmParameters());

        // AES/CCM — separate SPI because CCM is one-shot at the
        // OpenSSL layer (total plaintext length must be known up-front,
        // AAD must be passed in a single call). Registering with the
        // explicit "AES/CCM/NoPadding" form so JCE Cipher.getInstance
        // resolves directly to AESCCMCipherSpi rather than the generic
        // BlockCipherSpi.
        provider.addAlgorithmImplementation("Cipher", "AES/CCM/NoPadding",
                AESCCMCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESCCMCipherSpi(provider));

        // The NIST CCM OIDs, which CMS and PKCS#8 resolve a content-encryption
        // Cipher by. Registered as PRIMARIES rather than aliases of
        // "AES/CCM/NoPadding" because each OID names a key size, and the bare
        // transformation derives its cipher from the key length — an alias
        // would make id-aes128-CCM accept a 256-bit key. The pinned
        // constructor refuses a key of any other length.
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes128_CCM,
                AESCCMCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESCCMCipherSpi(OSSLCipher.AES128, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes192_CCM,
                AESCCMCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESCCMCipherSpi(OSSLCipher.AES192, provider));
        provider.addAlgorithmImplementation("Cipher", NISTObjectIdentifiers.id_aes256_CCM,
                AESCCMCipherSpi.class.getName(), generalAesAttributes,
                (arg) -> new AESCCMCipherSpi(OSSLCipher.AES256, provider));

        // XTS-AES (IEEE 1619 / SP 800-38E). Registered under the explicit
        // transformation so it appears in getServices() rather than only
        // resolving through the bare "AES" primary's engineSetMode. The mode
        // is pre-locked in the constructor because a form-1 lookup on the
        // full transformation does NOT call engineSetMode.
        //
        // No AES128/AES192/AES256 variants: the XTS key is key1||key2, so its
        // length alone picks the cipher (32 bytes -> AES-128-XTS, 64 ->
        // AES-256-XTS) and AES-192-XTS does not exist. There is no BC name to
        // follow here — BouncyCastle ships no AES-XTS at all.
        provider.addAlgorithmImplementation("Cipher", "AES/XTS/NoPadding",
                AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(null, OSSLMode.XTS, provider));

        // AES CBC-CTS (CBC with ciphertext stealing). Registered under both
        // spellings BouncyCastle uses, so a caller does not have to know which
        // library it is talking to: "AES/CTS/NoPadding" is BC's name, and
        // "AES/CBC/CS3Padding" is BC's explicit-variant name for the SAME
        // bytes (measured byte-identical at nine lengths -
        // fips-c-review/probes/CtsProbe2.java).
        //
        // The variant is CS3, pinned in C rather than inherited: OpenSSL
        // defaults to CS1, which does NOT interoperate with either BC name.
        // Mode pre-locked in the constructor because a form-1 lookup on the
        // full transformation does not call engineSetMode. No per-key-size
        // variants, matching the other AES mode registrations.
        provider.addAlgorithmImplementation("Cipher", "AES/CTS/NoPadding",
                AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(null, OSSLMode.CTS, provider));
        provider.addAlgorithmImplementation("Cipher", "AES/CBC/CS3Padding",
                AESBlockCipherSpi.class.getName(), generalAesAttributes, (arg) -> new AESBlockCipherSpi(null, OSSLMode.CTS, provider));

    }
}
