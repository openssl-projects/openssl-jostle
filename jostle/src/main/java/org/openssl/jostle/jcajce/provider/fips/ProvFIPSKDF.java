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

import org.openssl.jostle.jcajce.provider.kdf.HKDFSecretKeyFactory;
import org.openssl.jostle.jcajce.provider.kdf.KBKDFSecretKeyFactory;
import org.openssl.jostle.jcajce.provider.kdf.PBKDF2SecretKeyFactory;
import org.openssl.jostle.jcajce.provider.kdf.SSHKDFSecretKeyFactory;
import org.openssl.jostle.jcajce.provider.kdf.SSKDFSecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * KDF registrations for the FIPS provider: PBKDF2 over the approved HMACs,
 * HKDF (SP 800-56C / RFC 5869), KBKDF (SP 800-108), the SP 800-56C one-step
 * KDF and SSHKDF (RFC 4253). Deliberately absent: scrypt (not an approved KDF)
 * and the PBKDF2 variants over unapproved digests (MD5, MD5-SHA1, SM3,
 * RIPEMD-160, BLAKE2).
 */
class ProvFIPSKDF
{
    private static final String PBKDF_PREFIX = "org.openssl.jostle.jcajce.provider.ProvPBKDF";
    private static final String HKDF_PREFIX = "org.openssl.jostle.jcajce.provider.ProvHKDF";
    private static final String KBKDF_PREFIX = "org.openssl.jostle.jcajce.provider.ProvKBKDF";
    private static final String SSKDF_PREFIX = "org.openssl.jostle.jcajce.provider.ProvSSKDF";
    private static final String SSHKDF_PREFIX = "org.openssl.jostle.jcajce.provider.ProvSSHKDF";

    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }

    public void configure(final JostleFIPSProvider provider)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2", PBKDF_PREFIX + "Base", generalKDFAttributes,
                (arg) -> new PBKDF2SecretKeyFactory(FIPSNISelector.KdfNI, null));
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA1", "BaseSHA1", "SHA-1");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA224", "BaseSHA224", "SHA-224");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA256", "BaseSHA256", "SHA-256");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA384", "BaseSHA384", "SHA-384");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA512", "BaseSHA512", "SHA-512");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA512-224", "BaseSHA512_224", "SHA-512/224");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA512-256", "BaseSHA512_256", "SHA-512/256");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA3-224", "BaseSHA3_224", "SHA3-224");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA3-256", "BaseSHA3_256", "SHA3-256");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA3-384", "BaseSHA3_384", "SHA3-384");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA3-512", "BaseSHA3_512", "SHA3-512");

        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF-SHA256", HKDF_PREFIX + "SHA256", generalKDFAttributes,
                (arg) -> new HKDFSecretKeyFactory(FIPSNISelector.KdfNI, "SHA-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF-SHA384", HKDF_PREFIX + "SHA384", generalKDFAttributes,
                (arg) -> new HKDFSecretKeyFactory(FIPSNISelector.KdfNI, "SHA-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF-SHA512", HKDF_PREFIX + "SHA512", generalKDFAttributes,
                (arg) -> new HKDFSecretKeyFactory(FIPSNISelector.KdfNI, "SHA-512"));

        // KBKDF, SSKDF and SSHKDF are registered UNGATED: all three were
        // measured fetchable under fips=yes on both supported modules
        // (fips-c-review/probes/kdf_probe.c, conclusion 1). What differs
        // between the modules is the *-key-check floor and, for SSHKDF, which
        // digests -digest-check permits - neither of which is a registration
        // question.
        registerKbkdfHmac(provider, "SHA1", "SHA-1");
        registerKbkdfHmac(provider, "SHA224", "SHA-224");
        registerKbkdfHmac(provider, "SHA256", "SHA-256");
        registerKbkdfHmac(provider, "SHA384", "SHA-384");
        registerKbkdfHmac(provider, "SHA512", "SHA-512");
        registerKbkdfCmac(provider, "AES128", "AES-128-CBC");
        registerKbkdfCmac(provider, "AES192", "AES-192-CBC");
        registerKbkdfCmac(provider, "AES256", "AES-256-CBC");

        registerSskdf(provider, "SHA1", "SHA-1");
        registerSskdf(provider, "SHA224", "SHA-224");
        registerSskdf(provider, "SHA256", "SHA-256");
        registerSskdf(provider, "SHA384", "SHA-384");
        registerSskdf(provider, "SHA512", "SHA-512");

        registerSshkdf(provider, "SHA1", "SHA-1");
        registerSshkdf(provider, "SHA224", "SHA-224");
        registerSshkdf(provider, "SHA256", "SHA-256");
        registerSshkdf(provider, "SHA384", "SHA-384");
        registerSshkdf(provider, "SHA512", "SHA-512");
    }

    private static void registerKbkdfHmac(JostleFIPSProvider provider, String suffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "KBKDF-HMAC-" + suffix,
                KBKDF_PREFIX + "HMAC" + suffix, generalKDFAttributes,
                (arg) -> new KBKDFSecretKeyFactory(FIPSNISelector.KdfNI,
                        KBKDFSecretKeyFactory.HMAC, digest, null));
    }

    private static void registerKbkdfCmac(JostleFIPSProvider provider, String suffix, String cipher)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "KBKDF-CMAC-" + suffix,
                KBKDF_PREFIX + "CMAC" + suffix, generalKDFAttributes,
                (arg) -> new KBKDFSecretKeyFactory(FIPSNISelector.KdfNI,
                        KBKDFSecretKeyFactory.CMAC, null, cipher));
    }

    private static void registerSskdf(JostleFIPSProvider provider, String suffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "SSKDF-" + suffix,
                SSKDF_PREFIX + suffix, generalKDFAttributes,
                (arg) -> new SSKDFSecretKeyFactory(FIPSNISelector.KdfNI, digest));
    }

    private static void registerSshkdf(JostleFIPSProvider provider, String suffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "SSHKDF-" + suffix,
                SSHKDF_PREFIX + suffix, generalKDFAttributes,
                (arg) -> new SSHKDFSecretKeyFactory(FIPSNISelector.KdfNI, digest));
    }

    private static void registerPbkdf2(JostleFIPSProvider provider, String name, String classNameSuffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", name, PBKDF_PREFIX + classNameSuffix, generalKDFAttributes,
                (arg) -> new PBKDF2SecretKeyFactory(FIPSNISelector.KdfNI, digest));
    }
}
