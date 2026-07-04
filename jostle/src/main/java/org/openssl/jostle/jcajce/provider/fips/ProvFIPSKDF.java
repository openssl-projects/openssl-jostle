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
import org.openssl.jostle.jcajce.provider.kdf.PBKDF2SecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * KDF registrations for the FIPS provider: PBKDF2 over the approved HMACs
 * and HKDF (SP 800-56C / RFC 5869). Deliberately absent: scrypt (not an
 * approved KDF) and the PBKDF2 variants over unapproved digests (MD5,
 * MD5-SHA1, SM3, RIPEMD-160, BLAKE2).
 */
class ProvFIPSKDF
{
    private static final String PBKDF_PREFIX = "org.openssl.jostle.jcajce.provider.ProvPBKDF";
    private static final String HKDF_PREFIX = "org.openssl.jostle.jcajce.provider.ProvHKDF";

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
    }

    private static void registerPbkdf2(JostleFIPSProvider provider, String name, String classNameSuffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", name, PBKDF_PREFIX + classNameSuffix, generalKDFAttributes,
                (arg) -> new PBKDF2SecretKeyFactory(FIPSNISelector.KdfNI, digest));
    }
}
