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

    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }

    public void configure(final JostleFIPSProvider provider)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new PBKDF2SecretKeyFactory(FIPSNISelector.KdfNI, null));
        // id-PBKDF2, RFC 8018 A.2, mirroring ProvPBKDF. PBES2 / PKCS#8 / PKCS#12
        // resolve the key-derivation SecretKeyFactory by this OID, not by name.
        provider.addAlias("SecretKeyFactory", "PBKDF2", "1.2.840.113549.1.5.12");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA1", "SHA-1");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA224", "SHA-224");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA256", "SHA-256");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA384", "SHA-384");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA512", "SHA-512");
        // Both providers: the conversion is caller-side data preparation and
        // PBKDF2-HMAC-SHA1 is approved.
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHASCII", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new PBKDF2SecretKeyFactory(FIPSNISelector.KdfNI, "SHA-1", true));
        provider.addAlias("SecretKeyFactory", "PBKDF2WITHASCII", "PBKDF2WITH8BIT", "PBKDF2WITHHMACSHA1AND8BIT");

        registerPbkdf2(provider, "PBKDF2WITHHMACSHA512-224", "SHA-512/224");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA512-256", "SHA-512/256");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA3-224", "SHA3-224");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA3-256", "SHA3-256");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA3-384", "SHA3-384");
        registerPbkdf2(provider, "PBKDF2WITHHMACSHA3-512", "SHA3-512");

        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF-SHA256", HKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new HKDFSecretKeyFactory(FIPSNISelector.KdfNI, FIPSNISelector.MDServiceNI, "SHA-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF-SHA384", HKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new HKDFSecretKeyFactory(FIPSNISelector.KdfNI, FIPSNISelector.MDServiceNI, "SHA-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF-SHA512", HKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new HKDFSecretKeyFactory(FIPSNISelector.KdfNI, FIPSNISelector.MDServiceNI, "SHA-512"));

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
                KBKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new KBKDFSecretKeyFactory(FIPSNISelector.KdfNI,
                        KBKDFSecretKeyFactory.HMAC, digest, null));
    }

    private static void registerKbkdfCmac(JostleFIPSProvider provider, String suffix, String cipher)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "KBKDF-CMAC-" + suffix,
                KBKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new KBKDFSecretKeyFactory(FIPSNISelector.KdfNI,
                        KBKDFSecretKeyFactory.CMAC, null, cipher));
    }

    private static void registerSskdf(JostleFIPSProvider provider, String suffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "SSKDF-" + suffix,
                SSKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new SSKDFSecretKeyFactory(FIPSNISelector.KdfNI, digest));
    }

    private static void registerSshkdf(JostleFIPSProvider provider, String suffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "SSHKDF-" + suffix,
                SSHKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new SSHKDFSecretKeyFactory(FIPSNISelector.KdfNI, digest));
    }

    private static void registerPbkdf2(JostleFIPSProvider provider, String name, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", name, PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new PBKDF2SecretKeyFactory(FIPSNISelector.KdfNI, digest));
    }
}
