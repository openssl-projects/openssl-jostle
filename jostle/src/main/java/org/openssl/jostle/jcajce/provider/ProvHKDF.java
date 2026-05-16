/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.jcajce.provider.kdf.HKDFSecretKeyFactory;
import org.openssl.jostle.jcajce.provider.kdf.X963KDFSecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

class ProvHKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvHKDF.class.getName();

    public void configure(final JostleProvider provider)
    {
        // Bare HKDF — accepts any digest carried in the spec.
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDF",
                PREFIX + "Base", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory());

        // Per-PRF variants. JCE callers typically ask for one of these by
        // name (RFC 5869 only varies in the HMAC PRF; SHA-256/384/512 are
        // the practical CMS / CMP / TLS choices). Each pins the digest
        // at construction so a mismatched HKDFKeySpec is rejected.
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA256",
                PREFIX + "SHA256", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA384",
                PREFIX + "SHA384", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA512",
                PREFIX + "SHA512", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-512"));

        // SHA-1 variant kept for legacy interop. Modern CMP profiles do
        // NOT use HKDF-SHA1, but TLS 1.2 / 1.3 transcript machinery
        // sometimes does; registering for compatibility.
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA1",
                PREFIX + "SHA1", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-1"));

        // SHA-2 224 / 512-truncated variants for completeness.
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA224",
                PREFIX + "SHA224", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA512-224",
                PREFIX + "SHA512_224", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-512/224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA512-256",
                PREFIX + "SHA512_256", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA-512/256"));

        // SHA-3 family.
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA3-224",
                PREFIX + "SHA3_224", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA3-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA3-256",
                PREFIX + "SHA3_256", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA3-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA3-384",
                PREFIX + "SHA3_384", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA3-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "HKDFwithHmacSHA3-512",
                PREFIX + "SHA3_512", generalKDFAttributes, (arg) -> new HKDFSecretKeyFactory("SHA3-512"));

        // -----------------------------------------------------------------
        // ANSI X9.63 KDF (and SP 800-56A "concatenation KDF"). Most CMP
        // / CMS callers reach this via the composed ECDHwithSHA*KDF
        // KeyAgreement transformation; we additionally register the
        // standalone SecretKeyFactory form for direct use (testing /
        // KAT verification, callers that want to apply the KDF to a
        // pre-computed Z).
        // -----------------------------------------------------------------
        provider.addAlgorithmImplementation("SecretKeyFactory", "X963KDF",
                PREFIX + "X963KDFBase", generalKDFAttributes, (arg) -> new X963KDFSecretKeyFactory());
        provider.addAlgorithmImplementation("SecretKeyFactory", "X963KDFwithSHA1",
                PREFIX + "X963KDFSHA1", generalKDFAttributes, (arg) -> new X963KDFSecretKeyFactory("SHA-1"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "X963KDFwithSHA224",
                PREFIX + "X963KDFSHA224", generalKDFAttributes, (arg) -> new X963KDFSecretKeyFactory("SHA-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "X963KDFwithSHA256",
                PREFIX + "X963KDFSHA256", generalKDFAttributes, (arg) -> new X963KDFSecretKeyFactory("SHA-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "X963KDFwithSHA384",
                PREFIX + "X963KDFSHA384", generalKDFAttributes, (arg) -> new X963KDFSecretKeyFactory("SHA-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "X963KDFwithSHA512",
                PREFIX + "X963KDFSHA512", generalKDFAttributes, (arg) -> new X963KDFSecretKeyFactory("SHA-512"));
    }
}
