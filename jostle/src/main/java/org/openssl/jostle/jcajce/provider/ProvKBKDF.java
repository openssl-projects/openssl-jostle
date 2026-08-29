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

import org.openssl.jostle.jcajce.provider.kdf.KBKDFSecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * SP 800-108 KBKDF registrations.
 *
 * <p>The PRF goes in the name, following the {@code HKDF-SHA256} precedent —
 * {@code KBKDF-HMAC-<digest>} and {@code KBKDF-CMAC-AES<bits>}. The MODE
 * (counter or feedback) does not: both modes are served by every supported
 * OpenSSL build with either PRF, and putting a second orthogonal dimension in
 * the name would double the registration count for a choice the
 * {@code KBKDFParameterSpec} already carries.</p>
 *
 * <p>BouncyCastle has no JCE name for this KDF (only the lightweight
 * {@code KDFCounterBytesGenerator} / {@code KDFFeedbackBytesGenerator}), so
 * there is no interop name to match.</p>
 *
 * <p>SHA-3 digests are not registered here, for symmetry with the SSHKDF and
 * SSKDF families where the 3.5.x FIPS module's {@code *-digest-check} makes
 * SHA-3 conditional. Adding them would be a separate, capability-gated group.</p>
 */
class ProvKBKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }


    public void configure(final JostleProvider provider)
    {
        addHmac(provider, "SHA1", "SHA-1");
        addHmac(provider, "SHA224", "SHA-224");
        addHmac(provider, "SHA256", "SHA-256");
        addHmac(provider, "SHA384", "SHA-384");
        addHmac(provider, "SHA512", "SHA-512");

        addCmac(provider, "AES128", "AES-128-CBC");
        addCmac(provider, "AES192", "AES-192-CBC");
        addCmac(provider, "AES256", "AES-256-CBC");
    }

    private static void addHmac(JostleProvider provider, String suffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "KBKDF-HMAC-" + suffix,
                KBKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new KBKDFSecretKeyFactory(KBKDFSecretKeyFactory.HMAC, digest, null));
    }

    private static void addCmac(JostleProvider provider, String suffix, String cipher)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "KBKDF-CMAC-" + suffix,
                KBKDFSecretKeyFactory.class.getName(), generalKDFAttributes,
                (arg) -> new KBKDFSecretKeyFactory(KBKDFSecretKeyFactory.CMAC, null, cipher));
    }
}
