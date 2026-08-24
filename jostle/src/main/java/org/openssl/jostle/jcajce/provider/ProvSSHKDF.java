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

import org.openssl.jostle.jcajce.provider.kdf.SSHKDFSecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * RFC 4253 section 7.2 SSH key-derivation registrations. Naming follows the
 * {@code HKDF-SHA256} precedent.
 *
 * <p>SHA-1 is registered because SSH itself still uses it
 * ({@code diffie-hellman-group14-sha1}), and it was measured accepted by both
 * supported FIPS modules — {@code sshkdf-digest-check} turns out not to be a
 * SHA-1 gate. SHA-3 is NOT registered: that same switch refuses SHA3-256 on
 * the 3.5.x module while 3.1.2 accepts it, so it would need a capability gate
 * for a digest no SSH key exchange defines.</p>
 */
class ProvSSHKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvSSHKDF.class.getName();

    public void configure(final JostleProvider provider)
    {
        add(provider, "SHA1", "SHA-1");
        add(provider, "SHA224", "SHA-224");
        add(provider, "SHA256", "SHA-256");
        add(provider, "SHA384", "SHA-384");
        add(provider, "SHA512", "SHA-512");
    }

    private static void add(JostleProvider provider, String suffix, String digest)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "SSHKDF-" + suffix,
                PREFIX + suffix, generalKDFAttributes,
                (arg) -> new SSHKDFSecretKeyFactory(digest));
    }
}
