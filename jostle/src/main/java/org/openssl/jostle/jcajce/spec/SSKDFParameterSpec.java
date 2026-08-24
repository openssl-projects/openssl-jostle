/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

/**
 * Parameters for the NIST SP 800-56C one-step KDF (OpenSSL's {@code SSKDF}), as
 * served by {@code SecretKeyFactory.getInstance("SSKDF-SHA256")} and its
 * siblings. The auxiliary function H is the digest fixed by the registered
 * algorithm name; this spec carries the shared secret Z and the FixedInfo.
 *
 * <p>BouncyCastle's equivalent is the lightweight
 * {@code ConcatenationKDFGenerator} with {@code KDFParameters(z, otherInfo)};
 * there is no BC JCE spec to mirror, so the accessors follow SP 800-56C's own
 * vocabulary.</p>
 *
 * <h2>Why there is no salt</h2>
 *
 * <p>OpenSSL's SSKDF lists {@code salt} among its settable parameters, and it
 * is live for the MAC-based variants of the one-step KDF. In DIGEST mode — the
 * only mode this factory serves — it was measured to be silently ignored on
 * every supported OpenSSL build: absent, {@code salt1} and {@code salt2} all
 * produce the identical key. Exposing a knob a caller could vary with no
 * effect would be worse than omitting it, so it is omitted.</p>
 */
public class SSKDFParameterSpec
    implements KeySpec, AlgorithmParameterSpec
{
    private final byte[] secret;
    private final byte[] info;
    private final int outputLength;

    /**
     * @param secret       the shared secret Z. Must not be null.
     * @param info         the FixedInfo, or null for none. An absent FixedInfo
     *                     and an empty one produce the same key.
     * @param outputLength derived key length in bytes. Must be positive.
     */
    public SSKDFParameterSpec(byte[] secret, byte[] info, int outputLength)
    {
        if (secret == null)
        {
            throw new IllegalArgumentException("secret is null");
        }

        // See KBKDFParameterSpec for why zero is refused in Java rather than
        // left to the provider.
        if (outputLength <= 0)
        {
            throw new IllegalArgumentException("output length must be positive");
        }

        this.secret = Arrays.clone(secret);
        this.info = Arrays.clone(info);
        this.outputLength = outputLength;
    }

    /**
     * @return a copy of the shared secret Z.
     */
    public byte[] getSecret()
    {
        return Arrays.clone(secret);
    }

    /**
     * @return a copy of the FixedInfo, or null if none was supplied.
     */
    public byte[] getInfo()
    {
        return Arrays.clone(info);
    }

    /**
     * @return the derived key length in bytes.
     */
    public int getOutputLength()
    {
        return outputLength;
    }
}
