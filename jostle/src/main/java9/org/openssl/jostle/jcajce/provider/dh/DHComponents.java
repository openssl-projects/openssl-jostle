/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.dh;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

import javax.crypto.spec.DHParameterSpec;
import java.lang.ref.Reference;
import java.math.BigInteger;

/**
 * Shared helper that fetches DH components from the native EVP_PKEY.
 *
 * <p>Java 9+ override of the Java 8 baseline. Uses
 * {@link Reference#reachabilityFence} to keep the underlying
 * {@code PKEYKeySpec} reachable across the two-step native calls
 * (query length, then fetch), replacing the {@code synchronized(spec)}
 * idiom in the baseline.
 */
final class DHComponents
{
    private DHComponents() {}

    /** Fetch a BIGNUM-valued component (p, q, g, y or x). */
    static BigInteger getBigInteger(PKEYKeySpec spec, int component)
    {
        try
        {
            int len = NISelector.DHServiceNI.getComponent(
                    spec.getReference(), component, null);
            byte[] raw = new byte[len];
            int written = NISelector.DHServiceNI.getComponent(
                    spec.getReference(), component, raw);
            if (written != raw.length)
            {
                byte[] trimmed = new byte[written];
                System.arraycopy(raw, 0, trimmed, 0, written);
                raw = trimmed;
            }
            // Big-endian unsigned magnitude — positive sign forces
            // BigInteger to interpret without two's-complement wrapping.
            return new BigInteger(1, raw);
        }
        finally
        {
            Reference.reachabilityFence(spec);
        }
    }

    /**
     * Materialise the domain parameters (p, g) of the underlying
     * EVP_PKEY as a {@link DHParameterSpec}. PKCS#3 DH has no q; the
     * private-value length {@code l} is left at 0 (unspecified), the
     * JCE convention when no constraint was requested.
     */
    static DHParameterSpec getParams(PKEYKeySpec spec)
    {
        return new DHParameterSpec(
                getBigInteger(spec, DHServiceNI.COMP_P),
                getBigInteger(spec, DHServiceNI.COMP_G));
    }

    /**
     * Convert a non-negative {@link BigInteger} to its big-endian
     * unsigned magnitude byte string. {@code BigInteger.toByteArray} is
     * two's-complement and may carry a leading zero (sign byte) that
     * the native {@code BN_bin2bn} path doesn't need. Callers reject
     * negative values before converting.
     */
    static byte[] unsignedMagnitude(BigInteger value)
    {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0)
        {
            byte[] out = new byte[raw.length - 1];
            System.arraycopy(raw, 1, out, 0, out.length);
            return out;
        }
        return raw;
    }
}
