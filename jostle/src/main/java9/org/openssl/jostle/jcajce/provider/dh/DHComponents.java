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

import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.Arrays;

import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;

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
    static BigInteger getBigInteger(DHServiceNI dhServiceNI, PKEYKeySpec spec, int component)
    {
        byte[] raw = null;
        byte[] trimmed = null;
        try
        {
            int len = dhServiceNI.getComponent(
                    spec.getReference(), component, null);
            raw = new byte[len];
            int written = dhServiceNI.getComponent(
                    spec.getReference(), component, raw);
            byte[] magnitude = raw;
            if (written != raw.length)
            {
                trimmed = new byte[written];
                System.arraycopy(raw, 0, trimmed, 0, written);
                magnitude = trimmed;
            }
            // Big-endian unsigned magnitude — positive sign forces
            // BigInteger to interpret without two's-complement wrapping.
            return new BigInteger(1, magnitude);
        }
        finally
        {
            // These transient buffers may hold the private value x
            // (COMP_PRIVATE_VALUE); the returned BigInteger keeps its
            // own copy, so scrub them (Arrays.clear is null-safe).
            Arrays.clear(raw);
            Arrays.clear(trimmed);
            Reference.reachabilityFence(spec);
        }
    }

    /**
     * Materialise the domain parameters of the underlying EVP_PKEY.
     *
     * <p>Returns a {@link DHDomainParameterSpec} when the key carries the
     * subgroup order q (X9.42) and a plain {@link DHParameterSpec} when it
     * does not (PKCS#3) — so a caller can recover q from a key that has one
     * instead of it being dropped on the floor. The private-value length
     * {@code l} is left at 0 (unspecified), the JCE convention when no
     * constraint was requested.
     */
    static DHParameterSpec getParams(DHServiceNI dhServiceNI, PKEYKeySpec spec)
    {
        BigInteger p = getBigInteger(dhServiceNI, spec, DHServiceNI.COMP_P);
        BigInteger g = getBigInteger(dhServiceNI, spec, DHServiceNI.COMP_G);
        if (!hasQ(dhServiceNI, spec))
        {
            return new DHParameterSpec(p, g);
        }
        return new DHDomainParameterSpec(
                p, getBigInteger(dhServiceNI, spec, DHServiceNI.COMP_Q), g);
    }

    /**
     * Does this key carry q? Asked through the RAW component call rather than
     * the throwing wrapper: a PKCS#3 key legitimately has no q, and the
     * two-call length probe reports that as a negative code. The OpenSSL error
     * entry a failed probe leaves behind is cleared by the next component
     * call, which clears the queue on entry.
     */
    static boolean hasQ(DHServiceNI dhServiceNI, PKEYKeySpec spec)
    {
        try
        {
            return dhServiceNI.ni_getComponent(
                    spec.getReference(), DHServiceNI.COMP_Q, null) > 0;
        }
        finally
        {
            Reference.reachabilityFence(spec);
        }
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
