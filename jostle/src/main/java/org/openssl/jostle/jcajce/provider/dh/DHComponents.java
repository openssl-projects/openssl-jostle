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
import java.math.BigInteger;

/**
 * Shared helper that fetches DH components from the native EVP_PKEY.
 * Mirrors {@code DSAComponents}: synchronizes on the spec to keep the
 * underlying EVP_PKEY reachable across the two-call protocol (query
 * length, then fetch).
 */
final class DHComponents
{
    private DHComponents() {}

    /** Fetch a BIGNUM-valued component (p, q, g, y or x). */
    static BigInteger getBigInteger(DHServiceNI dhServiceNI, PKEYKeySpec spec, int component)
    {
        synchronized (spec)
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
            }
        }
    }

    /**
     * Materialise the domain parameters of the underlying EVP_PKEY.
     *
     * <p>The form is the key's type, one fact: a {@link DHDomainParameterSpec}
     * (with q) for an X9.42 key and a plain {@link DHParameterSpec} for a
     * PKCS#3 key, whatever OpenSSL knows about its group. {@code l} is the
     * key's own private-value length, 0 when none was set.
     */
    static DHParameterSpec getParams(DHServiceNI dhServiceNI, PKEYKeySpec spec)
    {
        BigInteger p = getBigInteger(dhServiceNI, spec, DHServiceNI.COMP_P);
        BigInteger g = getBigInteger(dhServiceNI, spec, DHServiceNI.COMP_G);
        int l = intComponent(dhServiceNI, spec, DHServiceNI.COMP_PRIVATE_LENGTH);
        if (intComponent(dhServiceNI, spec, DHServiceNI.COMP_FORM) != DHServiceNI.FORM_X942)
        {
            return new DHParameterSpec(p, g, l);
        }
        return new DHDomainParameterSpec(
                p, getBigInteger(dhServiceNI, spec, DHServiceNI.COMP_Q), g, l);
    }

    /** An integer-valued component (the form or the private-value length), asked once. */
    static int intComponent(DHServiceNI dhServiceNI, PKEYKeySpec spec, int component)
    {
        synchronized (spec)
        {
            return dhServiceNI.getComponent(spec.getReference(), component, null);
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
