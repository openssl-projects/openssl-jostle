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

/**
 * Parameters for KMAC128 / KMAC256 (NIST SP 800-185): the requested output
 * length {@code L} and the customisation string {@code S}.
 * <p>
 * Deliberately shaped to mirror {@code org.bouncycastle.jcajce.spec.KMACParameterSpec}
 * — same constructors, same accessor names, same validation — so code written
 * against BouncyCastle's KMAC needs only an import change to run on Jostle. The
 * two are separate classes rather than a dependency because Jostle's provider
 * does not depend on BouncyCastle at runtime.
 * <p>
 * Both parameters are optional. Omitting the spec entirely gives an empty
 * customisation string and the algorithm's default output length — 32 bytes for
 * KMAC128 and 64 for KMAC256 — which is what SP 800-185 specifies and what
 * OpenSSL reports when asked (the length is queried from OpenSSL, never
 * transcribed). An absent customisation string and an empty one produce
 * identical tags, measured on every supported OpenSSL build.
 * <p>
 * Note that {@code L} is bound into the KMAC input, so two different output
 * lengths do not share a prefix: asking for 32 bytes and truncating a 64-byte
 * tag are different operations with different results.
 */
public class KMACParameterSpec
        implements AlgorithmParameterSpec
{
    private final int macSizeInBits;
    private final byte[] customizationString;

    /**
     * Requested output length with an empty customisation string.
     *
     * @param macSizeInBits the requested MAC output length in bits; must be
     *                      positive and a multiple of 8.
     */
    public KMACParameterSpec(int macSizeInBits)
    {
        this(macSizeInBits, new byte[0]);
    }

    /**
     * @param macSizeInBits       the requested MAC output length in bits; must
     *                            be positive and a multiple of 8.
     * @param customizationString the customisation string {@code S}; may be
     *                            empty, and {@code null} is treated as empty.
     */
    public KMACParameterSpec(int macSizeInBits, byte[] customizationString)
    {
        // Matches BouncyCastle's validation exactly, including the message
        // wording, so a caller porting between the two sees the same failure.
        if ((macSizeInBits & 7) != 0)
        {
            throw new IllegalArgumentException("macSizeInBits must be a multiple of 8");
        }
        // A zero or negative length must never reach OpenSSL: three of the four
        // supported OpenSSL builds accept size=0 and then emit a ZERO-LENGTH
        // MAC, which compares equal to every other zero-length tag. Refusing
        // here is what keeps 0 usable as the internal "unspecified" sentinel.
        if (macSizeInBits <= 0)
        {
            throw new IllegalArgumentException("macSizeInBits must be positive");
        }

        this.macSizeInBits = macSizeInBits;
        this.customizationString = (customizationString == null)
                ? new byte[0] : Arrays.clone(customizationString);
    }

    public int getMacSizeInBits()
    {
        return macSizeInBits;
    }

    public byte[] getCustomizationString()
    {
        return Arrays.clone(customizationString);
    }
}
