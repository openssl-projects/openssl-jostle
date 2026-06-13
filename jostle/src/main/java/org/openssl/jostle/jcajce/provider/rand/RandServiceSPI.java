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

package org.openssl.jostle.jcajce.provider.rand;

import org.openssl.jostle.jcajce.provider.NISelector;

import java.security.SecureRandomSpi;

/**
 * {@link SecureRandomSpi} backed by OpenSSL RAND.
 * <p>
 * OpenSSL owns entropy collection for this implementation. Caller-supplied
 * seed bytes supplement the native RAND state but are not treated as
 * deterministic input. The Java 8 baseline implementation accepts only
 * unparameterized construction; the Java 9+ multi-release implementation adds
 * support for {@code DrbgParameters}.
 * </p>
 */
public final class RandServiceSPI extends SecureRandomSpi
{
    private static final long serialVersionUID = 5952625728129925027L;
    private static final RandServiceNI randServiceNI = NISelector.RandServiceNI;

    private final RandAlgorithm algorithm;

    /**
     * Constructs an OpenSSL-backed SecureRandom SPI for the supplied algorithm.
     *
     * @param algorithm the registered SecureRandom algorithm
     * @throws NullPointerException if {@code algorithm} is {@code null}
     */
    public RandServiceSPI(RandAlgorithm algorithm)
    {
        this(algorithm, null);
    }

    /**
     * Constructs an OpenSSL-backed SecureRandom SPI.
     * <p>
     * The Java 8 baseline implementation rejects non-null parameters. The
     * Java 9+ multi-release implementation accepts
     * {@code DrbgParameters.Instantiation}.
     * </p>
     *
     * @param algorithm the registered SecureRandom algorithm
     * @param params construction parameters, or {@code null}
     * @throws NullPointerException if {@code algorithm} is {@code null}
     * @throws UnsupportedOperationException if {@code params} is non-null
     */
    public RandServiceSPI(RandAlgorithm algorithm, Object params)
    {
        if (params != null)
        {
            throw new UnsupportedOperationException("SecureRandom parameters are not supported");
        }

        if (algorithm == null)
        {
            throw new NullPointerException("algorithm cannot be null");
        }

        this.algorithm = algorithm;
    }

    @Override
    protected void engineSetSeed(byte[] seed)
    {
        if (seed == null)
        {
            throw new NullPointerException("seed cannot be null");
        }

        if (seed.length > 0)
        {
            randServiceNI.reseed(algorithm.getMaxStrength(), false, seed);
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes)
    {
        if (numBytes < 0)
        {
            throw new IllegalArgumentException("numBytes cannot be negative");
        }

        byte[] bytes = new byte[numBytes];
        randServiceNI.randomBytes(bytes, bytes.length, algorithm.getMaxStrength());
        return bytes;
    }

    @Override
    protected void engineNextBytes(byte[] bytes)
    {
        if (bytes == null)
        {
            throw new NullPointerException("bytes cannot be null");
        }

        randServiceNI.randomBytes(bytes, bytes.length, algorithm.getMaxStrength());
    }

    private Object readResolve()
    {
        return new RandServiceSPI(algorithm);
    }
}
