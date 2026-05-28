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
 * SecureRandomSpi backed by OpenSSL RAND.
 * <p>
 * OpenSSL owns seeding and reseeding for this implementation. Caller-supplied
 * seed bytes are accepted for SecureRandom API compatibility, but they are not
 * treated as deterministic input or additional entropy. JDK 9+ parameterized
 * DRBG operations are not supported by this SPI.
 * </p>
 */
public final class RandServiceSPI extends SecureRandomSpi
{
    private static final long serialVersionUID = 5952625728129925027L;
    private static final RandServiceNI randServiceNI = NISelector.RandServiceNI;

    private final RandAlgorithm algorithm;

    public RandServiceSPI(RandAlgorithm algorithm)
    {
        if (algorithm == null)
        {
            throw new NullPointerException("algorithm cannot be null");
        }

        this.algorithm = algorithm;
    }

    @Override
    protected void engineSetSeed(byte[] seed)
    {
        // See the class-level seeding contract.
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes)
    {
        if (numBytes < 0)
        {
            throw new IllegalArgumentException("numBytes cannot be negative");
        }

        byte[] bytes = new byte[numBytes];
        randServiceNI.randomBytes(bytes, bytes.length, algorithm.getStrength());
        return bytes;
    }

    @Override
    protected void engineNextBytes(byte[] bytes)
    {
        if (bytes == null)
        {
            throw new NullPointerException("bytes cannot be null");
        }

        randServiceNI.randomBytes(bytes, bytes.length, algorithm.getStrength());
    }

    private Object readResolve()
    {
        return new RandServiceSPI(algorithm);
    }
}
