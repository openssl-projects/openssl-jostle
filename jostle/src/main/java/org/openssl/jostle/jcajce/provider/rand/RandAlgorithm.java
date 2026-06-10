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

/**
 * SecureRandom algorithms registered by the Jostle provider.
 */
public enum RandAlgorithm
{
    /**
     * OpenSSL-backed DRBG service advertised through the JCA SecureRandom API.
     */
    DRBG("DRBG", 256);

    private final String jcaName;
    private final int strength;

    RandAlgorithm(String jcaName, int strength)
    {
        if (jcaName == null)
        {
            throw new NullPointerException("jcaName cannot be null");
        }

        if (strength < 0)
        {
            throw new IllegalArgumentException("strength cannot be negative");
        }

        this.jcaName = jcaName;
        this.strength = strength;
    }

    /**
     * Returns the JCA algorithm name used during provider registration.
     *
     * @return the JCA SecureRandom algorithm name
     */
    public String getJcaName()
    {
        return jcaName;
    }

    /**
     * Returns the maximum security strength advertised by this algorithm.
     *
     * @return strength in bits
     */
    public int getStrength()
    {
        return strength;
    }
}
