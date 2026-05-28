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

public enum RandAlgorithm
{
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

    public String getJcaName()
    {
        return jcaName;
    }

    public int getStrength()
    {
        return strength;
    }
}
