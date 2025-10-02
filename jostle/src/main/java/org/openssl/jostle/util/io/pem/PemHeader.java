/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.util.io.pem;

/**
 * Class representing a PEM header (name, value) pair.
 */
public class PemHeader
{
    private final String name;
    private final String value;

    /**
     * Base constructor.
     *
     * @param name name of the header property.
     * @param value value of the header property.
     */
    public PemHeader(String name, String value)
    {
        this.name = name;
        this.value = value;
    }

    public String getName()
    {
        return name;
    }

    public String getValue()
    {
        return value;
    }

    public int hashCode()
    {
        return getHashCode(this.name) + 31 * getHashCode(this.value);    
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof PemHeader))
        {
            return false;
        }

        PemHeader other = (PemHeader)o;

        return other == this || (isEqual(this.name, other.name) && isEqual(this.value, other.value));
    }

    private int getHashCode(String s)
    {
        if (s == null)
        {
            return 1;
        }

        return s.hashCode();
    }

    private boolean isEqual(String s1, String s2)
    {
        if (s1 == s2)
        {
            return true;
        }

        if (s1 == null || s2 == null)
        {
            return false;
        }

        return s1.equals(s2);
    }

}
