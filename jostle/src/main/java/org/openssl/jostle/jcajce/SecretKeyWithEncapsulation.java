/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce;

import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;

public class SecretKeyWithEncapsulation implements SecretKey
{
    private final SecretKey secretKey;
    private final byte[] encapsulation;

    public SecretKeyWithEncapsulation(SecretKey secretKey, byte[] encapsulation)
    {
        this.secretKey = secretKey;
        this.encapsulation = Arrays.clone(encapsulation);
    }

    public SecretKey getSecretKey()
    {
        return secretKey;
    }

    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }

    @Override
    public String getAlgorithm()
    {
        return secretKey.getAlgorithm();
    }

    @Override
    public String getFormat()
    {
        return secretKey.getFormat();
    }

    @Override
    public byte[] getEncoded()
    {
        return secretKey.getEncoded();
    }

    public boolean equals(Object o)
    {
        return secretKey.equals(o);
    }

    public int hashCode()
    {
        return secretKey.hashCode();
    }
    
}
