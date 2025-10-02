/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;

import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

public class KEMExtractSpec implements AlgorithmParameterSpec
{
    private final PrivateKey privateKey;
    private final String algorithmName;
    private final int keySizeInBits;
    private final byte[] encapsulation;


    public KEMExtractSpec(PrivateKey publicKey, String algorithmName, int keySize, byte[] encapsulation)
    {
        this.privateKey = publicKey;
        this.algorithmName = algorithmName;
        this.keySizeInBits = keySize;
        this.encapsulation = Arrays.clone(encapsulation);
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public int getKeySizeInBits()
    {
        return keySizeInBits;
    }

    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }

    public static Builder builder()
    {
        return new Builder(null, null, 256, null);
    }

    public static class Builder
    {
        private final PrivateKey privateKey;
        private final String algorithmName;
        private final int keySizeInBits;
        private final byte[] encapsulation;

        private Builder(PrivateKey publicKey, String algorithmName, int keysize, byte[] encapsulation)
        {
            this.privateKey = publicKey;
            this.algorithmName = algorithmName;
            this.keySizeInBits = keysize;
            this.encapsulation = encapsulation;
        }

        public Builder withPrivate(PrivateKey publicKey)
        {
            return new Builder(publicKey, algorithmName, keySizeInBits, encapsulation);
        }

        public Builder withAlgorithmName(String algorithmName)
        {
            return new Builder(privateKey, algorithmName, keySizeInBits, encapsulation);
        }

        public Builder withKeySizeInBits(int keysize)
        {
            return new Builder(privateKey, algorithmName, keysize, encapsulation);
        }

        public Builder withEncapsulatedKey(byte[] encapsulatedKey)
        {
            return new Builder(privateKey, algorithmName, keySizeInBits, encapsulatedKey);
        }


        public KEMExtractSpec build()
        {
            return new KEMExtractSpec(privateKey, algorithmName, keySizeInBits, encapsulation);
        }
    }

}
