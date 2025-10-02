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

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

public class KEMGenerateSpec implements AlgorithmParameterSpec
{
    private final PublicKey publicKey;
    private final String algorithmName;
    private final int keySizeInBits;

    private KEMGenerateSpec(PublicKey publicKey, String algorithmName, int keySizeInBits)
    {
        this.publicKey = publicKey;
        this.algorithmName = algorithmName;
        this.keySizeInBits = keySizeInBits;
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public int getKeySizeInBits()
    {
        return keySizeInBits;
    }

    public static Builder builder()
    {
        return new Builder(null, null, 256);
    }

    public static class Builder
    {
        private final PublicKey publicKey;
        private final String algorithmName;
        private final int keySizeInBits;

        private Builder(PublicKey publicKey, String algorithmName, int keysize)
        {
            this.publicKey = publicKey;
            this.algorithmName = algorithmName;
            this.keySizeInBits = keysize;
        }

        public Builder withPublicKey(PublicKey publicKey)
        {
            return new Builder(publicKey, algorithmName, keySizeInBits);
        }

        public Builder withAlgorithmName(String algorithmName)
        {
            return new Builder(publicKey, algorithmName, keySizeInBits);
        }

        public Builder withKeySizeInBits(int keysize)
        {
            return new Builder(publicKey, algorithmName, keysize);
        }

        public KEMGenerateSpec build()
        {
            return new KEMGenerateSpec(publicKey, algorithmName, keySizeInBits);
        }
    }

}
