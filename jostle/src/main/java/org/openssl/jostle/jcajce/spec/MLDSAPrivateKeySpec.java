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

import java.security.spec.KeySpec;

/**
 * PrivateKeySpec for ML-DSA.
 */
public class MLDSAPrivateKeySpec
    implements KeySpec
{
    private final byte[] data;
    private final byte[] publicData;
    private final MLDSAParameterSpec params;
    private final boolean isSeed;

    public MLDSAPrivateKeySpec(MLDSAParameterSpec params, byte[] seed)
    {
       if (seed.length != 32)
       {
            throw new IllegalArgumentException("incorrect length for seed");
       }

       this.isSeed = true;
       this.params = params;
       this.data = Arrays.clone(seed);
       this.publicData = null;
    }

    /**
     * Create a KeySpec using the long form private and public data.
     *
     * @param params the parameter set to use with the encodings.
     * @param privateData the long form private key.
     * @param publicData the long form public key - may be null.
     */
    public MLDSAPrivateKeySpec(MLDSAParameterSpec params, byte[] privateData, byte[] publicData)
    {
       this.isSeed = false;
       this.params = params;
       this.data = Arrays.clone(privateData);
       this.publicData = Arrays.clone(publicData);
    }

    public boolean isSeed()
    {
        return isSeed;
    }

    public MLDSAParameterSpec getParameterSpec()
    {
        return params;
    }

    public byte[] getSeed()
    {
        if (isSeed())
        {
            return Arrays.clone(data);
        }

        throw new IllegalStateException("KeySpec represents long form");
    }

    public byte[] getPrivateData()
    {
        if (!isSeed())
        {
            return Arrays.clone(data);
        }

        throw new IllegalStateException("KeySpec represents seed");
    }

    public byte[] getPublicData()
    {
        if (!isSeed())
        {
            return Arrays.clone(publicData);
        }

        throw new IllegalStateException("KeySpec represents long form");
    }
}
