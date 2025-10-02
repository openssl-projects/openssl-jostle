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
 * PrivateKeySpec for SLH-DSA.
 */
public class SLHDSAPrivateKeySpec
        implements KeySpec
{
    private final byte[] data;
    private final byte[] publicData;
    private final SLHDSAParameterSpec params;

    public SLHDSAPrivateKeySpec(SLHDSAParameterSpec params, byte[] data)
    {
        if (data.length != 32)
        {
            throw new IllegalArgumentException("incorrect length for seed");
        }


        this.params = params;
        this.data = Arrays.clone(data);
        this.publicData = null;
    }

    /**
     * Create a KeySpec using the long form private and public data.
     *
     * @param params      the parameter set to use with the encodings.
     * @param privateData the long form private key.
     * @param publicData  the long form public key - may be null.
     */
    public SLHDSAPrivateKeySpec(SLHDSAParameterSpec params, byte[] privateData, byte[] publicData)
    {

        this.params = params;
        this.data = Arrays.clone(privateData);
        this.publicData = Arrays.clone(publicData);
    }


    public SLHDSAParameterSpec getParameterSpec()
    {
        return params;
    }


    public byte[] getPrivateData()
    {

        return Arrays.clone(data);


    }

    public byte[] getPublicData()
    {

        return Arrays.clone(publicData);


    }
}
