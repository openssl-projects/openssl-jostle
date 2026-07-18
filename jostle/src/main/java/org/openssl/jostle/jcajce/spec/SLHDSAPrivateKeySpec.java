/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
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

    /**
     * Create a KeySpec from the raw private key encoding for the given
     * parameter set. The encoding is the SLH-DSA private key in either
     * seed form (3n bytes) or long form (4n bytes); the exact length is
     * validated against the parameter set by the native decoder when the
     * KeyFactory builds a key, so no length is transcribed here (OpenSSL is
     * the single source of truth for the per-variant sizes).
     *
     * @param params the parameter set to use with the encoding.
     * @param data   the raw private key encoding.
     */
    public SLHDSAPrivateKeySpec(SLHDSAParameterSpec params, byte[] data)
    {
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
