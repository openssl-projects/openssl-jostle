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
 * PublicKeySpec for SLH-DSA.
 */
public class SLHDSAPublicKeySpec
    implements KeySpec
{
    private final SLHDSAParameterSpec params;
    private final byte[] publicData;

    /**
     * Base constructor.
     *
     * @param params the parameters to use with the passed in encoding.
     * @param publicData the long form encoding of the public key.
     */
    public SLHDSAPublicKeySpec(SLHDSAParameterSpec params, byte[] publicData)
    {
        this.params = params;
        this.publicData = Arrays.clone(publicData);
    }

    public SLHDSAParameterSpec getParameterSpec()
    {
        return params;
    }

    public byte[] getPublicData()
    {
        return Arrays.clone(publicData);
    }
}
