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
 * PublicKeySpec for ML-DSA.
 */
public class MLDSAPublicKeySpec
    implements KeySpec
{
    private final MLDSAParameterSpec params;
    private final byte[] publicData;

    /**
     * Base constructor.
     *
     * @param params the parameters to use with the passed in encoding.
     * @param publicData the long form encoding of the public key.
     */
    public MLDSAPublicKeySpec(MLDSAParameterSpec params, byte[] publicData)
    {
        this.params = params;
        this.publicData = Arrays.clone(publicData);
    }

    public MLDSAParameterSpec getParameterSpec()
    {
        return params;
    }

    public byte[] getPublicData()
    {
        return Arrays.clone(publicData);
    }
}
