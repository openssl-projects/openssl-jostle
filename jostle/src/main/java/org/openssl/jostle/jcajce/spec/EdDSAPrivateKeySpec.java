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

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;

import java.security.spec.KeySpec;

public class EdDSAPrivateKeySpec implements KeySpec
{
    private final byte[] data;
    private final byte[] publicData;
    private final EdDSAParameterSpec params;

    public EdDSAPrivateKeySpec(EdDSAParameterSpec params, byte[] privateData, byte[] publicData)
    {
        this.params = params;
        this.data = Arrays.clone(privateData);
        this.publicData = Arrays.clone(publicData);
    }

    public EdDSAParameterSpec getParameterSpec()
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
