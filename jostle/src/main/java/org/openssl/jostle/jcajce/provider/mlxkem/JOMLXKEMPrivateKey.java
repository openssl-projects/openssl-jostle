/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlxkem;

import org.openssl.jostle.jcajce.interfaces.MLXKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

class JOMLXKEMPrivateKey extends AsymmetricKeyImpl implements MLXKEMPrivateKey
{
    // Instance field, not a NISelector static: the key is bound to whichever
    // interface library created its PKEY - NISelector for JSL, FIPSNISelector
    // for JSLFIPS - so it must not reach for the base provider's NI.
    private final MLXKEMServiceNI mlxkemServiceNI;

    JOMLXKEMPrivateKey(PKEYKeySpec spec)
    {
        this(NISelector.MLXKEMServiceNI, spec);
    }

    JOMLXKEMPrivateKey(MLXKEMServiceNI mlxkemServiceNI, PKEYKeySpec spec)
    {
        super(spec);
        this.mlxkemServiceNI = mlxkemServiceNI;
    }

    @Override
    public String getAlgorithm()
    {
        return getType().getAlgorithmName();
    }

    /**
     * Null - see {@link JOMLXKEMPublicKey#getFormat()}.
     */
    @Override
    public String getFormat()
    {
        return null;
    }

    /**
     * Null. There is no PKCS#8 form for a hybrid key, and no raw private
     * getter either: the provider releases the private material for the
     * X25519 / X448 variants and refuses it for the SecP ones, so an accessor
     * would be usable on half the family only.
     */
    @Override
    public byte[] getEncoded()
    {
        return null;
    }

    @Override
    public MLXKEMPublicKey getPublicKey()
    {
        return new JOMLXKEMPublicKey(mlxkemServiceNI, spec);
    }

    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    public MLXKEMParameterSpec getParameterSpec()
    {
        MLXKEMParameterSpec parameterSpec = MLXKEMParameterSpec.getSpecForOSSLType(spec.getType());

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());
        }
        return parameterSpec;
    }
}
