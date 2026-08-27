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

import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

class JOMLXKEMPublicKey extends AsymmetricKeyImpl implements MLXKEMPublicKey
{
    // Instance field, not a NISelector static: the key is bound to whichever
    // interface library created its PKEY - NISelector for JSL, FIPSNISelector
    // for JSLFIPS - so it must not reach for the base provider's NI.
    private final MLXKEMServiceNI mlxkemServiceNI;

    JOMLXKEMPublicKey(PKEYKeySpec spec)
    {
        this(NISelector.MLXKEMServiceNI, spec);
    }

    JOMLXKEMPublicKey(MLXKEMServiceNI mlxkemServiceNI, PKEYKeySpec spec)
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
     * Null - there is no encoding for a hybrid key. Per the
     * {@link java.security.Key} contract, a null format is how a key reports
     * that it does not support encoding, and it must be paired with a null
     * {@link #getEncoded()}.
     */
    @Override
    public String getFormat()
    {
        return null;
    }

    /**
     * Null. No provider registers a SubjectPublicKeyInfo encoder for these
     * groups - {@code i2d_PUBKEY} returns -1 - so there is nothing truthful to
     * return. Use {@link #getPublicData()} for the raw wire share.
     */
    @Override
    public byte[] getEncoded()
    {
        return null;
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

    @Override
    public byte[] getPublicData()
    {
        synchronized (this)
        {
            int len = mlxkemServiceNI.getPublicKey(spec.getReference(), null);
            byte[] out = new byte[len];
            mlxkemServiceNI.getPublicKey(spec.getReference(), out);

            return out;
        }
    }
}
