/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.*;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class MLKEMKeyGenerator extends KeyGeneratorSpi
{

    private boolean extract;
    private final OSSLKeyType forcedKeyType;
    private AlgorithmParameterSpec parameterSpec;


    public MLKEMKeyGenerator(MLKEMParameterSpec spec)
    {
        this.forcedKeyType = spec.getKeyType();
    }

    public MLKEMKeyGenerator()
    {
        this.forcedKeyType = OSSLKeyType.NONE;
    }

    @Override
    protected void engineInit(SecureRandom random)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        if (params instanceof KEMExtractSpec)
        {
            PrivateKey key = ((KEMExtractSpec) params).getPrivateKey();
            if (key instanceof MLKEMPrivateKey)
            {
                extract = true;
                MLKEMPrivateKey kem = (MLKEMPrivateKey) key;
                if (forcedKeyType != OSSLKeyType.NONE && kem.getSpec().getType() != forcedKeyType)
                {
                    throw new InvalidAlgorithmParameterException("expected " + MLKEMParameterSpec.getSpecForOSSLType(forcedKeyType).getName() + " but got " + MLKEMParameterSpec.getSpecForOSSLType(kem.getSpec().getType()).getName());
                }
                parameterSpec = params;
                return;
            }
            throw new InvalidAlgorithmParameterException("Only MLKEMPrivateKey is supported");

        } else if (params instanceof KEMGenerateSpec)
        {
            PublicKey key = ((KEMGenerateSpec) params).getPublicKey();
            if (key instanceof MLKEMPublicKey)
            {
                extract = false;
                MLKEMPublicKey kem = (MLKEMPublicKey) key;
                if (forcedKeyType != OSSLKeyType.NONE && kem.getSpec().getType() != forcedKeyType)
                {
                    throw new InvalidAlgorithmParameterException("expected " + MLKEMParameterSpec.getSpecForOSSLType(forcedKeyType).getName() + " but got " + MLKEMParameterSpec.getSpecForOSSLType(kem.getSpec().getType()).getName());
                }
                parameterSpec = params;
                return;
            }
            throw new InvalidAlgorithmParameterException("Only MLKEMPublicKey is supported");
        } else
        {
            throw new InvalidAlgorithmParameterException("unsupported parameters " + params.getClass().getName());
        }
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SecretKey engineGenerateKey()
    {
        if (extract)
        {
            KEMExtractSpec extractSpec = (KEMExtractSpec) parameterSpec;
            PKEYKeySpec spec = ((OSSLKey) extractSpec.getPrivateKey()).getSpec();
            byte[] wrappedKey = extractSpec.getEncapsulation();
            long len = NISelector.SpecNI.handleErrors(NISelector.SpecNI.decap(spec.getReference(), null, wrappedKey, 0, wrappedKey.length, null, 0, 0));

            byte[] out = new byte[(int) len];
            len = NISelector.SpecNI.handleErrors(NISelector.SpecNI.decap(spec.getReference(), null, wrappedKey, 0, wrappedKey.length, out, 0, out.length));

            if (len != out.length)
            {
                throw new IllegalStateException("encapsulation length mismatch");
            }

            return new SecretKeyWithEncapsulation(new SecretKeySpec(out, extractSpec.getAlgorithmName()), wrappedKey);

        } else
        {
            KEMGenerateSpec generateSpec = (KEMGenerateSpec) parameterSpec;
            PKEYKeySpec spec = ((OSSLKey) generateSpec.getPublicKey()).getSpec();
            byte[] secret = new byte[generateSpec.getKeySizeInBits() / 8];
            long len = NISelector.SpecNI.handleErrors(NISelector.SpecNI.encap(spec.getReference(), null, secret, 0, secret.length, null, 0, 0));
            byte[] wrappedKey = new byte[(int) len];
            len = NISelector.SpecNI.handleErrors(NISelector.SpecNI.encap(spec.getReference(), null, secret, 0, secret.length, wrappedKey, 0, wrappedKey.length));

            if (len != wrappedKey.length)
            {
                throw new IllegalStateException("encapsulation length mismatch");
            }

            return new SecretKeyWithEncapsulation(new SecretKeySpec(secret, generateSpec.getAlgorithmName()), wrappedKey);
        }

    }
}
