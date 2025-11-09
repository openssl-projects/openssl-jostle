/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */
package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;
import org.openssl.jostle.util.Strings;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.interfaces.PBEKey;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class ScryptSecretKeyFactory extends SecretKeyFactorySpi
{


    public ScryptSecretKeyFactory()
    {

    }


    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof ScryptKeySpec)
        {
            ScryptKeySpec spec = (ScryptKeySpec) keySpec;

            byte[] rawKey = new byte[spec.getKeyLength() >> 3];


            NISelector.KdfNI.handleErrorCodes(NISelector.KdfNI.scrypt(
                    Strings.toUTF8ByteArray(spec.getPassword()),
                    spec.getSalt(),
                    spec.getCostParameter(),
                    spec.getBlockSize(),
                    spec.getParallelizationParameter(),
                    rawKey, 0, rawKey.length));


            String name = "ScryptWithUTF8";

            return new JOScryptKey(name, spec.getPassword(), spec.getSalt(), spec.getCostParameter(), spec.getBlockSize(), spec.getParallelizationParameter(), rawKey);

        }

        throw new InvalidKeySpecException("unsupported KeySpec " + keySpec.getClass().getName());
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException
    {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException
    {
        if (key == null)
        {
            throw new InvalidKeyException("key parameter is null");
        }

        if (key instanceof PBEKey)
        {
            PBEKey pbeKey = (PBEKey) key;
            return new JOPBEKey(key.getAlgorithm(), pbeKey.getPassword(), pbeKey.getSalt(), pbeKey.getIterationCount(), pbeKey.getEncoded());
        }

        throw new InvalidKeyException("unsupported key type: " + key.getClass());

    }
}
