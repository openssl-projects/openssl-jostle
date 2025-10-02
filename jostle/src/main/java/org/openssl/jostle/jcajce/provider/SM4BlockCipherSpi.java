/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider;

import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

class SM4BlockCipherSpi extends BlockCipherSpi
{

    SM4BlockCipherSpi()
    {
        super(null);
    }

    SM4BlockCipherSpi(OSSLCipher cipher)
    {
        super(cipher);
    }

    SM4BlockCipherSpi(OSSLCipher cipher, OSSLMode mode)
    {
        super(cipher, mode);
    }

    protected void determineOSSLCipher(int keySize) throws InvalidKeyException
    {

        switch (keySize)
        {
            case 16:
                osslCipher = OSSLCipher.SM4;
                break;
            default:
                throw new InvalidKeyException("unsupported key size, must be 16 bytes");
        }


        if (mandatedCipher != null && mandatedCipher != osslCipher)
        {
            throw new InvalidKeyException("invalid key size");
        }

    }


    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        determineOSSLCipher(key.getEncoded().length);
        super.engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        determineOSSLCipher(key.getEncoded().length);
        super.engineInit(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        determineOSSLCipher(key.getEncoded().length);
        // TODO: we should have a list of ParameterSpec to try here.
        try
        {
            super.engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), random);
        } catch (InvalidParameterSpecException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
    }
}
