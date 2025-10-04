/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

class ARIABlockCipherSpi extends BlockCipherSpi
{

     ARIABlockCipherSpi()
    {
        super(null);
    }

     ARIABlockCipherSpi(OSSLCipher cipher) {
        super(cipher);
    }

     ARIABlockCipherSpi(OSSLCipher cipher, OSSLMode mode) {
        super(cipher, mode);
    }

    protected void determineOSSLCipher(int keySize) throws InvalidKeyException
    {

        switch (keySize)
        {
            case 16:
                osslCipher = OSSLCipher.ARIA128;
                break;
            case 24:
                osslCipher = OSSLCipher.ARIA192;
                break;
            case 32:
                this.osslCipher = OSSLCipher.ARIA256;
                break;
            default:
                throw new InvalidKeyException("unsupported key size, must be 16, 24 or 32 bytes");
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
        }
        catch (InvalidParameterSpecException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
    }
}
