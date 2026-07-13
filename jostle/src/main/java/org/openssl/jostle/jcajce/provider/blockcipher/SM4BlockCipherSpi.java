/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;


import org.openssl.jostle.util.Arrays;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SM4BlockCipherSpi extends BlockCipherSpi
{

    public SM4BlockCipherSpi()
    {
        super(null, "SM4");
    }

    public SM4BlockCipherSpi(OSSLCipher cipher)
    {
        super(cipher, "SM4");
    }

    public SM4BlockCipherSpi(OSSLCipher cipher, OSSLMode mode)
    {
        super(cipher, mode, "SM4");
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
        validateKeyAlg(key);
        // Capture the encoded key once so the transient copy getEncoded()
        // returns can be zeroized; reading .length off a throwaway getEncoded()
        // leaves an un-scrubbed key copy on the heap (the base engineInit
        // makes and scrubs its own copy for the actual native init).
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("key has no encoded form");
        }
        try
        {
            determineOSSLCipher(encoded.length);
        }
        finally
        {
            Arrays.clear(encoded);
        }
        super.engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (!"SM4".equalsIgnoreCase(key.getAlgorithm()))
        {
            throw new InvalidKeyException("unsupported key algorithm " + key.getAlgorithm());
        }
        // Capture the encoded key once so the transient copy getEncoded()
        // returns can be zeroized; reading .length off a throwaway getEncoded()
        // leaves an un-scrubbed key copy on the heap (the base engineInit
        // makes and scrubs its own copy for the actual native init).
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("key has no encoded form");
        }
        try
        {
            determineOSSLCipher(encoded.length);
        }
        finally
        {
            Arrays.clear(encoded);
        }
        super.engineInit(opmode, key, params, random);
    }

    // engineInit(int, Key, AlgorithmParameters, SecureRandom) is intentionally NOT
    // overridden: the base implementation already tries every supported spec
    // (IvParameterSpec and GCMParameterSpec) and then dispatches to the
    // AlgorithmParameterSpec overload above — which performs determineOSSLCipher.
    // Overriding it here previously narrowed support to IvParameterSpec only,
    // which broke GCM decryption from an AlgorithmParameters (as used by CMS).
}
