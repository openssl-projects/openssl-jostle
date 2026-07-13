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

public class AESBlockCipherSpi extends BlockCipherSpi
{

    public AESBlockCipherSpi()
    {
        this(null, null);
        osslMode = OSSLMode.ECB;
    }

    public AESBlockCipherSpi(OSSLCipher cipher)
    {
        super(cipher, "AES");
    }

    public AESBlockCipherSpi(OSSLCipher cipher, OSSLMode mode)
    {
        super(cipher, mode, "AES");
    }

    //
    // NI-binding constructors for the FIPS provider: identical behaviour,
    // bound to the FIPS interface library's BlockCipherNI.
    //
    public AESBlockCipherSpi(BlockCipherNI blockCipherNi)
    {
        super(blockCipherNi, null, null, "AES");
        osslMode = OSSLMode.ECB;
    }

    public AESBlockCipherSpi(BlockCipherNI blockCipherNi, OSSLCipher cipher, OSSLMode mode)
    {
        super(blockCipherNi, cipher, mode, "AES");
    }

    protected void determineOSSLCipher(int keySize) throws InvalidKeyException
    {

        if (osslMode == OSSLMode.XTS)
        {
            switch (keySize)
            {
                case 32:
                    osslCipher = OSSLCipher.AES128;
                    break;
                case 64:
                    osslCipher = OSSLCipher.AES256;
                    break;
                default:
                    throw new InvalidKeyException("XTS requires a 32-byte (AES-128) or 64-byte (AES-256) key");
            }
        }
        else
        {
            switch (keySize)
            {
                case 16:
                    osslCipher = OSSLCipher.AES128;
                    break;
                case 24:
                    osslCipher = OSSLCipher.AES192;
                    break;
                case 32:
                    this.osslCipher = OSSLCipher.AES256;
                    break;
                default:
                    throw new InvalidKeyException("unsupported key size, must be 16, 24 or 32 bytes");
            }
        }


        if (mandatedCipher != null && mandatedCipher != osslCipher)
        {
            throw new InvalidKeyException("invalid key size");
        }

    }


    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {

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
