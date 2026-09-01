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

import org.openssl.jostle.jcajce.provider.NISelector;

import org.openssl.jostle.util.Arrays;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class CAMELLIABlockCipherSpi extends BlockCipherSpi
{

    public CAMELLIABlockCipherSpi()
    {
        super(null, "CAMELLIA");
        // Form-1 lookup of the bare name never calls engineSetMode, so
        // without a default osslMode is null and engineInit NPEs. Assigned,
        // not passed to super: that would also mandate the mode and break the
        // form-4 path.
        osslMode = OSSLMode.ECB;
    }

    public CAMELLIABlockCipherSpi(OSSLCipher cipher)
    {
        super(cipher, "CAMELLIA");
    }

    public CAMELLIABlockCipherSpi(OSSLCipher cipher, OSSLMode mode)
    {
        super(cipher, mode, "CAMELLIA");
    }

    //
    // Provider-binding constructor (MT-10) - see AESBlockCipherSpi.
    //
    public CAMELLIABlockCipherSpi(java.security.Provider providerInstance)
    {
        this(null, null, providerInstance);
        osslMode = OSSLMode.ECB;
    }

    public CAMELLIABlockCipherSpi(OSSLCipher cipher, OSSLMode mode,
                                  java.security.Provider providerInstance)
    {
        super(NISelector.BlockCipherNI, cipher, mode, "CAMELLIA", providerInstance);
    }

    protected void determineOSSLCipher(int keySize) throws InvalidKeyException
    {

        switch (keySize)
        {
            case 16:
                osslCipher = OSSLCipher.CAMELLIA128;
                break;
            case 24:
                osslCipher = OSSLCipher.CAMELLIA192;
                break;
            case 32:
                this.osslCipher = OSSLCipher.CAMELLIA256;
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
        // Ahead of the dereference below: a null key is an InvalidKeyException,
        // never an NPE.
        requireKey(key);

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
        // Ahead of the dereference below: a null key is an InvalidKeyException,
        // never an NPE.
        requireKey(key);

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
