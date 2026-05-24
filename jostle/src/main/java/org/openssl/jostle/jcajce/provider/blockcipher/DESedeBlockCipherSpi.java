/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;


import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * JCE Cipher SPI for 3-key Triple DES (DES-EDE3). Only ECB and CBC
 * modes are supported — those are the variants OpenSSL 3.5 keeps in
 * the default provider. The CFB* and OFB DES-EDE3 modes live in the
 * legacy provider and are intentionally not exposed here.
 */
public class DESedeBlockCipherSpi extends BlockCipherSpi
{
    /**
     * The DES-EDE3 key algorithm name. JCE convention accepts both
     * "DESede" (the registered Cipher name) and the alias "TripleDES"
     * for the SecretKey's algorithm field; both are honoured here.
     */
    private static final String DESEDE = "DESede";
    private static final String TRIPLE_DES = "TripleDES";

    public DESedeBlockCipherSpi()
    {
        super(null, DESEDE);
        osslMode = OSSLMode.ECB;
    }

    public DESedeBlockCipherSpi(OSSLCipher cipher)
    {
        super(cipher, DESEDE);
    }

    public DESedeBlockCipherSpi(OSSLCipher cipher, OSSLMode mode)
    {
        super(cipher, mode, DESEDE);
    }

    protected void determineOSSLCipher(int keySize) throws InvalidKeyException
    {
        // 3-key TDES expects a 24-byte key. We intentionally do NOT
        // accept the 16-byte 2-key shorthand (some providers expand it
        // to a 24-byte EDE3 key by repeating K1 as K3); the 2-key
        // variant maps to DES-EDE in legacy and is out of scope here.
        if (keySize != 24)
        {
            throw new InvalidKeyException("unsupported key size, DESede requires a 24-byte key");
        }

        osslCipher = OSSLCipher.DES_EDE3;

        if (mandatedCipher != null && mandatedCipher != osslCipher)
        {
            throw new InvalidKeyException("invalid key size");
        }
    }


    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        validateKeyAlg(key);
        determineOSSLCipher(key.getEncoded().length);
        super.engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        validateKeyAlg(key);
        determineOSSLCipher(key.getEncoded().length);
        super.engineInit(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        validateKeyAlg(key);
        determineOSSLCipher(key.getEncoded().length);
        try
        {
            super.engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), random);
        }
        catch (InvalidParameterSpecException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
    }

    /**
     * Accepts both "DESede" and the JCE-standard alias "TripleDES" as
     * the key's reported algorithm — applications that wire keys from
     * different libraries shouldn't have to translate.
     */
    @Override
    protected void validateKeyAlg(Key key) throws InvalidKeyException
    {
        String alg = key.getAlgorithm();
        if (DESEDE.equals(alg) || TRIPLE_DES.equals(alg))
        {
            return;
        }
        throw new InvalidKeyException("unsupported key algorithm " + alg);
    }
}
