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


import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.ProvSecretKeySpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KeyGenerator for ChaCha20 / ChaCha20-Poly1305. RFC 8439 fixes the key at
 * 256 bits, so this generator only ever produces 32-byte keys (tagged
 * "ChaCha20" — the same key type the raw and AEAD SPIs accept).
 */
public class ChaCha20KeyGenerator extends KeyGeneratorSpi
{
    private static final int KEY_SIZE_BITS = 256;

    private SecureRandom random;

    public ChaCha20KeyGenerator()
    {
        random = CryptoServicesRegistrar.getSecureRandom();
    }

    @Override
    protected void engineInit(SecureRandom random)
    {
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        throw new UnsupportedOperationException("not implemented, use keySize, random");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random)
    {
        if (keysize != KEY_SIZE_BITS)
        {
            throw new IllegalArgumentException("ChaCha20 key size must be 256 bits");
        }
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
    }

    @Override
    protected SecretKey engineGenerateKey()
    {
        byte[] keyBytes = new byte[KEY_SIZE_BITS >> 3];
        random.nextBytes(keyBytes);
        return new ProvSecretKeySpec(keyBytes, "ChaCha20");
    }
}
