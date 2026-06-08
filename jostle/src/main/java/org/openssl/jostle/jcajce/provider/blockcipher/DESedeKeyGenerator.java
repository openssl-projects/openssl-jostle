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
 * JCE KeyGenerator SPI for DESede (3-key Triple DES). Always
 * generates a 24-byte raw key — the 168-bit and 192-bit key-size
 * requests are both treated as 3-key TDES per JCE convention.
 * 2-key TDES (112/128-bit) is intentionally not supported: the
 * corresponding cipher (DES-EDE) lives in OpenSSL's legacy provider
 * and is out of scope.
 */
public class DESedeKeyGenerator extends KeyGeneratorSpi
{
    /**
     * Raw key size in bytes for 3-key TDES.
     */
    private static final int KEY_BYTES = 24;

    private SecureRandom random;

    public DESedeKeyGenerator()
    {
        // CLAUDE.md: SecureRandom construction blocks on entropy seeding;
        // the registrar returns a cached instance.
        random = CryptoServicesRegistrar.getSecureRandom();
    }

    @Override
    protected void engineInit(SecureRandom random)
    {
        if (random == null)
        {
            throw new IllegalArgumentException("random is null");
        }
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        throw new UnsupportedOperationException("not implemented, use keySize, random");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random)
    {
        // JCE convention for DESede: 168 (effective key bits) and 192
        // (full bits including parity) both denote 3-key TDES. Both
        // produce a 24-byte raw key. Anything else — including 112/128
        // for 2-key TDES — is rejected.
        if (keysize != 168 && keysize != 192)
        {
            throw new IllegalArgumentException("key size must be 168 or 192 bits for DESede (3-key Triple DES)");
        }

        if (random == null)
        {
            throw new IllegalArgumentException("random is null");
        }

        this.random = random;
    }

    @Override
    protected SecretKey engineGenerateKey()
    {
        byte[] keyBytes = new byte[KEY_BYTES];
        random.nextBytes(keyBytes);
        return new ProvSecretKeySpec(keyBytes, "DESede");
    }
}
