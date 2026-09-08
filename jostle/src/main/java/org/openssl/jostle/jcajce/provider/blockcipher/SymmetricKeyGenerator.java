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
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KeyGenerator for a symmetric cipher whose key is simply N random bytes.
 *
 * <p>Parameterised rather than copied per algorithm. {@code AESKeyGenerator},
 * {@code DESedeKeyGenerator} and {@code ChaCha20KeyGenerator} predate this and
 * each carry algorithm-specific behaviour — DESede's parity and 2-key handling,
 * AES's fixed-size OID variants — which is why they are not folded in here. For
 * ARIA, Camellia and SM4 there is nothing algorithm-specific to carry, so three
 * more near-identical files would only be three more places to drift.
 */
public class SymmetricKeyGenerator extends KeyGeneratorSpi
{
    private final String algorithm;
    private final int[] permittedSizes;
    private final SecureRandom providerRandom;

    private SecureRandom random;
    private int keySize;

    public SymmetricKeyGenerator(String algorithm, int defaultSize, int... permittedSizes)
    {
        this(algorithm, defaultSize, null, permittedSizes);
    }

    /**
     * Default-SecureRandom-injecting form for the FIPS provider: key bytes
     * default to the supplied source, and a later {@code init} that supplies a
     * SecureRandom not backed by that provider is overridden back to it. Mirrors
     * {@code AESKeyGenerator}'s FIPS constructors.
     */
    public SymmetricKeyGenerator(String algorithm, int defaultSize, SecureRandom providerRandom,
                                 int... permittedSizes)
    {
        this.algorithm = algorithm;
        this.permittedSizes = permittedSizes.clone();
        this.providerRandom = providerRandom;
        this.random = providerRandom != null ? providerRandom : CryptoServicesRegistrar.getSecureRandom();
        this.keySize = defaultSize;
    }

    @Override
    protected void engineInit(SecureRandom random)
    {
        this.random = CryptoServicesRegistrar.resolveProviderRandom(random, providerRandom);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        // JCA declares InvalidAlgorithmParameterException for this overload, so
        // an unchecked refusal would mean a caller's catch never fires (MT-48a).
        throw new InvalidAlgorithmParameterException(
                params == null
                        ? "no AlgorithmParameterSpec is supported; use init(keysize) or init(random)"
                        : "unsupported parameters " + params.getClass().getName()
                                + "; use init(keysize) or init(random)");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random)
    {
        boolean permitted = false;
        for (int size : permittedSizes)
        {
            if (size == keysize)
            {
                permitted = true;
                break;
            }
        }
        if (!permitted)
        {
            // MT-48c: InvalidParameterException is what JCA names for
            // KeyGenerator.init(int), and it extends IllegalArgumentException,
            // so this widens what callers catch rather than narrowing it.
            throw new InvalidParameterException("key size must be " + describeSizes());
        }

        this.random = CryptoServicesRegistrar.resolveProviderRandom(random, providerRandom);
        this.keySize = keysize;
    }

    @Override
    protected SecretKey engineGenerateKey()
    {
        byte[] keyBytes = new byte[keySize >> 3];
        random.nextBytes(keyBytes);
        try
        {
            // ProvSecretKeySpec clones its input; scrub the local plaintext copy
            // so it does not linger on the heap until GC.
            return new ProvSecretKeySpec(keyBytes, algorithm);
        }
        finally
        {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    private String describeSizes()
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < permittedSizes.length; i++)
        {
            if (i > 0)
            {
                sb.append(i == permittedSizes.length - 1 ? " or " : ", ");
            }
            sb.append(permittedSizes[i]);
        }
        return sb.toString();
    }
}
