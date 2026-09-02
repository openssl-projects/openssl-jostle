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

    private final SecureRandom providerRandom;

    private SecureRandom random;

    public DESedeKeyGenerator()
    {
        // CLAUDE.md: SecureRandom construction blocks on entropy seeding;
        // the registrar returns a cached instance.
        this.providerRandom = null;
        this.random = CryptoServicesRegistrar.getSecureRandom();
    }

    /**
     * Default-SecureRandom-injecting constructor for the FIPS provider, the
     * exact shape {@link AESKeyGenerator} uses: key bytes default to the
     * supplied source (the FIPS module's DRBG via the JSLFIPS SecureRandom
     * service), and a later {@code init(...)} supplying a SecureRandom NOT
     * backed by that provider is overridden back to it — so
     * {@code KeyGenerator.init(int)}'s JCE-injected JVM default cannot
     * silently pull key bytes from outside the FIPS boundary. A same-provider
     * SecureRandom is honoured, and the check can be disabled via
     * {@code CryptoServicesRegistrar.ENFORCE_PROVIDER_RANDOM}.
     */
    public DESedeKeyGenerator(SecureRandom random)
    {
        this.providerRandom = random;
        this.random = random;
    }

    @Override
    protected void engineInit(SecureRandom random)
    {
        // MT-48d, and the ONLY loosening in this arc: a null SecureRandom means
        // "use the default", which is what BouncyCastle and the JDK both do and
        // what the overload's contract implies - it declares no exception. We
        // were alone in refusing. resolveProviderRandom already supplies the
        // provider default for null, so removing the check is the whole fix.
        this.random = CryptoServicesRegistrar.resolveProviderRandom(random, providerRandom);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        // JCA declares InvalidAlgorithmParameterException for this overload, so
        // an unchecked refusal means a caller's catch never fires (MT-48a).
        // "No parameters are supported" is still the answer; only the type of
        // the refusal changes.
        throw new InvalidAlgorithmParameterException(
                params == null
                        ? "no AlgorithmParameterSpec is supported; use init(keysize) or init(random)"
                        : "unsupported parameters " + params.getClass().getName()
                                + "; use init(keysize) or init(random)");
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
            // MT-48c: the JCA-named type for init(int).
            throw new InvalidParameterException("key size must be 168 or 192 bits for DESede (3-key Triple DES)");
        }

        // MT-48d: a null SecureRandom is the caller asking for the default.
        this.random = CryptoServicesRegistrar.resolveProviderRandom(random, providerRandom);
    }

    @Override
    protected SecretKey engineGenerateKey()
    {
        byte[] keyBytes = new byte[KEY_BYTES];
        random.nextBytes(keyBytes);
        try
        {
            // ProvSecretKeySpec clones its input; scrub the local plaintext
            // key copy so it does not linger on the heap until GC.
            return new ProvSecretKeySpec(keyBytes, "DESede");
        }
        finally
        {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }
}
