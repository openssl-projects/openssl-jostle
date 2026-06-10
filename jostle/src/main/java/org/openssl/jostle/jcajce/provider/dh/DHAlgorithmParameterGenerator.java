/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.dh;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import javax.crypto.spec.DHParameterSpec;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * {@code AlgorithmParameterGenerator} for DH. Generates PKCS#3-style
 * safe-prime domain parameters (p, g) natively via
 * {@code EVP_PKEY_paramgen} and returns them as an
 * {@code AlgorithmParameters("DH")} instance initialised with the
 * resulting {@link DHParameterSpec}.
 *
 * <p>Sizes follow the legacy JCA contract: 512–8192 bits, a multiple
 * of 64. Safe-prime generation is a prime search — slow at 2048 bits
 * and above. For the RFC 7919 named groups use
 * {@code KeyPairGenerator.initialize(int)} instead, which is instant.
 */
public class DHAlgorithmParameterGenerator extends AlgorithmParameterGeneratorSpi
{
    /** Default modulus size when no engineInit is performed. */
    private static final int DEFAULT_KEY_SIZE = 2048;

    private int pBits = DEFAULT_KEY_SIZE;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());


    @Override
    protected void engineInit(int size, SecureRandom random)
    {
        // AlgorithmParameterGenerator.init(int) throws
        // InvalidParameterException (RuntimeException) per the JCA contract.
        if (size < 512 || size > 8192 || (size % 64) != 0)
        {
            throw new InvalidParameterException(
                    "DH parameter size " + size + " is not supported. "
                            + "Sizes must be 512..8192 and a multiple of 64.");
        }
        this.pBits = size;
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        // The JCA-standard generation spec for DH is the size-only
        // form; DHGenParameterSpec (prime size + exponent size) is not
        // supported by the OpenSSL paramgen surface this delegates to.
        throw new InvalidAlgorithmParameterException(
                "DH parameter generation takes a key size, not an AlgorithmParameterSpec; "
                        + "use init(int, SecureRandom)");
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters()
    {
        long paramsRef = NISelector.DHServiceNI.generateParameters(pBits, random);
        PKEYKeySpec paramsSpec = new PKEYKeySpec(paramsRef, OSSLKeyType.DH);
        DHParameterSpec spec = DHComponents.getParams(paramsSpec);
        try
        {
            // Resolve from the installed providers — if Jostle is
            // registered this returns our DHAlgorithmParameters (which
            // delegates the codec to the platform); on a bare JVM
            // SunJCE serves directly.
            AlgorithmParameters params = AlgorithmParameters.getInstance("DH");
            params.init(spec);
            return params;
        }
        catch (Exception e)
        {
            throw new ProviderException("unable to materialise DH AlgorithmParameters", e);
        }
    }
}
