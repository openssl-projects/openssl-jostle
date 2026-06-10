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

package org.openssl.jostle.jcajce.provider.dsa;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

/**
 * {@code AlgorithmParameterGenerator} for DSA. Generates FIPS 186-4
 * domain parameters (p, q, g) natively via {@code EVP_PKEY_paramgen}
 * and returns them as an {@code AlgorithmParameters("DSA")} instance
 * initialised with the resulting {@link DSAParameterSpec}.
 *
 * <p>Supported modulus sizes mirror {@link DSAKeyPairGenerator}:
 * 1024 (q = 160), 2048 and 3072 (q = 256). Parameter generation is a
 * multi-second prime search for the larger sizes.
 */
public class DSAAlgorithmParameterGenerator extends AlgorithmParameterGeneratorSpi
{
    /** Default modulus size when no engineInit is performed. */
    private static final int DEFAULT_KEY_SIZE = 2048;

    private int pBits = DEFAULT_KEY_SIZE;
    private int qBits = 256;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());


    @Override
    protected void engineInit(int size, SecureRandom random)
    {
        // AlgorithmParameterGenerator.init(int) throws
        // InvalidParameterException (RuntimeException) per the JCA contract.
        switch (size)
        {
            case 1024:
                this.qBits = 160;
                break;
            case 2048:
            case 3072:
                this.qBits = 256;
                break;
            default:
                throw new InvalidParameterException(
                        "DSA parameter size " + size + " is not supported. "
                                + "Supported sizes: 1024, 2048, 3072.");
        }
        this.pBits = size;
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        // The JCA-standard generation spec for DSA is the size-only
        // form; there is no standard DSAGenParameterSpec on the Java 8
        // baseline this provider compiles against.
        throw new InvalidAlgorithmParameterException(
                "DSA parameter generation takes a key size, not an AlgorithmParameterSpec; "
                        + "use init(int, SecureRandom)");
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters()
    {
        long paramsRef = NISelector.DSAServiceNI.generateParameters(pBits, qBits, random);
        PKEYKeySpec paramsSpec = new PKEYKeySpec(paramsRef, OSSLKeyType.DSA);
        DSAParameterSpec spec = DSAComponents.getParams(paramsSpec);
        try
        {
            // Resolve from the installed providers — if Jostle is
            // registered this returns our DSAAlgorithmParameters (which
            // delegates the codec to the platform); on a bare JVM the
            // SUN provider serves directly.
            AlgorithmParameters params = AlgorithmParameters.getInstance("DSA");
            params.init(spec);
            return params;
        }
        catch (Exception e)
        {
            throw new ProviderException("unable to materialise DSA AlgorithmParameters", e);
        }
    }
}
