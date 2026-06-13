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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * KeyPairGenerator for DSA.
 *
 * <p>Two initialisation surfaces:
 * <ul>
 *   <li>{@link #initialize(int)} — bit-size form. The supported sizes
 *       are the FIPS 186-4 modulus lengths {@code 1024} (with a
 *       160-bit q, the legacy FIPS 186-2 pairing), {@code 2048} and
 *       {@code 3072} (both with a 256-bit q). Domain parameters for a
 *       given size are generated once per JVM and cached — DSA
 *       parameter generation is a multi-second prime search, and
 *       sharing domain parameters across keys is standard practice
 *       (both the SUN provider and BouncyCastle do the same).</li>
 *   <li>{@link #initialize(AlgorithmParameterSpec)} with
 *       {@link DSAParameterSpec} — explicit (p, q, g), e.g. parameters
 *       produced by {@code AlgorithmParameterGenerator} or carried in
 *       a certificate. No caching; the supplied parameters are used
 *       directly.</li>
 * </ul>
 *
 * <p>DSA is a legacy algorithm (FIPS 186-5 deprecates DSA signature
 * generation); this implementation exists for interop with classic
 * protocol stacks (TLS &le; 1.2, CMS, OpenPGP). Note the OpenSSL FIPS
 * provider disallows DSA keygen/signing — against a FIPS-bound build
 * only verification works.
 */
public class DSAKeyPairGenerator extends KeyPairGenerator
{
    private static final DSAServiceNI dsaServiceNI = NISelector.DSAServiceNI;

    /** Default modulus size when no init is performed before generateKeyPair. */
    private static final int DEFAULT_KEY_SIZE = 2048;

    /**
     * Bounds for explicitly-supplied {@link DSAParameterSpec} domain
     * parameters (the {@link #initialize(int)} path is already restricted to
     * the FIPS 186-4 sizes). {@code p} below 1024 is broken; the 3072 ceiling
     * matches the largest size FIPS defines and caps the keygen cost. {@code q}
     * must be one of the FIPS 186-4 subgroup sizes (160/224/256) and strictly
     * smaller than {@code p}.
     */
    private static final int MIN_P_BITS = 1024;
    private static final int MAX_P_BITS = 3072;
    private static final int MIN_Q_BITS = 160;
    private static final int MAX_Q_BITS = 256;

    /**
     * Per-JVM cache of generated domain parameters, keyed by modulus
     * bit size. The cached {@link PKEYKeySpec} owns a parameters-only
     * EVP_PKEY; keygen runs against it without re-deriving (p, q, g).
     */
    private static final Map<Integer, PKEYKeySpec> PARAM_CACHE =
            new ConcurrentHashMap<Integer, PKEYKeySpec>();


    private int keySize = DEFAULT_KEY_SIZE;
    private DSAParameterSpec explicitParams = null;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());


    public DSAKeyPairGenerator()
    {
        super("DSA");
    }

    /**
     * FIPS 186-4 q size for a given modulus size, or -1 when the size
     * is unsupported.
     */
    private static int qBitsFor(int keySize)
    {
        switch (keySize)
        {
            case 1024:
                return 160;
            case 2048:
            case 3072:
                return 256;
            default:
                return -1;
        }
    }

    @Override
    public void initialize(int keysize, SecureRandom random)
    {
        // KeyPairGenerator.initialize(int) throws InvalidParameterException
        // (RuntimeException) for unsupported sizes per the JCA contract.
        if (qBitsFor(keysize) < 0)
        {
            throw new InvalidParameterException(
                    "DSA key size " + keysize + " is not supported. "
                            + "Supported sizes: 1024, 2048, 3072. "
                            + "For other parameters use DSAParameterSpec.");
        }
        this.keySize = keysize;
        this.explicitParams = null;
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec is null");
        }
        if (!(params instanceof DSAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException(
                    "expected DSAParameterSpec (got " + params.getClass().getName() + ")");
        }
        DSAParameterSpec dsaSpec = (DSAParameterSpec) params;
        if (dsaSpec.getP() == null || dsaSpec.getQ() == null || dsaSpec.getG() == null)
        {
            throw new InvalidAlgorithmParameterException(
                    "DSAParameterSpec p, q and g must all be non-null");
        }
        if (dsaSpec.getP().signum() <= 0 || dsaSpec.getQ().signum() <= 0
                || dsaSpec.getG().signum() <= 0)
        {
            throw new InvalidAlgorithmParameterException(
                    "DSAParameterSpec p, q and g must all be positive");
        }
        int pBits = dsaSpec.getP().bitLength();
        int qBits = dsaSpec.getQ().bitLength();
        if (pBits < MIN_P_BITS || pBits > MAX_P_BITS)
        {
            throw new InvalidAlgorithmParameterException(
                    "DSA prime size " + pBits + " bits is out of range ["
                            + MIN_P_BITS + ", " + MAX_P_BITS + "]");
        }
        if (qBits < MIN_Q_BITS || qBits > MAX_Q_BITS)
        {
            throw new InvalidAlgorithmParameterException(
                    "DSA subgroup size " + qBits + " bits is out of range ["
                            + MIN_Q_BITS + ", " + MAX_Q_BITS + "]");
        }
        if (qBits >= pBits)
        {
            throw new InvalidAlgorithmParameterException(
                    "DSA subgroup q (" + qBits + " bits) must be smaller than p ("
                            + pBits + " bits)");
        }
        this.explicitParams = dsaSpec;
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        initialize(params, null);
    }

    @Override
    public KeyPair generateKeyPair()
    {
        PKEYKeySpec paramsSpec;
        if (explicitParams != null)
        {
            paramsSpec = makeParamsSpec(explicitParams);
        }
        else
        {
            paramsSpec = cachedParamsSpec(keySize, random);
        }

        long ref;
        // Keep the params spec reachable across the native call so its
        // disposer can't free the parameters-only EVP_PKEY mid-keygen.
        synchronized (paramsSpec)
        {
            ref = dsaServiceNI.generateKeyPair(paramsSpec.getReference(), random);
        }
        if (ref == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }
        PKEYKeySpec spec = new PKEYKeySpec(ref, OSSLKeyType.DSA);
        return new KeyPair(new JODSAPublicKey(spec), new JODSAPrivateKey(spec));
    }

    /** Import explicit (p, q, g) as a parameters-only key spec. */
    static PKEYKeySpec makeParamsSpec(DSAParameterSpec dsaSpec)
    {
        BigInteger p = dsaSpec.getP();
        BigInteger q = dsaSpec.getQ();
        BigInteger g = dsaSpec.getG();
        long paramsRef = NISelector.DSAServiceNI.makeParamsFromComponents(
                DSAComponents.unsignedMagnitude(p),
                DSAComponents.unsignedMagnitude(q),
                DSAComponents.unsignedMagnitude(g));
        return new PKEYKeySpec(paramsRef, OSSLKeyType.DSA);
    }

    /**
     * Fetch (or generate and cache) the per-JVM domain parameters for
     * the given modulus size. The first caller per size pays the
     * paramgen cost; everyone after reuses the cached parameters.
     */
    private static PKEYKeySpec cachedParamsSpec(final int keySize, final RandSource random)
    {
        PKEYKeySpec cached = PARAM_CACHE.get(keySize);
        if (cached != null)
        {
            return cached;
        }
        long paramsRef = NISelector.DSAServiceNI.generateParameters(
                keySize, qBitsFor(keySize), random);
        PKEYKeySpec fresh = new PKEYKeySpec(paramsRef, OSSLKeyType.DSA);
        PKEYKeySpec winner = PARAM_CACHE.putIfAbsent(keySize, fresh);
        return winner != null ? winner : fresh;
    }
}
