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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KeyPairGenerator for finite-field Diffie-Hellman.
 *
 * <p>Two initialisation surfaces:
 * <ul>
 *   <li>{@link #initialize(int)} — bit-size form. The supported sizes
 *       are 2048, 3072, 4096, 6144 and 8192, each mapped to the
 *       matching RFC 7919 named group ({@code ffdhe2048} …
 *       {@code ffdhe8192}). Named-group keygen is instant — no prime
 *       search — and the RFC 7919 groups are the modern interop
 *       baseline (TLS 1.3 FFDHE). Sizes without an RFC 7919 group
 *       (512/768/1024/1536) are deliberately rejected here; generate
 *       parameters via {@code AlgorithmParameterGenerator} or supply
 *       an explicit {@link DHParameterSpec} instead.</li>
 *   <li>{@link #initialize(AlgorithmParameterSpec)} with
 *       {@link DHParameterSpec} — explicit (p, g), e.g. parameters
 *       negotiated by a protocol or produced by
 *       {@code AlgorithmParameterGenerator}.</li>
 * </ul>
 */
public class DHKeyPairGenerator extends KeyPairGenerator
{
    private static final DHServiceNI dhServiceNI = NISelector.DHServiceNI;

    /** Default modulus size when no init is performed before generateKeyPair. */
    private static final int DEFAULT_KEY_SIZE = 2048;

    /**
     * Security floor / DoS ceiling for an explicitly-supplied {@code p}
     * (the {@link #initialize(int)} path is already restricted to the RFC 7919
     * named groups). 1024 is the absolute floor — DH below it is broken
     * cryptographically; 16384 caps the modexp cost so a multi-million-bit
     * modulus can't turn keygen into a CPU sink. Mirrors
     * {@code RSAKeyPairGenerator}'s named bounds.
     */
    private static final int MIN_P_BITS = 1024;
    private static final int MAX_P_BITS = 16384;


    private int keySize = DEFAULT_KEY_SIZE;
    private DHParameterSpec explicitParams = null;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());


    public DHKeyPairGenerator()
    {
        super("DH");
    }

    /**
     * RFC 7919 group name for a given modulus size, or null when the
     * size has no ffdhe group.
     */
    static String groupFor(int keySize)
    {
        switch (keySize)
        {
            case 2048:
                return "ffdhe2048";
            case 3072:
                return "ffdhe3072";
            case 4096:
                return "ffdhe4096";
            case 6144:
                return "ffdhe6144";
            case 8192:
                return "ffdhe8192";
            default:
                return null;
        }
    }

    @Override
    public void initialize(int keysize, SecureRandom random)
    {
        // KeyPairGenerator.initialize(int) throws InvalidParameterException
        // (RuntimeException) for unsupported sizes per the JCA contract.
        String group = groupFor(keysize);
        if (group == null)
        {
            throw new InvalidParameterException(
                    "DH key size " + keysize + " is not supported. "
                            + "Supported sizes (RFC 7919 groups): 2048, 3072, 4096, 6144, 8192. "
                            + "For other parameters use DHParameterSpec.");
        }
        if (!dhServiceNI.groupSupported(group))
        {
            throw new InvalidParameterException(
                    "DH group " + group + " (key size " + keysize
                            + ") is not supported by the loaded OpenSSL build");
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
        if (!(params instanceof DHParameterSpec))
        {
            throw new InvalidAlgorithmParameterException(
                    "expected DHParameterSpec (got " + params.getClass().getName() + ")");
        }
        DHParameterSpec dhSpec = (DHParameterSpec) params;
        if (dhSpec.getP() == null || dhSpec.getG() == null)
        {
            throw new InvalidAlgorithmParameterException(
                    "DHParameterSpec p and g must both be non-null");
        }
        if (dhSpec.getP().signum() <= 0 || dhSpec.getG().signum() <= 0)
        {
            throw new InvalidAlgorithmParameterException(
                    "DHParameterSpec p and g must both be positive");
        }
        int pBits = dhSpec.getP().bitLength();
        if (pBits < MIN_P_BITS || pBits > MAX_P_BITS)
        {
            // Reject here rather than driving an unbounded (or worthless)
            // native modexp at generateKeyPair, where no typed exception
            // could be raised.
            throw new InvalidAlgorithmParameterException(
                    "DH prime size " + pBits + " bits is out of range ["
                            + MIN_P_BITS + ", " + MAX_P_BITS + "]");
        }
        this.explicitParams = dhSpec;
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
        long ref;
        if (explicitParams != null)
        {
            PKEYKeySpec paramsSpec = makeParamsSpec(explicitParams);
            // Keep the params spec reachable across the native call so
            // its disposer can't free the parameters-only EVP_PKEY
            // mid-keygen.
            synchronized (paramsSpec)
            {
                ref = dhServiceNI.generateKeyPair(paramsSpec.getReference(), random);
            }
        }
        else
        {
            ref = dhServiceNI.generateKeyPairByGroup(groupFor(keySize), random);
        }
        if (ref == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }
        PKEYKeySpec spec = new PKEYKeySpec(ref, OSSLKeyType.DH);
        return new KeyPair(new JODHPublicKey(spec), new JODHPrivateKey(spec));
    }

    /** Import explicit (p, g) as a parameters-only key spec. */
    static PKEYKeySpec makeParamsSpec(DHParameterSpec dhSpec)
    {
        BigInteger p = dhSpec.getP();
        BigInteger g = dhSpec.getG();
        long paramsRef = NISelector.DHServiceNI.makeParamsFromComponents(
                DHComponents.unsignedMagnitude(p),
                DHComponents.unsignedMagnitude(g));
        return new PKEYKeySpec(paramsRef, OSSLKeyType.DH);
    }
}
