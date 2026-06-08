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

package org.openssl.jostle.jcajce.provider.xec;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KeyPairGenerator for X25519 / X448. Each instance is fixed to one key
 * type (set at construction by the provider registration), so unlike EC
 * there is no curve to select — the algorithm name fully determines the
 * key. {@code generateKeyPair} delegates to OpenSSL keygen via
 * {@link XECServiceNI}.
 *
 * <p>The key size is fixed by the algorithm, so {@code initialize(int)}
 * ignores its size argument (it only refreshes the RNG) and
 * {@code initialize(AlgorithmParameterSpec)} accepts only {@code null}.
 * A generic "XDH" generator that disambiguates via
 * {@code NamedParameterSpec} (Java 11+) is intentionally out of scope for
 * this cut — callers pick the variant by name ("X25519" / "X448").
 */
public class XECKeyPairGenerator extends KeyPairGenerator
{
    private static final XECServiceNI xecServiceNI = NISelector.XECServiceNI;

    private final OSSLKeyType keyType;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    public XECKeyPairGenerator(OSSLKeyType keyType)
    {
        super(keyType.getAlgorithmName());
        this.keyType = keyType;
    }

    @Override
    public void initialize(int keysize, SecureRandom random)
    {
        // The key size is fixed by the algorithm (X25519 / X448); the
        // size argument is advisory only. Refresh the RNG if supplied.
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException(
                    "no parameters accepted for " + keyType.getAlgorithmName());
        }
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
        long ref = xecServiceNI.generateKeyPair(keyType.getTypeName(), random);
        if (ref == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }
        PKEYKeySpec spec = new PKEYKeySpec(ref, keyType);
        return new KeyPair(new JOXECPublicKey(spec), new JOXECPrivateKey(spec));
    }
}
