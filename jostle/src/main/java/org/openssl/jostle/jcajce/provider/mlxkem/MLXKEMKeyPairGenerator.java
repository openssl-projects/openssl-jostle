/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlxkem;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.jcajce.util.SpecUtil;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KeyPairGenerator for one hybrid group.
 *
 * <p>There is no umbrella instance, unlike ML-KEM's: registration is per
 * variant because the module serves them individually, so an instance is
 * always bound to the group it was constructed for and {@code initialize}
 * can only confirm that group, never switch to another.
 */
public class MLXKEMKeyPairGenerator extends KeyPairGenerator
{
    private final MLXKEMParameterSpec parameterSpec;

    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final MLXKEMServiceNI mlxkemServiceNI;
    private final SpecNI specNI;

    /**
     * Cached RandSource, resolved at construction so a caller can go straight
     * to generateKeyPair() without initialize(). See MLKEMKeyPairGenerator for
     * the strength rationale (GH issue #34).
     */
    private RandSource randSource;

    public MLXKEMKeyPairGenerator(MLXKEMParameterSpec parameterSpec)
    {
        this(NISelector.MLXKEMServiceNI, NISelector.SpecNI, parameterSpec);
    }

    /**
     * NI-injecting form. The SPI is bound to whichever interface library its
     * NIs came from - NISelector for JSL, FIPSNISelector for JSLFIPS - so it
     * must never reach for the base provider's statics.
     */

    /**
     * The provider INSTANCE this SPI belongs to, or null when constructed
     * outside any provider. Every key this SPI produces is BOUND to it. Inert
     * until Phase 2 passes an instance at registration. See MT-14 and
     * {@code PKEYKeySpec.usableBy}.
     */
    private final java.security.Provider providerInstance;

    public MLXKEMKeyPairGenerator(MLXKEMServiceNI mlxkemServiceNI, SpecNI specNI,
                                  MLXKEMParameterSpec parameterSpec)
    {
        this(mlxkemServiceNI, specNI, parameterSpec, null);
    }

    public MLXKEMKeyPairGenerator(MLXKEMServiceNI mlxkemServiceNI, SpecNI specNI,
                                  MLXKEMParameterSpec parameterSpec, java.security.Provider providerInstance)
    {
        super(parameterSpec.getName());
        this.providerInstance = providerInstance;
        this.mlxkemServiceNI = mlxkemServiceNI;
        this.specNI = specNI;
        this.parameterSpec = parameterSpec;

        randSource = mlxkemServiceNI.providerManagesEntropy()
                ? DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom())
                : DefaultRandSource.replaceWith(null, null, parameterSpec.getRequiredStrengthBits());
    }

    /**
     * Route a no-SecureRandom call through with null so replaceWith picks a
     * strength-appropriate default rather than the JDK's injected one.
     */
    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        initialize(params, null);
    }

    @Override
    public void initialize(int keysize, SecureRandom random)
    {
        throw new InvalidParameterException(
                "hybrid KEMs are group-based; use initialize(MLXKEMParameterSpec)");
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            throw new InvalidAlgorithmParameterException("parameter spec cannot be null");
        }

        String specName;
        if (params instanceof MLXKEMParameterSpec)
        {
            specName = ((MLXKEMParameterSpec) params).getName();
        }
        else
        {
            specName = SpecUtil.getNameFrom(params);
        }

        if (specName == null || !specName.equalsIgnoreCase(parameterSpec.getName()))
        {
            throw new InvalidAlgorithmParameterException(
                    "expected " + parameterSpec.getName() + " but was supplied "
                            + (specName != null ? specName : params.getClass().getName()));
        }

        int strengthBits = parameterSpec.getRequiredStrengthBits();

        // Skipped under a provider that supplies its own entropy (the FIPS
        // module): the caller's SecureRandom is never consulted there, so
        // rejecting it would turn a caller away over a value nothing reads.
        if (!mlxkemServiceNI.providerManagesEntropy())
        {
            int suppliedStrength = DefaultRandSource.strengthOf(random);
            if (suppliedStrength > 0 && suppliedStrength < strengthBits)
            {
                throw new InvalidAlgorithmParameterException(
                        "supplied SecureRandom reports " + suppliedStrength
                                + "-bit strength but " + specName
                                + " requires " + strengthBits);
            }
        }

        randSource = DefaultRandSource.replaceWith(randSource, random, strengthBits);
    }

    @Override
    public KeyPair generateKeyPair()
    {
        OSSLKeyType keyType = parameterSpec.getKeyType();
        long res = mlxkemServiceNI.generateKeyPair(keyType.getKsType(), randSource);

        PKEYKeySpec spec = new PKEYKeySpec(specNI, res, keyType, providerInstance);
        return new KeyPair(new JOMLXKEMPublicKey(mlxkemServiceNI, spec),
                new JOMLXKEMPrivateKey(mlxkemServiceNI, spec));
    }
}
