/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mldsa;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.util.SpecUtil;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.Strings;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class MLDSAKeyPairGeneratorImpl extends KeyPairGenerator
{
    Logger LOG = Logger.getLogger("MLDSAKeyPairGeneratorImpl(Java 8)");
    private OSSLKeyType keyType;

    /**
     * Cached RandSource. Initialised in the constructor to a
     * strength-appropriate default based on the constructor's keyType
     * (so {@code generateKeyPair} works on a typed instance without an
     * explicit {@code initialize} call). {@code initialize} replaces it
     * via {@link DefaultRandSource#replaceWith(RandSource, SecureRandom, int)},
     * which reuses the existing instance when the request is already
     * satisfied — eliminating the per-call wrap allocation.
     */
    private RandSource randSource;

    private static final Map<Object, OSSLKeyType> paramToTypeMap = new HashMap<Object, OSSLKeyType>()
    {
        {
            put("ML-DSA", OSSLKeyType.NONE);

            put("ML-DSA-44", OSSLKeyType.ML_DSA_44);
            put("ML-DSA-65", OSSLKeyType.ML_DSA_65);
            put("ML-DSA-87", OSSLKeyType.ML_DSA_87);

            put(MLDSAParameterSpec.ml_dsa_44, OSSLKeyType.ML_DSA_44);
            put(MLDSAParameterSpec.ml_dsa_65, OSSLKeyType.ML_DSA_65);
            put(MLDSAParameterSpec.ml_dsa_87, OSSLKeyType.ML_DSA_87);
        }
    };


    /**
     * Creates a {@code KeyPairGenerator} object for the specified algorithm.
     *
     * @param algorithm the standard string name of the algorithm.
     *                  See the KeyPairGenerator section in the <a href=
     *                  "{@docRoot}/../specs/security/standard-names.html#keypairgenerator-algorithms">
     *                  Java Security Standard Algorithm Names Specification</a>
     *                  for information about standard algorithm names.
     */
    public MLDSAKeyPairGeneratorImpl(Object algorithm)
    {
        super(algorithm.toString());
        keyType = paramToTypeMap.get(algorithm);

        if (keyType == null)
        {
            throw new IllegalArgumentException("unknown algorithm: " + algorithm);
        }

        // Pre-resolve a strength-appropriate default RandSource so a
        // typed instance (e.g. KeyPairGenerator.getInstance("ML-DSA-65"))
        // works without an explicit initialize() call. The umbrella
        // "ML-DSA" alias resolves to NONE; fall back to the 128-bit
        // category — generateKeyPair on a NONE instance without
        // initialize() will fail at the native layer anyway.
        randSource = DefaultRandSource.replaceWith(null, null, strengthForKeyType(keyType));
    }

    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        initialize(params, null);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom rand) throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            throw new InvalidAlgorithmParameterException("parameter spec cannot be null");
        }

        // Resolve the parameter-set name: use the name directly for our own
        // MLDSAParameterSpec, otherwise reflect on getName() so a foreign spec
        // (e.g. BouncyCastle's MLDSAParameterSpec) is accepted too.
        String specName;
        if (params instanceof MLDSAParameterSpec)
        {
            specName = ((MLDSAParameterSpec) params).getName();
        }
        else
        {
            String reflected = SpecUtil.getNameFrom(params);
            specName = (reflected == null) ? null : Strings.toUpperCase(reflected);
        }

        OSSLKeyType newType = (specName == null) ? null : paramToTypeMap.get(specName);

        if (newType == null)
        {
            throw new InvalidAlgorithmParameterException(
                    "unknown algorithm: " + (specName != null ? specName : params.getClass().getName()));
        }

        if (keyType == OSSLKeyType.NONE)
        {
            keyType = newType;
        }

        if (keyType != newType)
        {
            throw new InvalidAlgorithmParameterException("expected " + keyType + " but was supplied " + newType);
        }

        int strengthBits = strengthForKeyType(keyType);

        // Fail fast if the caller supplied a SecureRandom that reports
        // a strength below the algorithm's requirement (Java 9+ DRBG
        // path). Sources that don't expose a strength claim
        // (plain new SecureRandom(), Java 8, custom subclasses) return
        // 0 here and are accepted — the C-side RAND gate is the safety
        // net for those.
        int suppliedStrength = DefaultRandSource.strengthOf(rand);
        if (suppliedStrength > 0 && suppliedStrength < strengthBits)
        {
            throw new InvalidAlgorithmParameterException(
                    "supplied SecureRandom reports " + suppliedStrength
                            + "-bit strength but " + specName
                            + " requires " + strengthBits);
        }

        // Resolve / upgrade the RandSource to match the now-final keyType.
        // replaceWith reuses the existing instance when it already
        // satisfies the request — no allocation when the strength is
        // unchanged AND the caller didn't supply a different SecureRandom.
        randSource = DefaultRandSource.replaceWith(randSource, rand, strengthBits);
    }

    private static int strengthForKeyType(OSSLKeyType type)
    {
        OSSLKeyType activeType = (type == OSSLKeyType.NONE) ? OSSLKeyType.ML_DSA_44 : type;
        return MLDSAParameterSpec.fromName(activeType.getTypeName()).getRequiredStrengthBits();
    }

    @Override
    public KeyPair generateKeyPair()
    {
        long res = NISelector.MLDSAServiceNI.generateKeyPair(keyType.getKsType(), randSource);


        if (res == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }


        PKEYKeySpec spec = new PKEYKeySpec(res, keyType);
        return new KeyPair(new JOMLDSAPublicKey(spec), new JOMLDSAPrivateKey(spec));
    }


    public static class MLDSA44 extends MLDSAKeyPairGeneratorImpl
    {

        public MLDSA44()
        {
            super(MLDSAParameterSpec.ml_dsa_44);
        }
    }

    public static class MLDSA65 extends MLDSAKeyPairGeneratorImpl
    {

        public MLDSA65()
        {
            super(MLDSAParameterSpec.ml_dsa_65);
        }
    }

    public static class MLDSA87 extends MLDSAKeyPairGeneratorImpl
    {

        public MLDSA87()
        {
            super(MLDSAParameterSpec.ml_dsa_87);
        }
    }

}
