/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlkem;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class MLKEMKeyPairGenerator extends KeyPairGenerator
{

    private OSSLKeyType keyType;
    /**
     * Cached RandSource. Initialised in the constructor to a
     * strength-appropriate default based on the constructor's keyType
     * (so {@code generateKeyPair} works on a typed instance without an
     * explicit {@code initialize} call). {@code initialize} replaces it
     * via {@link DefaultRandSource#replaceWith(RandSource, SecureRandom, int)},
     * which reuses the existing instance when the request is already
     * satisfied — eliminating the per-call wrap allocation that the
     * GH issue #34 fix originally introduced.
     */
    private RandSource randSource;

    private static final Map<Object, OSSLKeyType> paramToTypeMap = new HashMap<Object, OSSLKeyType>()
    {
        {
            put("ML-KEM", OSSLKeyType.NONE);

            put("ML-KEM-512", OSSLKeyType.ML_KEM_512);
            put("ML-KEM-768", OSSLKeyType.ML_KEM_768);
            put("ML-KEM-1024", OSSLKeyType.ML_KEM_1024);

            put(MLKEMParameterSpec.ml_kem_512, OSSLKeyType.ML_KEM_512);
            put(MLKEMParameterSpec.ml_kem_768, OSSLKeyType.ML_KEM_768);
            put(MLKEMParameterSpec.ml_kem_1024, OSSLKeyType.ML_KEM_1024);
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
    public MLKEMKeyPairGenerator(Object algorithm)
    {
        super(algorithm.toString());
        keyType = paramToTypeMap.get(algorithm);

        if (keyType == null)
        {
            throw new IllegalArgumentException("unknown algorithm: " + algorithm);
        }

        // Pre-resolve a strength-appropriate default RandSource so a
        // typed instance (e.g. KeyPairGenerator.getInstance("ML-KEM-768"))
        // works without an explicit initialize() call. The umbrella
        // "ML-KEM" alias resolves to NONE; fall back to the 128-bit
        // category — generateKeyPair on a NONE instance without
        // initialize() will fail at the native layer anyway.
        randSource = DefaultRandSource.replaceWith(null, null, strengthForKeyType(keyType));
    }


    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof MLKEMParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("only MLKEMParameterSpec is supported got " + params.getClass().getName());
        }

        MLKEMParameterSpec spec = (MLKEMParameterSpec) params;

        OSSLKeyType newType = paramToTypeMap.get(spec.getName());

        if (newType == null)
        {
            throw new InvalidAlgorithmParameterException("unknown algorithm: " + spec.getName());
        }

        if (keyType == OSSLKeyType.NONE)
        {
            keyType = newType;
        }

        if (keyType != newType)
        {
            throw new InvalidAlgorithmParameterException("expected " + MLKEMParameterSpec.getSpecForOSSLType(keyType).getName() + " but was supplied " + MLKEMParameterSpec.getSpecForOSSLType(newType).getName());
        }

        keyType = newType;

        int strengthBits = strengthForKeyType(keyType);

        // Fail fast if the caller supplied a SecureRandom that reports
        // a strength below the algorithm's requirement (Java 9+ DRBG
        // path). Sources that don't expose a strength claim
        // (plain new SecureRandom(), Java 8, custom subclasses) return
        // 0 here and are accepted — the C-side RAND gate is the safety
        // net for those.
        int suppliedStrength = DefaultRandSource.strengthOf(random);
        if (suppliedStrength > 0 && suppliedStrength < strengthBits)
        {
            throw new InvalidAlgorithmParameterException(
                    "supplied SecureRandom reports " + suppliedStrength
                            + "-bit strength but " + spec.getName()
                            + " requires " + strengthBits);
        }

        // Resolve / upgrade the RandSource to match the now-final keyType.
        // replaceWith reuses the existing instance when it already
        // satisfies the request — no allocation when the strength is
        // unchanged AND the caller didn't supply a different SecureRandom.
        randSource = DefaultRandSource.replaceWith(randSource, random, strengthBits);
    }

    private static int strengthForKeyType(OSSLKeyType type)
    {
        OSSLKeyType activeType = (type == OSSLKeyType.NONE) ? OSSLKeyType.ML_KEM_512 : type;
        return MLKEMParameterSpec.getSpecForOSSLType(activeType).getRequiredStrengthBits();
    }

    @Override
    public KeyPair generateKeyPair()
    {
        long res = NISelector.MLKEMServiceNI.generateKeyPair(keyType.getKsType(), randSource);

        PKEYKeySpec spec = new PKEYKeySpec(res, keyType);
        return new KeyPair(new JOMLKEMPublicKey(spec), new JOMLKEMPrivateKey(spec));
    }


}
