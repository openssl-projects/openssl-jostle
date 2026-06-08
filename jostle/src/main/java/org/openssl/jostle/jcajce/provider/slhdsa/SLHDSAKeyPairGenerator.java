/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import static org.openssl.jostle.jcajce.spec.OSSLKeyType.NONE;

public class SLHDSAKeyPairGenerator extends KeyPairGenerator
{

    private final OSSLKeyType forcedType;
    private OSSLKeyType keyType;
    /**
     * Cached RandSource. Initialised in the constructor to a
     * strength-appropriate default based on the constructor's keyType
     * (so {@code generateKeyPair} works on a typed instance without an
     * explicit {@code initialize} call). {@code initialize} replaces it
     * via {@link DefaultRandSource#replaceWith(RandSource, SecureRandom, int)},
     * which reuses the existing instance when the request is already
     * satisfied — eliminating the per-call wrap allocation. SLH-DSA-*-192
     * (192-bit) and SLH-DSA-*-256 (256-bit) need higher than the JDK
     * default 128-bit DRBG (same root cause as GH issue #34).
     */
    private RandSource randSource;

    private static final Map<Object, OSSLKeyType> paramToTypeMap = new HashMap<Object, OSSLKeyType>()
    {
        {
            put("SLH-DSA", NONE);
            SLHDSAParameterSpec.getParameterNames().forEach((key) ->
            {
                SLHDSAParameterSpec value = SLHDSAParameterSpec.fromName(key);
                put(value.getName(), ((SLHDSAParameterSpec) value).getKeyType());
                put(value, ((SLHDSAParameterSpec) value).getKeyType());
            });
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
    public SLHDSAKeyPairGenerator(Object algorithm)
    {
        super(algorithm.toString());
        forcedType = paramToTypeMap.get(algorithm);

        if (forcedType == null)
        {
            throw new IllegalArgumentException("unknown algorithm: " + algorithm);
        }

        if (forcedType != OSSLKeyType.NONE)
        {
            keyType = forcedType;
        }

        // Pre-resolve a strength-appropriate default RandSource so a
        // typed instance works without an explicit initialize() call.
        // For the umbrella "SLH-DSA" alias (NONE), fall back to the
        // 128-bit category — generateKeyPair pre-init will fail at the
        // native layer anyway.
        randSource = DefaultRandSource.replaceWith(null, null, strengthForKeyType(keyType));
    }

    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        initialize(params, null);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof SLHDSAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("only SLHDSAParameterSpec is supported");
        }

        SLHDSAParameterSpec spec = (SLHDSAParameterSpec) params;

        OSSLKeyType newType = paramToTypeMap.get(spec.getName());

        if (newType == null)
        {
            throw new InvalidAlgorithmParameterException("unknown algorithm: " + spec.getName());
        }

        if (forcedType == OSSLKeyType.NONE)
        {
            keyType = newType;
        }
        else
        {
            if (forcedType != newType)
            {
                throw new InvalidAlgorithmParameterException(
                        "expected " + SLHDSAParameterSpec.getSpecForOSSLType(forcedType).getName() + " but was supplied " + SLHDSAParameterSpec.getSpecForOSSLType(newType).getName());
            }
            keyType = newType;
        }

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
        OSSLKeyType activeType = (type == null || type == OSSLKeyType.NONE)
                ? OSSLKeyType.SLH_DSA_SHA2_128f : type;
        return SLHDSAParameterSpec.getSpecForOSSLType(activeType).getRequiredStrengthBits();
    }

    public KeyPair generateKeyPair()
    {
        long res = NISelector.SLHDSAServiceNI.generateKeyPair(keyType.getKsType(), randSource);

        PKEYKeySpec spec = new PKEYKeySpec(res, keyType);
        return new KeyPair(new JOSLHDSAPublicKey(spec), new JOSLHDSAPrivateKey(spec));
    }


}
