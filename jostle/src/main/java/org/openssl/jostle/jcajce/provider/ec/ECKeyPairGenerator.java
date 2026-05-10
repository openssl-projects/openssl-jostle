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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * KeyPairGenerator for EC.
 *
 * <p>The provider deliberately does not maintain its own curve list —
 * curve names are passed straight through to OpenSSL via
 * {@code EVP_PKEY_CTX_set_params(OSSL_PKEY_PARAM_GROUP_NAME)}. Whatever
 * name OpenSSL recognises, this provider recognises. Unknown curves
 * surface as {@link InvalidAlgorithmParameterException} thanks to a
 * pre-flight probe via {@link ECServiceNI#curveSupported(String)}.
 *
 * <p>Two initialisation surfaces:
 * <ul>
 *   <li>{@link #initialize(int)} — bit-size form. Bits are mapped to a
 *       canonical curve name via the small {@link #SIZE_TO_CURVE} table.
 *       Sizes outside the table are rejected.</li>
 *   <li>{@link #initialize(AlgorithmParameterSpec)} with
 *       {@link ECGenParameterSpec} — preferred. The curve name is
 *       passed straight through to OpenSSL.</li>
 * </ul>
 *
 * <p>Explicit-parameters form ({@code java.security.spec.ECParameterSpec})
 * is not supported in this initial cut; callers that need a non-named
 * curve should use OpenSSL directly.
 */
public class ECKeyPairGenerator extends KeyPairGenerator
{
    private static final ECServiceNI ecServiceNI = NISelector.ECServiceNI;

    /**
     * Bit-size → canonical curve name. Standard NIST mapping. If
     * OpenSSL doesn't support one of these at runtime (FIPS build,
     * custom provider stripping curves, etc.) the curveSupported()
     * probe in {@code initialize} will catch it and throw a typed
     * exception.
     */
    private static final Map<Integer, String> SIZE_TO_CURVE;

    static
    {
        Map<Integer, String> m = new HashMap<>();
        m.put(256, "P-256");
        m.put(384, "P-384");
        m.put(521, "P-521");
        SIZE_TO_CURVE = Collections.unmodifiableMap(m);
    }

    /** Default curve when no init is performed before generateKeyPair. */
    private static final String DEFAULT_CURVE = "P-256";


    private String curveName = DEFAULT_CURVE;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());


    public ECKeyPairGenerator()
    {
        super("EC");
    }

    @Override
    public void initialize(int keysize, SecureRandom random)
    {
        // KeyPairGenerator.initialize(int) throws InvalidParameterException
        // (RuntimeException) for unsupported sizes per the JCA contract.
        String curve = SIZE_TO_CURVE.get(keysize);
        if (curve == null)
        {
            throw new InvalidParameterException(
                    "EC key size " + keysize + " is not supported. "
                            + "Supported sizes: " + SIZE_TO_CURVE.keySet()
                            + ". For other curves use ECGenParameterSpec.");
        }
        if (!ecServiceNI.curveSupported(curve))
        {
            throw new InvalidParameterException(
                    "EC curve " + curve + " (key size " + keysize
                            + ") is not supported by the loaded OpenSSL build");
        }
        this.curveName = curve;
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec is null");
        }
        if (!(params instanceof ECGenParameterSpec))
        {
            // ECParameterSpec (explicit-parameters form) is not supported
            // in this cut. Tell callers what to do instead.
            throw new InvalidAlgorithmParameterException(
                    "expected ECGenParameterSpec (got " + params.getClass().getName()
                            + "). Explicit-parameter ECParameterSpec is not supported "
                            + "— use a named curve.");
        }
        String name = ((ECGenParameterSpec) params).getName();
        if (name == null || name.isEmpty())
        {
            throw new InvalidAlgorithmParameterException(
                    "ECGenParameterSpec name is null or empty");
        }
        if (!ecServiceNI.curveSupported(name))
        {
            throw new InvalidAlgorithmParameterException(
                    "curve '" + name + "' is not supported by the loaded OpenSSL build");
        }
        this.curveName = name;
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
        long ref = ecServiceNI.generateKeyPair(curveName, random);
        if (ref == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }
        PKEYKeySpec spec = new PKEYKeySpec(ref, OSSLKeyType.EC);
        return new KeyPair(new JOECPublicKey(spec), new JOECPrivateKey(spec));
    }
}
