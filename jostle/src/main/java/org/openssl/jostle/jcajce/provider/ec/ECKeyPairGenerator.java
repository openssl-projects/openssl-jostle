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
 * <h2>Accepted curve names</h2>
 *
 * Any name OpenSSL accepts via {@code OSSL_PKEY_PARAM_GROUP_NAME} works
 * directly. Common families:
 *
 * <ul>
 *   <li><b>NIST P-curves (prime field)</b>: {@code P-256}, {@code P-384},
 *       {@code P-521}, {@code P-224} — also accepted as the SECG
 *       {@code secp256r1}/{@code secp384r1}/{@code secp521r1}/{@code secp224r1},
 *       the X9.62 {@code prime256v1}, or the OID dotted form.</li>
 *   <li><b>NIST K-curves (binary field, Koblitz)</b>: {@code K-163},
 *       {@code K-233}, {@code K-283}, {@code K-409}, {@code K-571} —
 *       BC-style aliases for the SECG {@code sect163k1} … {@code sect571k1}.</li>
 *   <li><b>NIST B-curves (binary field, random)</b>: {@code B-163},
 *       {@code B-233}, {@code B-283}, {@code B-409}, {@code B-571} —
 *       BC-style aliases for {@code sect163r2}/{@code sect233r1}/
 *       {@code sect283r1}/{@code sect409r1}/{@code sect571r1}. Note
 *       {@code B-163} maps to {@code sect163r2} (not r1 — sect163r1 was
 *       withdrawn before NIST adopted the family).</li>
 *   <li><b>SECG Koblitz prime</b>: {@code secp256k1}.</li>
 *   <li><b>Brainpool (RFC 5639)</b>: {@code brainpoolP{160,192,224,256,320,384,512}{r1,t1}}.</li>
 *   <li><b>Other SECG/X9.62 curves</b>: any {@code sectNNN(k1|r1|r2)} or
 *       {@code primeNNNvN} the OpenSSL build advertises.</li>
 * </ul>
 *
 * <p>Two initialisation surfaces:
 * <ul>
 *   <li>{@link #initialize(int)} — bit-size form, P-curves only. Bits
 *       are mapped to a canonical curve name via the small
 *       {@link #SIZE_TO_CURVE} table (256/384/521 only). Binary curves
 *       are deliberately omitted because the bit→curve mapping is
 *       ambiguous (e.g. 283 could mean K-283 or B-283); pass them by
 *       name through {@code ECGenParameterSpec} instead.</li>
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
