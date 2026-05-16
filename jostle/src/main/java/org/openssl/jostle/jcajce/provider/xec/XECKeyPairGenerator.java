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
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
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

/**
 * KeyPairGenerator for X25519 / X448. The native side dispatches inside
 * {@code ec_generate_key} based on the curve name, so the same
 * {@link ECServiceNI#generateKeyPair(String, RandSource)} entry point
 * is used as for prime-field EC.
 *
 * <p>Two registration variants:
 * <ol>
 *   <li>{@code KeyPairGenerator.getInstance("X25519")} —
 *       fixed-curve, no init required.</li>
 *   <li>{@code KeyPairGenerator.getInstance("XDH")} —
 *       curve picked at {@link #initialize(AlgorithmParameterSpec)}
 *       time, via {@link NamedParameterSpec} carrying "X25519" or "X448".
 *       Mirrors {@code java.security.spec.NamedParameterSpec.X25519} /
 *       {@code .X448} (Java 11+) at the value level without requiring
 *       us to compile against those constants on Java 8.</li>
 * </ol>
 */
public class XECKeyPairGenerator extends KeyPairGenerator
{
    private static final ECServiceNI ecServiceNI = NISelector.ECServiceNI;

    /** Set when the transformation pins one of X25519 / X448. */
    private final OSSLKeyType mandatedType;

    private String curveName;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    /**
     * Bare "XDH" form — curve chosen at init time. The provider also
     * registers per-curve {@code XECKeyPairGenerator}s that pre-set the
     * curve.
     */
    public XECKeyPairGenerator()
    {
        this(null, "XDH");
    }

    /** Pinned-curve form used by the X25519 / X448 registrations. */
    public XECKeyPairGenerator(OSSLKeyType mandatedType, String algorithmName)
    {
        super(algorithmName);
        this.mandatedType = mandatedType;
        if (mandatedType != null)
        {
            this.curveName = mandatedType.getTypeName();
        }
    }

    @Override
    public void initialize(int keysize, SecureRandom random)
    {
        // X25519 / X448 don't accept a key size in bits — JCE callers
        // who pass an int are mapped to the closest curve. 255 / 256
        // bits resolves to X25519; 448 to X448. Anything else is an
        // error.
        OSSLKeyType resolved;
        switch (keysize)
        {
            case 255:
            case 256:
                resolved = OSSLKeyType.X25519;
                break;
            case 448:
                resolved = OSSLKeyType.X448;
                break;
            default:
                throw new InvalidParameterException(
                        "XDH key size " + keysize + " is not supported. Use 255/256 for X25519 or 448 for X448.");
        }
        if (mandatedType != null && mandatedType != resolved)
        {
            throw new InvalidParameterException(
                    "key size " + keysize + " resolves to " + resolved.getTypeName()
                            + " but this transformation is pinned to " + mandatedType.getTypeName());
        }
        this.curveName = resolved.getTypeName();
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec is null");
        }
        // NamedParameterSpec arrived in Java 11; on the Java 8 baseline
        // we use reflection to accept it without requiring a compile-time
        // dependency. We also accept ECGenParameterSpec by-name so
        // Java 8 callers (and BC-style code) have a path that works
        // without NamedParameterSpec.
        String name = extractName(params);
        if (name == null)
        {
            throw new InvalidAlgorithmParameterException(
                    "expected NamedParameterSpec or ECGenParameterSpec (got "
                            + params.getClass().getName() + ")");
        }
        if (name == null || name.isEmpty())
        {
            throw new InvalidAlgorithmParameterException("NamedParameterSpec name is null or empty");
        }
        // Accept canonical "X25519" / "X448" and BC-style "X25519"/"X448"
        // case-insensitively. Anything else is rejected.
        OSSLKeyType resolved;
        if (name.equalsIgnoreCase("X25519"))
        {
            resolved = OSSLKeyType.X25519;
        }
        else if (name.equalsIgnoreCase("X448"))
        {
            resolved = OSSLKeyType.X448;
        }
        else
        {
            throw new InvalidAlgorithmParameterException(
                    "unknown XDH curve name: '" + name + "' (expected X25519 or X448)");
        }
        if (mandatedType != null && mandatedType != resolved)
        {
            throw new InvalidAlgorithmParameterException(
                    "spec asked for " + resolved.getTypeName()
                            + " but this transformation is pinned to " + mandatedType.getTypeName());
        }
        if (!ecServiceNI.curveSupported(resolved.getTypeName()))
        {
            throw new InvalidAlgorithmParameterException(
                    "curve '" + resolved.getTypeName() + "' is not supported by the loaded OpenSSL build");
        }
        this.curveName = resolved.getTypeName();
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        initialize(params, null);
    }

    /**
     * Pull a curve-name string out of an arbitrary AlgorithmParameterSpec.
     * Recognises {@link ECGenParameterSpec} (Java 8 baseline) and uses
     * reflection for {@link java.security.spec.NamedParameterSpec} (Java
     * 11+) so we don't take a compile-time dependency on it.
     * <p>Returns {@code null} if no curve name can be extracted.
     */
    private static String extractName(AlgorithmParameterSpec params)
    {
        if (params instanceof ECGenParameterSpec)
        {
            return ((ECGenParameterSpec) params).getName();
        }
        try
        {
            Class<?> namedSpec = Class.forName("java.security.spec.NamedParameterSpec");
            if (namedSpec.isInstance(params))
            {
                return (String) namedSpec.getMethod("getName").invoke(params);
            }
        }
        catch (ReflectiveOperationException ignore)
        {
            // Class not present (Java 8) or method invocation failed —
            // fall through to the null return.
        }
        return null;
    }

    @Override
    public KeyPair generateKeyPair()
    {
        if (curveName == null)
        {
            // Bare XDH with no init — pick X25519 as the default.
            curveName = OSSLKeyType.X25519.getTypeName();
        }
        long ref = ecServiceNI.generateKeyPair(curveName, random);
        if (ref == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }
        OSSLKeyType type = curveName.equals("X448") ? OSSLKeyType.X448 : OSSLKeyType.X25519;
        PKEYKeySpec spec = new PKEYKeySpec(ref, type);
        return new KeyPair(new JOXECPublicKey(spec), new JOXECPrivateKey(spec));
    }
}
