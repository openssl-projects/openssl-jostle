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
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.util.asn1.Asn1Ni;
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

/**
 * KeyPairGenerator for X25519 / X448. Each instance is fixed to one key
 * type (set at construction by the provider registration), so unlike EC
 * there is no curve to select — the algorithm name fully determines the
 * key. {@code generateKeyPair} delegates to OpenSSL keygen via
 * {@link XECServiceNI}.
 *
 * <p>The key size is fixed by the algorithm, so {@code initialize(int)}
 * accepts only this variant's canonical key size (255 bits for X25519,
 * 448 for X448) and rejects any other with {@code InvalidParameterException};
 * {@code initialize(AlgorithmParameterSpec)} accepts only {@code null}.
 * A generic "XDH" generator that disambiguates via
 * {@code NamedParameterSpec} (Java 11+) is intentionally out of scope for
 * this cut — callers pick the variant by name ("X25519" / "X448").
 */
public class XECKeyPairGenerator extends KeyPairGenerator
{
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final XECServiceNI xecServiceNI;
    private final SpecNI specNI;
    private final Asn1Ni asn1NI;

    private final OSSLKeyType keyType;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());

    // Canonical RFC 8410 key sizes in bits, used only to validate the JCA
    // initialize(int) selector against this generator's fixed variant. These
    // are external JCE-convention constants (like algorithm names / OIDs),
    // not OpenSSL-owned fixed values to be queried at the boundary — the key
    // itself is generated from the type name, never from a size.
    private static final int X25519_KEY_BITS = 255;
    private static final int X448_KEY_BITS = 448;

    public XECKeyPairGenerator(OSSLKeyType keyType)
    {
        this(NISelector.XECServiceNI, NISelector.SpecNI, NISelector.Asn1NI, keyType);
    }

    public XECKeyPairGenerator(XECServiceNI xecServiceNI, SpecNI specNI, Asn1Ni asn1NI, OSSLKeyType keyType)
    {
        super(keyType.getAlgorithmName());
        this.keyType = keyType;
        this.xecServiceNI = xecServiceNI;
        this.specNI = specNI;
        this.asn1NI = asn1NI;
    }

    @Override
    public void initialize(int keysize, SecureRandom random)
    {
        // The key size is fixed by the algorithm (X25519 / X448). Reject a
        // size that does not match this variant so a caller asking for the
        // wrong strength gets a typed error rather than silently receiving
        // this variant's key regardless — SunEC's fixed XDH generators do
        // the same. The RNG is refreshed only after the size is validated.
        int expected = expectedKeySizeBits();
        if (keysize != expected)
        {
            throw new InvalidParameterException(
                    keyType.getAlgorithmName() + " key size must be " + expected
                            + " bits; got " + keysize);
        }
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    /** Canonical key size in bits for this generator's fixed variant. */
    private int expectedKeySizeBits()
    {
        return keyType == OSSLKeyType.X448 ? X448_KEY_BITS : X25519_KEY_BITS;
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
        PKEYKeySpec spec = new PKEYKeySpec(specNI, ref, keyType);
        return new KeyPair(new JOXECPublicKey(asn1NI, spec), new JOXECPrivateKey(asn1NI, spec));
    }
}
