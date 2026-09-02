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

package org.openssl.jostle.jcajce.provider.ed;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.asn1.Asn1Ni;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class EdDSAKeyPairGenerator extends KeyPairGenerator
{
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final EDServiceNI edServiceNI;
    private final SpecNI specNI;
    private final Asn1Ni asn1NI;

    private OSSLKeyType keyType = OSSLKeyType.NONE;

    /** Ed25519's field size in bits - what the JDK's generator expects. */
    private static final int ED25519_FIELD_BITS = 255;
    /** Ed25519's encoded length in bits - what BouncyCastle also accepts. */
    private static final int ED25519_ENCODED_BITS = 256;
    /** Ed448, agreed by both references. */
    private static final int ED448_KEY_BITS = 448;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());


    private static final Map<Object, OSSLKeyType> paramToTypeMap = new HashMap<Object, OSSLKeyType>()
    {
        {
            put("EDDSA", OSSLKeyType.NONE);
            put("ED25519", OSSLKeyType.ED25519);
            put("ED448", OSSLKeyType.ED448);
            put(EdDSAParameterSpec.ED25519, OSSLKeyType.ED25519);
            put(EdDSAParameterSpec.ED448, OSSLKeyType.ED448);
        }
    };

    public EdDSAKeyPairGenerator(Object algorithm)
    {
        this(NISelector.EDServiceNI, NISelector.SpecNI, NISelector.Asn1NI, algorithm);
    }


    /**
     * The provider INSTANCE this SPI belongs to, or null when constructed
     * outside any provider. Every key this SPI produces is BOUND to it, and is
     * then usable only through that instance. Null is the direct-SPI realm,
     * which has no provider boundary to protect. See MT-14 and
     * {@code PKEYKeySpec.usableBy}.
     */
    private final java.security.Provider providerInstance;

    public EdDSAKeyPairGenerator(EDServiceNI edServiceNI, SpecNI specNI, Asn1Ni asn1NI, Object algorithm)
    {
        this(edServiceNI, specNI, asn1NI, algorithm, null);
    }

    public EdDSAKeyPairGenerator(EDServiceNI edServiceNI, SpecNI specNI, Asn1Ni asn1NI, Object algorithm, java.security.Provider providerInstance)
    {
        super(algorithmName(algorithm));
        this.providerInstance = providerInstance;
        this.edServiceNI = edServiceNI;
        this.specNI = specNI;
        this.asn1NI = asn1NI;
        keyType = paramToTypeMap.get(algorithm);

        if (keyType == null)
        {
            throw new IllegalArgumentException("unknown algorithm: " + algorithm);
        }
    }

    /**
     * The algorithm name reported by {@link #getAlgorithm()}. An
     * {@link EdDSAParameterSpec} has no {@code toString()}, so
     * {@code super(algorithm.toString())} would surface a
     * {@code ...EdDSAParameterSpec@<hash>} identity string; use its declared
     * name instead. String algorithms (e.g. "EDDSA") pass through unchanged.
     */
    private static String algorithmName(Object algorithm)
    {
        if (algorithm instanceof EdDSAParameterSpec)
        {
            return ((EdDSAParameterSpec) algorithm).getName();
        }
        return String.valueOf(algorithm);
    }

    @Override
    public void initialize(int keysize, SecureRandom random)
    {
        // MT-52. This USED to ignore the size entirely, with a comment claiming
        // it mirrored XECKeyPairGenerator - which actually validates. So the
        // comment asserted a parity that did not exist, and we accepted -1, 0,
        // 2^26 and Integer.MIN_VALUE where BouncyCastle and the JDK both raise
        // InvalidParameterException.
        //
        // The two references disagree slightly on Ed25519 and the superset is
        // taken deliberately: the JDK accepts 255 (the curve's field size),
        // BouncyCastle accepts 255 and 256 (the encoded byte length in bits).
        // Both name the same key, so refusing either would reject a caller one
        // reference tells to use. Ed448 is 448 on both.
        int effective = keysize;
        boolean ok = (keyType == OSSLKeyType.ED448)
                ? (effective == ED448_KEY_BITS)
                : (effective == ED25519_FIELD_BITS || effective == ED25519_ENCODED_BITS);
        if (!ok)
        {
            throw new InvalidParameterException("key size " + keysize + " is not valid for "
                    + (keyType == OSSLKeyType.ED448 ? "Ed448 (448)" : "Ed25519 (255 or 256)"));
        }
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        initialize(params, null);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        this.random = DefaultRandSource.replaceWith(this.random, random);

        if (!(params instanceof EdDSAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("expected instance of EdDSAParameterSpec");
        }

        OSSLKeyType newType = paramToTypeMap.get(((EdDSAParameterSpec) params).getName());

        if (newType == null)
        {
            throw new InvalidAlgorithmParameterException("unknown algorithm: " + ((EdDSAParameterSpec) params).getName());
        }

        if (keyType == OSSLKeyType.NONE)
        {
            keyType = newType;
        }

        if (keyType != newType)
        {
            throw new InvalidAlgorithmParameterException("expected " + keyType + " but was supplied " + newType);
        }

    }

    @Override
    public KeyPair generateKeyPair()
    {
        // An uninitialised generic "EdDSA" generator defaults to Ed25519, as
        // SunEC and BouncyCastle do; the fixed ED25519 / ED448 subclasses set
        // keyType at construction, so this only affects the generic form.
        OSSLKeyType effectiveType = keyType == OSSLKeyType.NONE ? OSSLKeyType.ED25519 : keyType;

        long res = edServiceNI.generateKeyPair(effectiveType.getKsType(), random);

        if (res == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }

        PKEYKeySpec spec = new PKEYKeySpec(specNI, res, effectiveType, providerInstance);
        return new KeyPair(new JOEdPublicKey(edServiceNI, asn1NI, spec), new JOEdPrivateKey(edServiceNI, asn1NI, spec));
    }
}
