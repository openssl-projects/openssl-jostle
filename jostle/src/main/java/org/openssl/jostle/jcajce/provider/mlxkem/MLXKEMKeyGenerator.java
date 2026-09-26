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

import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kts.KemKeyDerivation;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * KEM encapsulate / decapsulate for one hybrid group, driven through the
 * generic {@code SpecNI} encap/decap - the same shape as
 * {@code MLKEMKeyGenerator}, bound to a single group.
 *
 * <p>The group's shared secret is the ML-KEM secret and the ECDH secret
 * CONCATENATED, so its length is group-specific. The key the caller gets is
 * derived from it through the spec's KDF (X9.44 KDF3 with SHA-256 by default),
 * the same rule as {@code MLKEMKeyGenerator}; a TLS caller wanting the raw
 * secret sets no KDF and asks for exactly the secret's length.
 */
public class MLXKEMKeyGenerator extends KeyGeneratorSpi
{
    // Bounds on the caller-requested derived-key size, checked at engineInit
    // so a negative value can't reach new byte[bits/8] and a huge value can't
    // drive an unbounded allocation (DoS).
    private static final int MIN_KEY_SIZE_BITS = 1;
    private static final int MAX_KEY_SIZE_BITS = 32768;

    private final MLXKEMParameterSpec parameterSpec;

    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final MLXKEMServiceNI mlxkemServiceNI;
    private final SpecNI specNI;

    private boolean extract;
    private AlgorithmParameterSpec kemSpec;
    private RandSource randSource;
    private KemKeyDerivation derivation;

    public MLXKEMKeyGenerator(MLXKEMParameterSpec parameterSpec)
    {
        this(NISelector.MLXKEMServiceNI, NISelector.SpecNI, parameterSpec);
    }

    public MLXKEMKeyGenerator(MLXKEMServiceNI mlxkemServiceNI, SpecNI specNI,
                              MLXKEMParameterSpec parameterSpec)
    {
        this(mlxkemServiceNI, specNI, parameterSpec, null);
    }

    /** The provider instance this SPI belongs to; null when unbound. MT-14. */
    private final java.security.Provider providerInstance;

    public MLXKEMKeyGenerator(MLXKEMServiceNI mlxkemServiceNI, SpecNI specNI,
                              MLXKEMParameterSpec parameterSpec,
                              java.security.Provider providerInstance)
    {
        this.providerInstance = providerInstance;
        this.mlxkemServiceNI = mlxkemServiceNI;
        this.specNI = specNI;
        this.parameterSpec = parameterSpec;
        this.randSource = DefaultRandSource.replaceWith(null, null, parameterSpec.getRequiredStrengthBits());
    }

    @Override
    protected void engineInit(SecureRandom random)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        if (params instanceof KEMExtractSpec)
        {
            initExtract((KEMExtractSpec) params, random);
            return;
        }
        if (params instanceof KEMGenerateSpec)
        {
            initGenerate((KEMGenerateSpec) params, random);
            return;
        }
        throw new InvalidAlgorithmParameterException(
                "unsupported parameters " + (params == null ? "null" : params.getClass().getName()));
    }

    private void initExtract(KEMExtractSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        PrivateKey key = params.getPrivateKey();
        if (!(key instanceof MLXKEMPrivateKey))
        {
            throw new InvalidAlgorithmParameterException("Only MLXKEMPrivateKey is supported");
        }

        PKEYKeySpec spec = ((OSSLKey) key).getSpec();
        requireGroup(spec.getType());

        // Provider isolation, private side only: a key is bound to the
        // interface library - and OSSL_LIB_CTX - that created it. Unlike every
        // other family there is no encode-and-re-decode escape hatch here,
        // because hybrid keys have no encoding at all; the only remedy is to
        // generate the keypair through the provider that will use it.
        // Both halves. The library check (WI-10) is the only one with teeth in
        // the unbound direct-SPI realm; instance-equal implies library-equal
        // for anything a provider made.
        if (spec.getSpecNI() != specNI || !spec.usableBy(providerInstance))
        {
            throw new InvalidAlgorithmParameterException(
                    "private key was created by a different Jostle provider instance; hybrid KEM keys have no encoding, "
                            + "so generate the keypair through this provider instead");
        }

        if (params.getEncapsulation() == null)
        {
            // A KEMExtractSpec built without an encapsulation would NPE at
            // engineGenerateKey (wrappedKey.length) - reject at init.
            throw new InvalidAlgorithmParameterException("KEMExtractSpec has no encapsulation");
        }

        checkKeySize(params.getKeySizeInBits());
        derivation = KemKeyDerivation.plan(spec, params.getKeySizeInBits(), params.getKdfAlgorithm(),
                params.getOtherInfo(), providerInstance, randSource);

        extract = true;
        kemSpec = params;
        randSource = DefaultRandSource.replaceWith(randSource, random, parameterSpec.getRequiredStrengthBits());
    }

    private void initGenerate(KEMGenerateSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        PublicKey key = params.getPublicKey();
        if (!(key instanceof MLXKEMPublicKey))
        {
            throw new InvalidAlgorithmParameterException("Only MLXKEMPublicKey is supported");
        }

        // Provider isolation, public side. Be precise about WHERE the work
        // happens, because it is not where the provider name suggests:
        // encapsulate() drives spec.getSpecNI(), the library that CREATED the
        // key, not this SPI's specNI. So a JSLFIPS KeyGenerator handed a JSL
        // public key OBJECT encapsulated through the base library - correct
        // bytes, wrong module, invisible to every functional test.
        //
        // MT-14 closes that route: this check refuses a public key belonging
        // to a different provider INSTANCE. Instance-only, no library half -
        // the instance check subsumes it for anything a provider made, and
        // there is no reason to refuse a public key between two unbound,
        // hand-wired SPIs.
        //
        // The sanctioned crossing for this family is NOT re-encoding: hybrid
        // keys have no encoding. It is exporting the raw share and re-importing
        // it through this provider's KeyFactory - what a real TLS peer does,
        // and what FIPSMLXKEMAgreementTest uses. Hence the hybrid-specific
        // message below: "encode it with getEncoded()" would be advice a
        // caller cannot follow.
        PKEYKeySpec pubSpec = ((OSSLKey) key).getSpec();
        if (!pubSpec.usableBy(providerInstance))
        {
            throw new InvalidAlgorithmParameterException(
                    "public key was created by a different Jostle provider instance; hybrid KEM "
                            + "keys have no encoding, so generate the keypair through this "
                            + "provider instead");
        }
        requireGroup(pubSpec.getType());

        checkKeySize(params.getKeySizeInBits());
        KemKeyDerivation planned = KemKeyDerivation.plan(pubSpec, params.getKeySizeInBits(),
                params.getKdfAlgorithm(), params.getOtherInfo(), providerInstance, randSource);

        int strengthBits = parameterSpec.getRequiredStrengthBits();

        // The natural KeyGenerator.init(spec) call has the JCE inject the
        // platform default SecureRandom, which the caller never chose - drop a
        // too-weak one rather than rejecting the caller (GH #34). A reported 0
        // means "unknown" and is left as-is, with the C-side RAND gate as the
        // safety net.
        int suppliedStrength = DefaultRandSource.strengthOf(random);
        if (suppliedStrength > 0 && suppliedStrength < strengthBits)
        {
            random = null;
        }

        extract = false;
        derivation = planned;
        kemSpec = params;
        randSource = DefaultRandSource.replaceWith(randSource, random, strengthBits);
    }

    private static void checkKeySize(int keySizeInBits)
            throws InvalidAlgorithmParameterException
    {
        if (keySizeInBits < MIN_KEY_SIZE_BITS || keySizeInBits > MAX_KEY_SIZE_BITS)
        {
            throw new InvalidAlgorithmParameterException(
                    "KEM key size in bits out of range [" + MIN_KEY_SIZE_BITS + ", "
                            + MAX_KEY_SIZE_BITS + "]: " + keySizeInBits);
        }
    }

    private void requireGroup(OSSLKeyType type) throws InvalidAlgorithmParameterException
    {
        if (type != parameterSpec.getKeyType())
        {
            MLXKEMParameterSpec supplied = MLXKEMParameterSpec.getSpecForOSSLType(type);
            throw new InvalidAlgorithmParameterException(
                    "expected " + parameterSpec.getName() + " but got "
                            + (supplied == null ? type.getAlgorithmName() : supplied.getName()));
        }
    }

    @Override
    protected SecretKey engineGenerateKey()
    {
        if (kemSpec == null)
        {
            throw new IllegalStateException("not initialized");
        }
        if (extract)
        {
            return decapsulate((KEMExtractSpec) kemSpec);
        }
        return encapsulate((KEMGenerateSpec) kemSpec);
    }

    private SecretKey decapsulate(KEMExtractSpec extractSpec)
    {
        PKEYKeySpec spec = ((OSSLKey) extractSpec.getPrivateKey()).getSpec();
        byte[] wrappedKey = extractSpec.getEncapsulation();

        long len = spec.getSpecNI().decap(spec.getReference(), null, wrappedKey, 0, wrappedKey.length,
                null, 0, 0, randSource);
        byte[] out = new byte[(int) len];
        byte[] key = null;
        try
        {
            len = spec.getSpecNI().decap(spec.getReference(), null, wrappedKey, 0, wrappedKey.length,
                    out, 0, out.length, randSource);
            if (len != out.length)
            {
                throw new IllegalStateException("shared secret length mismatch");
            }
            key = derivation.keyFrom(out);
            // SecretKeySpec clones its input; the finally scrubs the local copies
            // of the shared secret and the key (wrappedKey is the public encapsulation).
            return new SecretKeyWithEncapsulation(
                    new SecretKeySpec(key, extractSpec.getAlgorithmName()), wrappedKey);
        }
        finally
        {
            Arrays.fill(out, (byte) 0);
            if (key != null)
            {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    private SecretKey encapsulate(KEMGenerateSpec generateSpec)
    {
        PKEYKeySpec spec = ((OSSLKey) generateSpec.getPublicKey()).getSpec();
        // Sized to the shared secret the KEM produces; the key is derived from it.
        byte[] secret = new byte[derivation.secretBytes()];
        byte[] key = null;
        try
        {
            int encapsulationLen = spec.getSpecNI().encapsulationLength(spec.getReference(), spec.getType(),
                    secret.length, randSource);
            byte[] wrappedKey = new byte[encapsulationLen];
            int len = spec.getSpecNI().encap(spec.getReference(), null, secret, 0, secret.length,
                    wrappedKey, 0, wrappedKey.length, randSource);
            if (len != wrappedKey.length)
            {
                throw new IllegalStateException("encapsulation length mismatch");
            }
            key = derivation.keyFrom(secret);
            return new SecretKeyWithEncapsulation(
                    new SecretKeySpec(key, generateSpec.getAlgorithmName()), wrappedKey);
        }
        finally
        {
            Arrays.fill(secret, (byte) 0);
            if (key != null)
            {
                Arrays.fill(key, (byte) 0);
            }
        }
    }
}
