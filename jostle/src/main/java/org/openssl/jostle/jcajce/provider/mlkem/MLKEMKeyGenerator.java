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

import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.*;
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

public class MLKEMKeyGenerator extends KeyGeneratorSpi
{

    // Bounds on the caller-requested derived-key size, checked at engineInit
    // so a negative value can't reach new byte[bits/8] (NegativeArraySizeException)
    // and a huge value can't drive an unbounded allocation (DoS). ML-KEM's
    // shared secret is 256-bit; the upper bound is generously above any real
    // symmetric key while still bounding the allocation.
    private static final int MIN_KEY_SIZE_BITS = 1;
    private static final int MAX_KEY_SIZE_BITS = 32768;

    private boolean extract;
    private final OSSLKeyType forcedKeyType;
    private AlgorithmParameterSpec parameterSpec;
    private RandSource randSource;

    // OpenSSL-probed encapsulation lengths, memoized once per parameter set (see NativeLengthCache).
    private static final NativeLengthCache<OSSLKeyType> encapsulationLengths = new NativeLengthCache<OSSLKeyType>();


    /**
     * The SpecNI this KeyGenerator belongs to — the interface library, and
     * hence the {@code OSSL_LIB_CTX}, whose keys it will accept for
     * decapsulation.
     *
     * <p>Taken by constructor, deliberately NOT derived from
     * {@code DefaultServiceNI.providerName()}: only 6 of the 22 FIPS NI
     * classes override that, and {@code SpecFIPSJNI} is not among them, so it
     * answers "JSL" under JSLFIPS and would make this check silently
     * vacuous. See MT-12.
     */
    private final SpecNI specNI;

    public MLKEMKeyGenerator(MLKEMParameterSpec spec)
    {
        this(NISelector.SpecNI, spec);
    }

    public MLKEMKeyGenerator(SpecNI specNI, MLKEMParameterSpec spec)
    {
        this(specNI, spec, null);
    }

    /** The provider instance this SPI belongs to; null when unbound. MT-14. */
    private final java.security.Provider providerInstance;

    public MLKEMKeyGenerator(SpecNI specNI, MLKEMParameterSpec spec,
                             java.security.Provider providerInstance)
    {
        this.providerInstance = providerInstance;
        this.specNI = specNI;
        this.forcedKeyType = spec.getKeyType();
        randSource = DefaultRandSource.replaceWith(null, null, strengthForKeyType(forcedKeyType));
    }

    public MLKEMKeyGenerator()
    {
        this(NISelector.SpecNI);
    }

    public MLKEMKeyGenerator(SpecNI specNI)
    {
        this(specNI, (java.security.Provider) null);
    }

    public MLKEMKeyGenerator(SpecNI specNI, java.security.Provider providerInstance)
    {
        this.providerInstance = providerInstance;
        this.specNI = specNI;
        this.forcedKeyType = OSSLKeyType.NONE;
        // No forced type — default to 128-bit baseline. engineInit
        // will trigger a strength upgrade for the peer key's variant
        // if needed.
        randSource = DefaultRandSource.replaceWith(null, null, strengthForKeyType(OSSLKeyType.NONE));
    }

    private static int strengthForKeyType(OSSLKeyType type)
    {
        OSSLKeyType activeType = (type == OSSLKeyType.NONE) ? OSSLKeyType.ML_KEM_512 : type;
        return MLKEMParameterSpec.getSpecForOSSLType(activeType).getRequiredStrengthBits();
    }

    @Override
    protected void engineInit(SecureRandom random)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        if (params instanceof KEMExtractSpec)
        {
            PrivateKey key = ((KEMExtractSpec) params).getPrivateKey();
            if (key instanceof MLKEMPrivateKey)
            {
                extract = true;
                MLKEMPrivateKey kem = (MLKEMPrivateKey) key;

                // Provider isolation, private side only. The handle is bound
                // to the interface library - and OSSL_LIB_CTX - that created
                // it, so a JSL private key must not be decapsulated through
                // the JSLFIPS NI or vice versa.
                //
                // ML-KEM's isolation previously lived only on
                // MLKEMKTSCipherSpi, and this KEM path (KEMExtractSpec ->
                // SpecNI.decap) never passes through it — so the family had
                // the check on one surface and not the other. See MT-8.
                //
                // InvalidAlgorithmParameterException, not InvalidKeyException:
                // KeyGeneratorSpi.engineInit declares nothing else. The
                // MESSAGE is the canonical one, unlike MLXKEMKeyGenerator's —
                // ML-KEM keys encode as PKCS#8, so "encode it and decode it
                // through this provider's KeyFactory" is real advice here,
                // where for the hybrids it would be a dead end. Do not unify
                // the two messages: the difference is the remedy that exists.
                // Both halves. The library check (MT-8) has teeth only in the
                // unbound direct-SPI realm; instance-equal implies
                // library-equal for anything a provider made.
                if (kem.getSpec().getSpecNI() != specNI
                        || !kem.getSpec().usableBy(providerInstance))
                {
                    throw new InvalidAlgorithmParameterException(
                            "private key was created by a different Jostle provider instance; encode it "
                                    + "with getEncoded() and decode it through this provider's "
                                    + "KeyFactory");
                }
                if (forcedKeyType != OSSLKeyType.NONE && kem.getSpec().getType() != forcedKeyType)
                {
                    throw new InvalidAlgorithmParameterException("expected " + MLKEMParameterSpec.getSpecForOSSLType(forcedKeyType).getName() + " but got " + MLKEMParameterSpec.getSpecForOSSLType(kem.getSpec().getType()).getName());
                }
                if (((KEMExtractSpec) params).getEncapsulation() == null)
                {
                    // A KEMExtractSpec built without an encapsulation would NPE
                    // at engineGenerateKey (wrappedKey.length) — reject at init.
                    throw new InvalidAlgorithmParameterException("KEMExtractSpec has no encapsulation");
                }
                parameterSpec = params;
                // Decap path doesn't consume entropy, but a caller-supplied
                // SecureRandom should still be honoured if they call
                // back through encap on a new init.
                randSource = DefaultRandSource.replaceWith(randSource, random, strengthForKeyType(kem.getSpec().getType()));
                return;
            }
            throw new InvalidAlgorithmParameterException("Only MLKEMPrivateKey is supported");

        }
        else
        {
            if (params instanceof KEMGenerateSpec)
            {
                PublicKey key = ((KEMGenerateSpec) params).getPublicKey();
                if (key instanceof MLKEMPublicKey)
                {
                    extract = false;
                    MLKEMPublicKey kem = (MLKEMPublicKey) key;
                    // MT-14, encap (public) side: instance-only, no library
                    // half. encapsulate() drives the SPEC's NI — the library
                    // that CREATED the key — so a foreign public key object
                    // encapsulated outside this provider while reporting
                    // success. Refuse the object; re-decode to cross.
                    if (!kem.getSpec().usableBy(providerInstance))
                    {
                        throw new InvalidAlgorithmParameterException(
                                "public key was created by a different Jostle provider instance; "
                                        + "encode it with getEncoded() and decode it through this "
                                        + "provider's KeyFactory");
                    }
                    if (forcedKeyType != OSSLKeyType.NONE && kem.getSpec().getType() != forcedKeyType)
                    {
                        throw new InvalidAlgorithmParameterException("expected " + MLKEMParameterSpec.getSpecForOSSLType(forcedKeyType).getName() + " but got " + MLKEMParameterSpec.getSpecForOSSLType(kem.getSpec().getType()).getName());
                    }

                    int keySizeInBits = ((KEMGenerateSpec) params).getKeySizeInBits();
                    if (keySizeInBits < MIN_KEY_SIZE_BITS || keySizeInBits > MAX_KEY_SIZE_BITS)
                    {
                        throw new InvalidAlgorithmParameterException(
                                "KEM key size in bits out of range [" + MIN_KEY_SIZE_BITS + ", " + MAX_KEY_SIZE_BITS + "]: " + keySizeInBits);
                    }

                    int strengthBits = strengthForKeyType(kem.getSpec().getType());

                    // The natural KeyGenerator.init(spec) call has the JCE inject
                    // the platform default SecureRandom (e.g. Windows JDK 9+ hands
                    // us a 128-bit DRBG), which the caller never chose. So rather
                    // than reject a source whose reported strength is below the
                    // algorithm's requirement, drop it and let replaceWith install
                    // a strength-appropriate DRBG (GH #34). A reported 0 means
                    // "unknown" (plain SecureRandom) and is left as-is with the
                    // C-side RAND gate as the safety net; a strong-enough source
                    // is honoured as-is. Only relevant on the encap path.
                    int suppliedStrength = DefaultRandSource.strengthOf(random);
                    if (suppliedStrength > 0 && suppliedStrength < strengthBits)
                    {
                        random = null;
                    }

                    parameterSpec = params;
                    // Resolve / upgrade RandSource for the peer key's variant —
                    // ML-KEM-768/1024 need 192/256-bit strength to pass the
                    // OpenSSL RAND gate (GH issue #34).
                    randSource = DefaultRandSource.replaceWith(randSource, random, strengthBits);
                    return;
                }
                throw new InvalidAlgorithmParameterException("Only MLKEMPublicKey is supported");
            }
            else
            {
                throw new InvalidAlgorithmParameterException("unsupported parameters " + params.getClass().getName());
            }
        }
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SecretKey engineGenerateKey()
    {
        if (parameterSpec == null)
        {
            // generateKey() called before any init — the JCE KeyGenerator
            // state machine requires init first.
            throw new IllegalStateException("not initialized");
        }
        if (extract)
        {
            KEMExtractSpec extractSpec = (KEMExtractSpec) parameterSpec;
            PKEYKeySpec spec = ((OSSLKey) extractSpec.getPrivateKey()).getSpec();
            byte[] wrappedKey = extractSpec.getEncapsulation();
            long len = spec.getSpecNI().decap(spec.getReference(), null, wrappedKey, 0, wrappedKey.length, null, 0, 0, randSource);

            byte[] out = new byte[(int) len];
            try
            {
                len = spec.getSpecNI().decap(spec.getReference(), null, wrappedKey, 0, wrappedKey.length, out, 0, out.length, randSource);

                if (len != out.length)
                {
                    throw new IllegalStateException("encapsulation length mismatch");
                }

                // SecretKeySpec clones its input; the finally scrubs the
                // local copy of the shared secret (wrappedKey is the public
                // encapsulation — not secret, and not ours to clear).
                return new SecretKeyWithEncapsulation(new SecretKeySpec(out, extractSpec.getAlgorithmName()), wrappedKey);
            }
            finally
            {
                Arrays.fill(out, (byte) 0);
            }
        }
        else
        {
            KEMGenerateSpec generateSpec = (KEMGenerateSpec) parameterSpec;
            PKEYKeySpec spec = ((OSSLKey) generateSpec.getPublicKey()).getSpec();
            // engineInit resolved randSource for the peer key's
            // strength category — use it directly.
            byte[] secret = new byte[generateSpec.getKeySizeInBits() / 8];
            try
            {
                int encapsulationLen = encapsulationLengths.get(spec.getType());
                if (encapsulationLen == NativeLengthCache.UNKNOWN)
                {
                    encapsulationLen = spec.getSpecNI().encap(spec.getReference(), null, secret, 0, secret.length, null, 0, 0, randSource);
                    // Memoize OpenSSL's reported encapsulation length for this parameter set.
                    encapsulationLengths.cache(spec.getType(), encapsulationLen);
                }
                byte[] wrappedKey = new byte[encapsulationLen];
                int len = spec.getSpecNI().encap(spec.getReference(), null, secret, 0, secret.length, wrappedKey, 0, wrappedKey.length, randSource);

                if (len != wrappedKey.length)
                {
                    throw new IllegalStateException("encapsulation length mismatch");
                }

                // SecretKeySpec clones its input; the finally scrubs the
                // local copy of the shared secret (wrappedKey is the public
                // encapsulation — not secret).
                return new SecretKeyWithEncapsulation(new SecretKeySpec(secret, generateSpec.getAlgorithmName()), wrappedKey);
            }
            finally
            {
                Arrays.fill(secret, (byte) 0);
            }
        }

    }
}
