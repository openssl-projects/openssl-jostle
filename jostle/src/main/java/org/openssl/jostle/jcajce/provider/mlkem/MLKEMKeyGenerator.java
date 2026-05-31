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
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.*;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

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

    private boolean extract;
    private final OSSLKeyType forcedKeyType;
    private AlgorithmParameterSpec parameterSpec;
    private RandSource randSource;


    public MLKEMKeyGenerator(MLKEMParameterSpec spec)
    {
        this.forcedKeyType = spec.getKeyType();
        randSource = DefaultRandSource.replaceWith(null, null, strengthForKeyType(forcedKeyType));
    }

    public MLKEMKeyGenerator()
    {
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
                if (forcedKeyType != OSSLKeyType.NONE && kem.getSpec().getType() != forcedKeyType)
                {
                    throw new InvalidAlgorithmParameterException("expected " + MLKEMParameterSpec.getSpecForOSSLType(forcedKeyType).getName() + " but got " + MLKEMParameterSpec.getSpecForOSSLType(kem.getSpec().getType()).getName());
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
                    if (forcedKeyType != OSSLKeyType.NONE && kem.getSpec().getType() != forcedKeyType)
                    {
                        throw new InvalidAlgorithmParameterException("expected " + MLKEMParameterSpec.getSpecForOSSLType(forcedKeyType).getName() + " but got " + MLKEMParameterSpec.getSpecForOSSLType(kem.getSpec().getType()).getName());
                    }

                    int strengthBits = strengthForKeyType(kem.getSpec().getType());

                    // Fail fast if the caller supplied a SecureRandom
                    // that reports a strength below the algorithm's
                    // requirement (Java 9+ DRBG path). Sources that
                    // don't expose a strength claim return 0 and are
                    // accepted — the C-side RAND gate is the safety
                    // net for those. Only enforced on the encap path:
                    // decap doesn't consume entropy.
                    int suppliedStrength = DefaultRandSource.strengthOf(random);
                    if (suppliedStrength > 0 && suppliedStrength < strengthBits)
                    {
                        throw new InvalidAlgorithmParameterException(
                                "supplied SecureRandom reports " + suppliedStrength
                                        + "-bit strength but " + MLKEMParameterSpec.getSpecForOSSLType(kem.getSpec().getType()).getName()
                                        + " requires " + strengthBits);
                    }

                    parameterSpec = params;
                    // Resolve / upgrade RandSource for the peer key's
                    // variant — ML-KEM-768/1024 need 192/256-bit
                    // strength to pass the OpenSSL RAND gate
                    // (GH issue #34).
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
        if (extract)
        {
            KEMExtractSpec extractSpec = (KEMExtractSpec) parameterSpec;
            PKEYKeySpec spec = ((OSSLKey) extractSpec.getPrivateKey()).getSpec();
            byte[] wrappedKey = extractSpec.getEncapsulation();
            long len = NISelector.SpecNI.decap(spec.getReference(), null, wrappedKey, 0, wrappedKey.length, null, 0, 0);

            byte[] out = new byte[(int) len];
            len = NISelector.SpecNI.decap(spec.getReference(), null, wrappedKey, 0, wrappedKey.length, out, 0, out.length);

            if (len != out.length)
            {
                throw new IllegalStateException("encapsulation length mismatch");
            }

            return new SecretKeyWithEncapsulation(new SecretKeySpec(out, extractSpec.getAlgorithmName()), wrappedKey);

        }
        else
        {
            KEMGenerateSpec generateSpec = (KEMGenerateSpec) parameterSpec;
            PKEYKeySpec spec = ((OSSLKey) generateSpec.getPublicKey()).getSpec();
            // engineInit resolved randSource for the peer key's
            // strength category — use it directly.
            byte[] secret = new byte[generateSpec.getKeySizeInBits() / 8];
            int encapsulationLen = MLKEMLengths.getEncapsulationLength(spec.getType());
            if (encapsulationLen == MLKEMLengths.UNKNOWN_ENCAPSULATION_LENGTH)
            {
                encapsulationLen = NISelector.SpecNI.encap(spec.getReference(), null, secret, 0, secret.length, null, 0, 0, randSource);
            }
            byte[] wrappedKey = new byte[encapsulationLen];
            int len = NISelector.SpecNI.encap(spec.getReference(), null, secret, 0, secret.length, wrappedKey, 0, wrappedKey.length, randSource);

            if (len != wrappedKey.length)
            {
                throw new IllegalStateException("encapsulation length mismatch");
            }

            return new SecretKeyWithEncapsulation(new SecretKeySpec(secret, generateSpec.getAlgorithmName()), wrappedKey);
        }

    }
}
