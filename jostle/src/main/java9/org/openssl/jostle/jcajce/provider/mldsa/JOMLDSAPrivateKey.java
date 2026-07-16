/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mldsa;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

import java.lang.ref.Reference;

class JOMLDSAPrivateKey extends AsymmetricKeyImpl implements MLDSAPrivateKey, OSSLKey
{
    final boolean seedOnly;

    public JOMLDSAPrivateKey(PKEYKeySpec spec)
    {
        super(spec);
        seedOnly = false;
    }

    public JOMLDSAPrivateKey(PKEYKeySpec spec, boolean seedOnly)
    {
        super(spec);
        this.seedOnly = seedOnly;
    }

    @Override
    public String getAlgorithm()
    {
        return getType().getAlgorithmName();
    }

    @Override
    public String getFormat()
    {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        // synchronized(this) keeps this key (and thus its PKEYKeySpec) reachable
        // across the native encoding call in ASN1Encoder, which reads
        // spec.getReference() but does not itself fence the spec — the caller
        // must. See java-spi.md "Native references must outlive every JNI/FFI call".
        try
        {
            // FIPS 204: AlgorithmIdentifier parameters MUST be absent.
            if (seedOnly)
            {
                return ASN1Encoder.asCanonicalPrivateKeyInfo(spec, PrivateKeyOptions.SEED_ONLY);
            }
            return ASN1Encoder.asCanonicalPrivateKeyInfo(spec, PrivateKeyOptions.DEFAULT);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    public byte[] getSeed()
    {
        try
        {
            // A key imported from an expanded encoding has no retrievable seed:
            // the raw NI getter returns JO_SEED_UNAVAILABLE, which we answer as
            // null (rather than surfacing it as an error) so getPrivateKey(true)
            // can fall back to the expanded key.
            int len = NISelector.MLDSAServiceNI.ni_getSeed(spec.getReference(), null);
            if (len == ErrorCode.JO_SEED_UNAVAILABLE.getCode())
            {
                return null;
            }
            NISelector.MLDSAServiceNI.handleErrors(len);
            byte[] out = new byte[len];
            NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.ni_getSeed(spec.getReference(), out));

            return out;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public byte[] getPrivateData()
    {
        //
        // Raw bytes
        //
        try
        {
            long len = NISelector.MLDSAServiceNI.getPrivateKey(spec.getReference(), null);
            byte[] out = new byte[(int) len];
            NISelector.MLDSAServiceNI.getPrivateKey(spec.getReference(), out);

            return out;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    public MLDSAPrivateKey getPrivateKey(boolean preferSeedOnly)
    {
        if (preferSeedOnly)
        {
            byte[] seed = getSeed();
            if (seed != null)
            {
                try
                {
                    OSSLKeyType type = getType();
                    return new JOMLDSAPrivateKey(
                            new PKEYKeySpec(

                                            NISelector.MLDSAServiceNI.generateKeyPair(type.getKsType(), seed, seed.length,
                                                    DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom())
                                    ), type), preferSeedOnly
                    );
                }
                finally
                {
                    // Scrub the transient seed once the keypair is derived.
                    Arrays.clear(seed);
                }
            }
        }

        return new JOMLDSAPrivateKey(spec);
    }


    @Override
    public MLDSAPublicKey getPublicKey()
    {
        return new JOMLDSAPublicKey(spec);
    }

    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    public MLDSAParameterSpec getParameterSpec()
    {
        switch (spec.getType())
        {
            case ML_DSA_44:
                return MLDSAParameterSpec.ml_dsa_44;
            case ML_DSA_87:
                return MLDSAParameterSpec.ml_dsa_87;
            case ML_DSA_65:
                return MLDSAParameterSpec.ml_dsa_65;

            default:
                throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());

        }
    }

}
