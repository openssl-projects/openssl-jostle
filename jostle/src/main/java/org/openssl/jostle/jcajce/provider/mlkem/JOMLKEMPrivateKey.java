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

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

class JOMLKEMPrivateKey extends AsymmetricKeyImpl implements MLKEMPrivateKey
{
    final boolean seedOnly;

    // Instance field, not a NISelector static: the key is bound to whichever
    // interface library created its PKEY - NISelector for JSL, FIPSNISelector
    // for JSLFIPS - so it must not reach for the base provider's NI.
    private final MLKEMServiceNI mlkemServiceNI;

    public JOMLKEMPrivateKey(PKEYKeySpec spec)
    {
        this(NISelector.MLKEMServiceNI, spec, false);
    }

    public JOMLKEMPrivateKey(PKEYKeySpec spec, boolean seedOnly)
    {
        this(NISelector.MLKEMServiceNI, spec, seedOnly);
    }

    public JOMLKEMPrivateKey(MLKEMServiceNI mlkemServiceNI, PKEYKeySpec spec)
    {
        this(mlkemServiceNI, spec, false);
    }

    public JOMLKEMPrivateKey(MLKEMServiceNI mlkemServiceNI, PKEYKeySpec spec, boolean seedOnly)
    {
        super(spec);
        this.mlkemServiceNI = mlkemServiceNI;
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
        synchronized (this)
        {
            // FIPS 203: AlgorithmIdentifier parameters MUST be absent.
            if (seedOnly)
            {
                return ASN1Encoder.asCanonicalPrivateKeyInfo(spec, PrivateKeyOptions.SEED_ONLY);
            }
            return ASN1Encoder.asCanonicalPrivateKeyInfo(spec, PrivateKeyOptions.DEFAULT);
        }
    }

    public byte[] getSeed()
    {
        synchronized (this)
        {
            // Probe via the RAW NI so a seedless key (imported from an expanded
            // private-key encoding) answers null rather than surfacing a generic
            // OpenSSL error. getPrivateKey(preferSeedOnly) relies on this null
            // to fall back to the expanded key.
            int len = mlkemServiceNI.ni_getSeed(spec.getReference(), null);
            if (len == ErrorCode.JO_SEED_UNAVAILABLE.getCode())
            {
                return null;
            }
            mlkemServiceNI.handleErrors(len);
            byte[] out = new byte[len];
            mlkemServiceNI.handleErrors(mlkemServiceNI.ni_getSeed(spec.getReference(), out));

            return out;
        }
    }

    @Override
    public MLKEMPrivateKey getPrivateKey(boolean preferSeedOnly)
    {
        if (preferSeedOnly)
        {
            byte[] seed = getSeed();
            if (seed != null)
            {
                OSSLKeyType type = getType();
                return new JOMLKEMPrivateKey(
                        mlkemServiceNI,
                        new PKEYKeySpec(
                                spec.getSpecNI(),
                                mlkemServiceNI.generateKeyPair(
                                        type.getKsType(),
                                        seed,
                                        seed.length,
                                        DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom())
                                ), type),
                        preferSeedOnly
                );
            }
        }

        return new JOMLKEMPrivateKey(mlkemServiceNI, spec);
    }

    public byte[] getDirectEncoding()
    {
        //
        // Raw bytes
        //
        synchronized (this)
        {
            long len = mlkemServiceNI.getPrivateKey(spec.getReference(), null);
            byte[] out = new byte[(int) len];
            mlkemServiceNI.getPrivateKey(spec.getReference(), out);

            return out;
        }
    }


    @Override
    public MLKEMPublicKey getPublicKey()
    {
        return new JOMLKEMPublicKey(this.getSpec());
    }

    @Override
    public byte[] getPrivateData()
    {
        return getDirectEncoding();
    }


    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    public MLKEMParameterSpec getParameterSpec()
    {
        MLKEMParameterSpec parameterSpec = MLKEMParameterSpec.getSpecForOSSLType(spec.getType());

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());
        }
        return parameterSpec;
    }

}
