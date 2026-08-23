/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.slhdsa;

import org.openssl.jostle.jcajce.interfaces.SLHDSAPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.util.asn1.ASN1Encoder;

class JOSLHDSAPublicKey extends AsymmetricKeyImpl implements SLHDSAPublicKey
{
    // Instance field, not a NISelector static: the key is bound to whichever
    // interface library created its PKEY - NISelector for JSL, FIPSNISelector
    // for JSLFIPS - so it must not reach for the base provider's NI.
    private final SLHDSAServiceNI slhdsaServiceNI;

    public JOSLHDSAPublicKey(PKEYKeySpec spec)
    {
        this(NISelector.SLHDSAServiceNI, spec);
    }

    public JOSLHDSAPublicKey(SLHDSAServiceNI slhdsaServiceNI, PKEYKeySpec spec)
    {
        super(spec);
        this.slhdsaServiceNI = slhdsaServiceNI;
    }

    @Override
    public String getAlgorithm()
    {
        return getType().getAlgorithmName();
    }

    @Override
    public String getFormat()
    {
        return "X.509";
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
            // FIPS 205: AlgorithmIdentifier parameters MUST be absent.
            return ASN1Encoder.asCanonicalSubjectPublicKeyInfo(spec);
        }
    }

    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    public SLHDSAParameterSpec getParameterSpec()
    {

        SLHDSAParameterSpec slhdsaParameterSpec = SLHDSAParameterSpec.getSpecForOSSLType(spec.getType());

        if (slhdsaParameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());
        }
        return slhdsaParameterSpec;
    }

    @Override
    public byte[] getPublicData()
    {
        //
        // Raw bytes
        //
        synchronized (this)
        {
            long len = slhdsaServiceNI.getPublicKey(spec.getReference(), null);
            byte[] out = new byte[(int) len];
            slhdsaServiceNI.getPublicKey(spec.getReference(), out);

            return out;
        }
    }
}
