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

import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASNEncoder;

class JOMLDSAPrivateKey extends AsymmetricKeyImpl implements MLDSAPrivateKey,OSSLKey
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
        return getType().name();
    }

    @Override
    public String getFormat()
    {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        return ASNEncoder.asPrivateKeyInfo(spec);
    }

    public byte[] getSeed()
    {
        long len = NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.getSeed(spec.getReference(), null));
        byte[] out = new byte[(int) len];
        NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.getSeed(spec.getReference(), out));

        return out;
    }

    @Override
    public byte[] getPrivateData()
    {
        //
        // Raw bytes
        //
        long len = NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.getPrivateKey(spec.getReference(), null));
        byte[] out = new byte[(int) len];
        NISelector.MLDSAServiceNI.handleErrors(NISelector.MLDSAServiceNI.getPrivateKey(spec.getReference(), out));

        return out;
    }

    public MLDSAPrivateKey getPrivateKey(boolean preferSeedOnly)
    {
        if (preferSeedOnly)
        {
            byte[] seed = getSeed();
            if (seed != null)
            {
                OSSLKeyType type = getType();
                return new JOMLDSAPrivateKey(
                        new PKEYKeySpec(
                                NISelector.MLDSAServiceNI.handleErrors(
                                        NISelector.MLDSAServiceNI.generateKeyPair(type.getKsType(), seed, seed.length)
                                ), type)
                );
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
