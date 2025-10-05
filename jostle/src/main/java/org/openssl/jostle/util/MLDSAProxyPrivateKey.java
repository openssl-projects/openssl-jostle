package org.openssl.jostle.util;

import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

import java.security.PublicKey;

public class MLDSAProxyPrivateKey implements MLDSAPrivateKey
{
    private final MLDSAPublicKey publicKey;
    private final PKEYKeySpec spec;

    public MLDSAProxyPrivateKey(PublicKey publicKey)
    {
        if (!(publicKey instanceof MLDSAPublicKey))
        {
            throw new IllegalArgumentException("public key must be an ML-DSA public key");
        }
        this.publicKey = (MLDSAPublicKey) publicKey;
        this.spec = ((MLDSAPublicKey) publicKey).getSpec();
    }

    public MLDSAPublicKey getPublicKey()
    {
        return publicKey;
    }

    @Override
    public String getAlgorithm()
    {
        return publicKey.getAlgorithm();
    }

    @Override
    public String getFormat()
    {
        return null;
    }

    @Override
    public byte[] getEncoded()
    {
        return new byte[0];
    }

    @Override
    public MLDSAParameterSpec getParameterSpec()
    {
        return publicKey.getParameterSpec();
    }

    @Override
    public byte[] getPrivateData()
    {
        return new byte[0];
    }

    @Override
    public byte[] getSeed()
    {
        return new byte[0];
    }

    @Override
    public MLDSAPrivateKey getPrivateKey(boolean preferSeedOnly)
    {
        return null;
    }

    @Override
    public PKEYKeySpec getSpec()
    {
        return spec;
    }
}
