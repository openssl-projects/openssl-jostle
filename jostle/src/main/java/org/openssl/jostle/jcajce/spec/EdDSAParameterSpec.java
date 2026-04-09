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

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.jcajce.provider.EdECObjectIdentifiers;

import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

public class EdDSAParameterSpec implements AlgorithmParameterSpec
{
    private final OSSLKeyType keyType;
    private final String curveName;

    public static final EdDSAParameterSpec ED25519 = new EdDSAParameterSpec("Ed25519");
    public static final EdDSAParameterSpec ED448 = new EdDSAParameterSpec("Ed448");


    public EdDSAParameterSpec(String curveName)
    {
        if ("Ed25519".equalsIgnoreCase(curveName))
        {
            this.keyType = OSSLKeyType.ED25519;
            this.curveName = "ED25519";
        }
        else if ("Ed448".equalsIgnoreCase(curveName))
        {
            this.keyType = OSSLKeyType.ED448;
            this.curveName = "ED448";
        }
        else if (curveName.equals(EdECObjectIdentifiers.id_Ed25519.getId()))
        {
            this.keyType = OSSLKeyType.ED25519;
            this.curveName = "ED25519";
        }
        else if (curveName.equals(EdECObjectIdentifiers.id_Ed448.getId()))
        {
            this.keyType = OSSLKeyType.ED448;
            this.curveName = "ED448";
        }
        else
        {
            throw new InvalidParameterException("Unknown EdDSA curve name: " + curveName);
        }
    }

    public OSSLKeyType getKeyType()
    {
        return keyType;
    }

    public String getName()
    {
        return curveName;
    }

    @Override
    public boolean equals(Object object)
    {
        if (!(object instanceof EdDSAParameterSpec))
        {
            return false;
        }
        EdDSAParameterSpec that = (EdDSAParameterSpec) object;
        return keyType == that.keyType;
    }

    @Override
    public int hashCode()
    {
        return Objects.hashCode(keyType);
    }
}












