/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

public class AsymmetricKeyImpl
{
    protected final PKEYKeySpec spec;

    public AsymmetricKeyImpl(PKEYKeySpec spec)
    {
        this.spec = spec;
    }

    public OSSLKeyType getType()
    {
        return spec.getType();
    }

    public long getReference()
    {
        return spec.getReference();
    }

    /**
     * Two keys are equal when their encoded forms match. Every concrete subclass
     * implements {@link java.security.Key} (a public key encodes as X.509
     * SubjectPublicKeyInfo, a private key as PKCS#8 PrivateKeyInfo), and the
     * encoding embeds the algorithm OID — so encoding equality already implies
     * same algorithm and same key role (public vs private). We deliberately do
     * NOT compare {@code getAlgorithm()} strings, which are provider-specific
     * (e.g. JSL reports "ML-DSA-44" where the JDK reports "ML-DSA").
     *
     * <p>Without this, JSL keys inherited identity equality, so two instances of
     * the same key never compared equal — breaking callers that key collections
     * on keys or sanity-check a parsed key against a certificate's key.
     *
     * <p>When either operand is a {@link java.security.PrivateKey} the encoded
     * forms contain secret material, so the byte comparison is done with the
     * constant-time {@link java.security.MessageDigest#isEqual} rather than
     * {@link java.util.Arrays#equals} (which short-circuits on the first
     * differing byte and would leak key material through timing).
     */
    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (!(this instanceof java.security.Key) || !(o instanceof java.security.Key))
        {
            return false;
        }
        byte[] mine = ((java.security.Key) this).getEncoded();
        byte[] theirs = ((java.security.Key) o).getEncoded();
        if (mine == null || theirs == null)
        {
            return false;
        }
        if (this instanceof java.security.PrivateKey || o instanceof java.security.PrivateKey)
        {
            // Constant-time: do not short-circuit on secret key material.
            return java.security.MessageDigest.isEqual(mine, theirs);
        }
        return java.util.Arrays.equals(mine, theirs);
    }

    @Override
    public int hashCode()
    {
        if (this instanceof java.security.Key)
        {
            byte[] enc = ((java.security.Key) this).getEncoded();
            if (enc != null)
            {
                return java.util.Arrays.hashCode(enc);
            }
        }
        return System.identityHashCode(this);
    }

}
