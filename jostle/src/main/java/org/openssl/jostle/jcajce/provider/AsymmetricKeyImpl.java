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
import org.openssl.jostle.util.Arrays;

import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;

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
     * <p>When either operand is a {@link PrivateKey} the encoded forms contain
     * secret material, so the byte comparison is done with the constant-time
     * {@link MessageDigest#isEqual} rather than {@link Arrays#areEqual} (which
     * short-circuits on the first differing byte and would leak key material
     * through timing).
     */
    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (!(this instanceof Key) || !(o instanceof Key))
        {
            return false;
        }
        byte[] mine = ((Key) this).getEncoded();
        byte[] theirs = ((Key) o).getEncoded();
        if (mine == null || theirs == null)
        {
            // Guard before areEqual: areEqual(null, null) is true, but two
            // distinct keys whose encodings are unavailable must not be equal.
            return false;
        }
        if (this instanceof PrivateKey || o instanceof PrivateKey)
        {
            // Constant-time: do not short-circuit on secret key material.
            return MessageDigest.isEqual(mine, theirs);
        }
        return Arrays.areEqual(mine, theirs);
    }

    @Override
    public int hashCode()
    {
        if (this instanceof Key)
        {
            byte[] enc = ((Key) this).getEncoded();
            if (enc != null)
            {
                return Arrays.hashCode(enc);
            }
        }
        return System.identityHashCode(this);
    }

}
