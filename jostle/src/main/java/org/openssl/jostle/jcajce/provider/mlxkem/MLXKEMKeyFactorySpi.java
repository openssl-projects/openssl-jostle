/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlxkem;

import org.openssl.jostle.jcajce.interfaces.MLXKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMPublicKeySpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * KeyFactory for one hybrid group.
 *
 * <p>Public keys only, and raw only. These groups have no ASN.1 encoding, so
 * there is no X509EncodedKeySpec / PKCS8EncodedKeySpec path, and private keys
 * are not importable or exportable at all - the provider releases the private
 * material for the X25519 / X448 hybrids and refuses it for the SecP ones, so
 * offering the operation would be honouring it on half the family.
 * {@code engineGeneratePrivate} and the private arm of
 * {@code engineGetKeySpec} therefore reject rather than half-work.
 */
public class MLXKEMKeyFactorySpi extends KeyFactorySpi
{
    private final MLXKEMParameterSpec parameterSpec;

    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final MLXKEMServiceNI mlxkemServiceNI;
    private final SpecNI specNI;

    public MLXKEMKeyFactorySpi(MLXKEMParameterSpec parameterSpec)
    {
        this(NISelector.MLXKEMServiceNI, NISelector.SpecNI, parameterSpec);
    }

    public MLXKEMKeyFactorySpi(MLXKEMServiceNI mlxkemServiceNI, SpecNI specNI,
                               MLXKEMParameterSpec parameterSpec)
    {
        this.mlxkemServiceNI = mlxkemServiceNI;
        this.specNI = specNI;
        this.parameterSpec = parameterSpec;
    }

    /**
     * The SpecNI this factory's keys are bound to.
     */
    SpecNI ownSpecNI()
    {
        return specNI;
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (!(keySpec instanceof MLXKEMPublicKeySpec))
        {
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
        }

        MLXKEMPublicKeySpec pubSpec = (MLXKEMPublicKeySpec) keySpec;
        if (pubSpec.getParameterSpec() != parameterSpec)
        {
            throw new InvalidKeySpecException("expected " + parameterSpec.getName()
                    + " but got " + (pubSpec.getParameterSpec() == null
                    ? "no parameter set" : pubSpec.getParameterSpec().getName()));
        }

        OSSLKeyType keyType = parameterSpec.getKeyType();
        byte[] raw = pubSpec.getPublicData();
        if (raw == null)
        {
            throw new InvalidKeySpecException("key spec carries no public data");
        }

        try
        {
            PKEYKeySpec pkeySpec = new PKEYKeySpec(specNI, specNI.allocate(), keyType);
            mlxkemServiceNI.decode_publicKey(pkeySpec.getReference(), keyType.getKsType(),
                    raw, 0, raw.length);
            return new JOMLXKEMPublicKey(mlxkemServiceNI, pkeySpec);
        }
        catch (RuntimeException e)
        {
            // The native decoder surfaces a malformed share as
            // OpenSSLException / IllegalArgumentException; the KeyFactory
            // contract requires InvalidKeySpecException.
            throw new InvalidKeySpecException("unable to decode " + parameterSpec.getName() + " public key", e);
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException
    {
        throw new InvalidKeySpecException(
                "hybrid KEM private keys cannot be imported; they exist only inside the provider");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException
    {
        if (key instanceof JOMLXKEMPublicKey)
        {
            if (MLXKEMPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                JOMLXKEMPublicKey mKey = (JOMLXKEMPublicKey) key;
                return keySpec.cast(new MLXKEMPublicKeySpec(mKey.getParameterSpec(), mKey.getPublicData()));
            }
            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec);
        }
        if (key instanceof MLXKEMPrivateKey)
        {
            throw new InvalidKeySpecException(
                    "hybrid KEM private keys cannot be exported; they exist only inside the provider");
        }
        throw new InvalidKeySpecException("Invalid Key: " + key);
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException
    {
        if (key == null)
        {
            throw new InvalidKeyException("Invalid Key: null");
        }
        if (key instanceof MLXKEMPublicKey || key instanceof MLXKEMPrivateKey)
        {
            // Already ours. Note this accepts a public key from the OTHER
            // Jostle provider by design (public material carries no secret and
            // re-imports into the receiving lib ctx); a foreign PRIVATE key is
            // rejected below by the key-isolation check in the operation SPIs.
            return key;
        }
        // Nothing to re-encode through: a foreign hybrid key has no encoded
        // form either, so there is no neutral crossing to attempt.
        throw new InvalidKeyException("cannot translate a foreign hybrid KEM key: these keys have no encoding");
    }
}
