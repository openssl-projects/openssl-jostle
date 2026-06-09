/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */
package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.jcajce.util.DigestUtil;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * {@code SecretKeyFactory} surface for HKDF (RFC 5869), backed by the native
 * {@code EVP_KDF "HKDF"} (extract-and-expand) via {@link KdfNI#hkdf}. The digest
 * is fixed per registered algorithm ("HKDF-SHA256" / "HKDF-SHA384" / "HKDF-SHA512");
 * the {@link HKDFParameterSpec} supplies the IKM, optional salt, optional info and
 * the desired output length (in bytes).
 */
public class HKDFSecretKeyFactory extends SecretKeyFactorySpi
{
    private final String digestAlgorithm;

    public HKDFSecretKeyFactory(String digestAlgorithm)
    {
        this.digestAlgorithm = DigestUtil.getCanonicalDigestName(digestAlgorithm);
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        byte[] ikm;
        byte[] salt;
        byte[] info;
        int outputLength;

        if (keySpec instanceof HKDFParameterSpec)
        {
            HKDFParameterSpec spec = (HKDFParameterSpec) keySpec;
            ikm = spec.getIKM();
            salt = spec.getSalt();
            info = spec.getInfo();
            outputLength = spec.getOutputLength();
        }
        else if (keySpec != null)
        {
            // Accept any structurally-compatible HKDFParameterSpec (notably BouncyCastle's
            // org.bouncycastle.jcajce.spec.HKDFParameterSpec) without a compile-time dependency on
            // it, so high-level CMS/OpenPGP builders that construct that type can derive through this
            // native HKDF. Same accessor contract (getIKM/getSalt/getInfo/getOutputLength), same units
            // (output length in bytes). A spec missing any accessor surfaces as InvalidKeySpecException.
            Class<?> cls = keySpec.getClass();
            try
            {
                ikm = (byte[]) cls.getMethod("getIKM").invoke(keySpec);
                salt = (byte[]) cls.getMethod("getSalt").invoke(keySpec);
                info = (byte[]) cls.getMethod("getInfo").invoke(keySpec);
                outputLength = (Integer) cls.getMethod("getOutputLength").invoke(keySpec);
            }
            catch (ReflectiveOperationException | ClassCastException | NullPointerException e)
            {
                throw new InvalidKeySpecException("unsupported KeySpec " + cls.getName(), e);
            }
        }
        else
        {
            throw new InvalidKeySpecException("unsupported KeySpec null");
        }

        if (outputLength <= 0)
        {
            throw new InvalidKeySpecException("output length must be positive");
        }

        byte[] rawKey = new byte[outputLength];

        NISelector.KdfNI.handleErrorCodes(NISelector.KdfNI.hkdf(
                ikm,
                salt,
                info,
                digestAlgorithm,
                rawKey, 0, rawKey.length));

        return new SecretKeySpec(rawKey, "HKDF");
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException
    {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException
    {
        throw new InvalidKeyException("not implemented");
    }
}
