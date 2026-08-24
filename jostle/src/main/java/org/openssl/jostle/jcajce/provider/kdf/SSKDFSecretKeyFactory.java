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
import org.openssl.jostle.jcajce.spec.SSKDFParameterSpec;
import org.openssl.jostle.jcajce.util.DigestUtil;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * {@code SecretKeyFactory} surface for the NIST SP 800-56C one-step KDF, backed
 * by the native {@code EVP_KDF "SSKDF"} via {@link KdfNI#sskdf}. The auxiliary
 * function H is the digest fixed by the registered algorithm name
 * ({@code SSKDF-SHA256} and siblings, following the {@code HKDF-SHA256}
 * precedent); the {@link SSKDFParameterSpec} supplies the shared secret Z, the
 * optional FixedInfo and the output length.
 *
 * <p>Only the DIGEST form of the one-step KDF is served. The MAC-based forms
 * (HMAC, KMAC) are a different construction with a live salt, and would need
 * their own registered names and spec — they are not simply this factory with
 * an extra parameter.</p>
 */
public class SSKDFSecretKeyFactory extends SecretKeyFactorySpi
{
    private final KdfNI kdfNI;
    private final String digestAlgorithm;

    public SSKDFSecretKeyFactory(String digestAlgorithm)
    {
        this(NISelector.KdfNI, digestAlgorithm);
    }

    public SSKDFSecretKeyFactory(KdfNI kdfNI, String digestAlgorithm)
    {
        this.kdfNI = kdfNI;
        this.digestAlgorithm = DigestUtil.getCanonicalDigestName(digestAlgorithm);
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (!(keySpec instanceof SSKDFParameterSpec))
        {
            throw new InvalidKeySpecException("unsupported KeySpec "
                    + (keySpec == null ? "null" : keySpec.getClass().getName()));
        }

        SSKDFParameterSpec spec = (SSKDFParameterSpec) keySpec;

        byte[] secret = spec.getSecret();
        byte[] rawKey = new byte[spec.getOutputLength()];

        try
        {
            kdfNI.handleErrorCodes(kdfNI.sskdf(
                    digestAlgorithm,
                    secret,
                    spec.getInfo(),
                    rawKey, 0, rawKey.length));

            return new SecretKeySpec(rawKey, "SSKDF");
        }
        finally
        {
            Arrays.clear(secret);
            Arrays.clear(rawKey);
        }
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
