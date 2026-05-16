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

package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.X963KDFKeySpec;
import org.openssl.jostle.jcajce.util.DigestUtil;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Standalone {@link SecretKeyFactorySpi} wrapping the ANSI X9.63 KDF.
 *
 * <p>Most CMP / CMS callers will hit this via the composed
 * {@code ECDHwithSHA*KDF} KeyAgreement transformation rather than
 * directly. Direct exposure is useful for SP 800-56A KDF callers and
 * for tests / KAT verification.
 */
public class X963KDFSecretKeyFactory extends SecretKeyFactorySpi
{
    private final String forcedDigestAlgorithm;

    public X963KDFSecretKeyFactory()
    {
        this.forcedDigestAlgorithm = null;
    }

    public X963KDFSecretKeyFactory(String forcedDigestAlgorithm)
    {
        this.forcedDigestAlgorithm = DigestUtil.getCanonicalDigestName(forcedDigestAlgorithm);
    }


    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (!(keySpec instanceof X963KDFKeySpec))
        {
            throw new InvalidKeySpecException(
                    "unsupported key spec: " + (keySpec == null ? "null" : keySpec.getClass().getName())
                            + ". Use X963KDFKeySpec.");
        }
        X963KDFKeySpec spec = (X963KDFKeySpec) keySpec;

        String digest = spec.getPrf();
        if (forcedDigestAlgorithm != null && !forcedDigestAlgorithm.equals(digest))
        {
            throw new InvalidKeySpecException(
                    "PRF in spec " + digest
                            + " does not match forced PRF " + forcedDigestAlgorithm);
        }
        if (digest == null)
        {
            throw new InvalidKeySpecException("X963KDFKeySpec did not name a digest algorithm");
        }

        int outLen = spec.getOutLengthBytes();
        byte[] derived = new byte[outLen];

        NISelector.KdfNI.handleErrorCodes(NISelector.KdfNI.x963kdf(
                spec.getZ(),
                spec.getSharedInfo(),
                digest,
                derived, 0, outLen));

        return new SecretKeySpec(derived, "X963KDF");
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException
    {
        throw new UnsupportedOperationException(
                "X963KDF does not support extracting the input spec from a derived key");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException
    {
        throw new InvalidKeyException("X963KDF SecretKeyFactory does not translate keys");
    }
}
