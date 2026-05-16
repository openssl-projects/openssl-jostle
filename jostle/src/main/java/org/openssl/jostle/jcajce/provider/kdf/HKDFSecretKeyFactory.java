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
import org.openssl.jostle.jcajce.spec.HKDFKeySpec;
import org.openssl.jostle.jcajce.util.DigestUtil;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * JCE SecretKeyFactory wrapping HKDF (RFC 5869) extract-then-expand.
 *
 * <p>The factory consumes an {@link HKDFKeySpec} (the project's
 * pre-JDK-22 spec carrier) and returns a {@code SecretKeySpec} with
 * algorithm {@code "HKDF"} containing the derived key bytes.
 *
 * <p>For provider registration there are two variants:
 * <ol>
 *   <li>{@code HKDF} — accepts any digest specified in the spec
 *       (default registration with {@code forcedDigest == null}).</li>
 *   <li>{@code HKDFwithHmacSHA256} / {@code HKDFwithHmacSHA384} /
 *       {@code HKDFwithHmacSHA512} — pin the digest at construction so
 *       callers asking for a specific transformation get only that
 *       digest. A spec with a different digest is rejected.</li>
 * </ol>
 */
public class HKDFSecretKeyFactory extends SecretKeyFactorySpi
{
    private final String forcedDigestAlgorithm;

    public HKDFSecretKeyFactory()
    {
        this.forcedDigestAlgorithm = null;
    }

    public HKDFSecretKeyFactory(String forcedDigestAlgorithm)
    {
        this.forcedDigestAlgorithm = DigestUtil.getCanonicalDigestName(forcedDigestAlgorithm);
    }


    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (!(keySpec instanceof HKDFKeySpec))
        {
            throw new InvalidKeySpecException(
                    "unsupported key spec: " + (keySpec == null ? "null" : keySpec.getClass().getName())
                            + ". Use HKDFKeySpec.");
        }
        HKDFKeySpec spec = (HKDFKeySpec) keySpec;

        String digest = spec.getPrf();
        if (forcedDigestAlgorithm != null && !forcedDigestAlgorithm.equals(digest))
        {
            throw new InvalidKeySpecException(
                    "PRF in spec " + digest
                            + " does not match forced PRF " + forcedDigestAlgorithm);
        }
        if (digest == null)
        {
            // Bare HKDF registration without forced digest and spec didn't
            // name one — RFC 5869 requires a hash function, so the spec
            // construction should have rejected this. Belt and braces.
            throw new InvalidKeySpecException("HKDFKeySpec did not name a digest algorithm");
        }

        int outLen = spec.getOutLengthBytes();
        byte[] derived = new byte[outLen];

        // KdfNI handles error-code-to-exception mapping; the spec
        // construction itself rejected null/empty IKM, but a downstream
        // OpenSSL failure (e.g. unsupported digest) will surface as the
        // appropriate runtime exception.
        NISelector.KdfNI.handleErrorCodes(NISelector.KdfNI.hkdf(
                spec.getIkm(),
                spec.getSalt(),
                spec.getInfo(),
                digest,
                derived, 0, outLen));

        return new SecretKeySpec(derived, "HKDF");
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException
    {
        throw new UnsupportedOperationException("HKDF does not support extracting the input spec from a derived key");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException
    {
        throw new InvalidKeyException("HKDF SecretKeyFactory does not translate keys");
    }
}
