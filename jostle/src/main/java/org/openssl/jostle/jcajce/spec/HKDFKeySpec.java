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

import org.openssl.jostle.jcajce.util.DigestUtil;
import org.openssl.jostle.util.Arrays;

import java.security.spec.KeySpec;

/**
 * KeySpec for HKDF (RFC 5869) extract-then-expand. Carries the four
 * RFC-defined inputs (IKM, salt, info, output length) plus the digest
 * to drive HMAC.
 *
 * <p>This class predates {@code javax.crypto.spec.HKDFParameterSpec}
 * (introduced in JDK 22). When Jostle is consumed from a JDK 22+ host,
 * the {@code KDF}-based JCE entry point should be preferred; the
 * {@link javax.crypto.SecretKeyFactory} surface that consumes this spec
 * remains as the pre-22 fallback and continues to work on JDK 22+ for
 * compatibility with callers that haven't migrated.
 *
 * <p>Per the RFC, salt and info are optional. {@code null} or an empty
 * byte array is accepted for each. IKM and the digest are mandatory and
 * rejected by the constructor if missing.
 */
public class HKDFKeySpec implements KeySpec
{
    private final byte[] ikm;
    private final byte[] salt;
    private final byte[] info;
    private final int outLengthBytes;
    private final String prf;

    /**
     * @param ikm             Input keying material (RFC 5869 "IKM"). Must be non-null and non-empty.
     * @param salt            Optional salt. May be null or empty.
     * @param info            Optional context / application-specific info. May be null or empty.
     * @param outLengthBytes  Required output length in bytes; must be >0.
     *                        Per RFC 5869 §2.3 the upper bound is 255 * HashLen, but we let the
     *                        native EVP_KDF surface that as an error rather than guess the hash
     *                        size here.
     * @param digestAlgorithm Hash algorithm (e.g. "SHA-256"). Resolved through
     *                        {@link DigestUtil#getCanonicalDigestName}.
     */
    public HKDFKeySpec(byte[] ikm, byte[] salt, byte[] info, int outLengthBytes, String digestAlgorithm)
    {
        if (ikm == null)
        {
            throw new IllegalArgumentException("ikm is null");
        }
        if (ikm.length == 0)
        {
            throw new IllegalArgumentException("ikm is empty");
        }
        if (outLengthBytes <= 0)
        {
            throw new IllegalArgumentException("outLengthBytes must be positive");
        }
        if (digestAlgorithm == null)
        {
            throw new IllegalArgumentException("digestAlgorithm is null");
        }
        this.ikm = Arrays.clone(ikm);
        this.salt = Arrays.clone(salt);
        this.info = Arrays.clone(info);
        this.outLengthBytes = outLengthBytes;
        this.prf = DigestUtil.getCanonicalDigestName(digestAlgorithm);
    }

    /** Defensive copy. Never null. */
    public byte[] getIkm()
    {
        return Arrays.clone(ikm);
    }

    /** Defensive copy. May be null. */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    /** Defensive copy. May be null. */
    public byte[] getInfo()
    {
        return Arrays.clone(info);
    }

    public int getOutLengthBytes()
    {
        return outLengthBytes;
    }

    public String getPrf()
    {
        return prf;
    }
}
