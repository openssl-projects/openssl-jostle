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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.util.Arrays;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameter spec for ECDH-with-KDF (and X25519/X448-with-KDF) carrying
 * the optional shared-info / UKM bytes and an optional explicit output
 * key size in bits.
 *
 * <p>Mirrors the shape of BouncyCastle's
 * {@code org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec} at the
 * value level so bcpkix-style callers have a familiar carrier. BC's
 * own spec is also accepted via reflection by
 * {@link ECDHwithKDFKeyAgreementSpi}; this class is the
 * compile-time-typed alternative.
 */
public class KDFParameterSpec implements AlgorithmParameterSpec
{
    private final byte[] sharedInfo;
    private final int keySize;
    private final String digestAlgorithm;

    /**
     * @param sharedInfo      Optional shared info bytes. {@code null} or
     *                        empty array → treated as absent.
     * @param keySize         Desired output key size in bits. Pass 0 to let
     *                        the SPI derive at the digest's natural length
     *                        (or the algorithm-name default for known
     *                        target algorithms).
     * @param digestAlgorithm Optional digest name to use for the KDF.
     *                        {@code null} → use the digest pinned by
     *                        the transformation ({@code ECDHwithSHA256KDF}
     *                        etc.); required when used with the bare
     *                        {@code ECDHwithKDF} transformation.
     */
    public KDFParameterSpec(byte[] sharedInfo, int keySize, String digestAlgorithm)
    {
        this.sharedInfo = Arrays.clone(sharedInfo);
        if (keySize < 0)
        {
            throw new IllegalArgumentException("keySize must be non-negative");
        }
        this.keySize = keySize;
        this.digestAlgorithm = digestAlgorithm;
    }

    public KDFParameterSpec(byte[] sharedInfo, int keySize)
    {
        this(sharedInfo, keySize, null);
    }

    public KDFParameterSpec(byte[] sharedInfo)
    {
        this(sharedInfo, 0, null);
    }

    /** Defensive copy. May be {@code null}. */
    public byte[] getSharedInfo()
    {
        return Arrays.clone(sharedInfo);
    }

    /** Returns 0 if not explicitly set. */
    public int getKeySize()
    {
        return keySize;
    }

    /** Returns {@code null} if not explicitly set. */
    public String getDigestAlgorithm()
    {
        return digestAlgorithm;
    }
}
