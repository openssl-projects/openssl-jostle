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
 * KeySpec for the ANSI X9.63 KDF (also SP 800-56A "concatenation KDF",
 * the {@code ASN.1 KDF} family used by CMS for ECDH-derived key wrap).
 * Carries the secret {@code Z} (typically the raw ECDH shared secret),
 * optional shared-info (the "UserKeyingMaterial" of CMS / RFC 5753
 * §7.2), a required output length in bytes, and the digest driving
 * the iterated hash.
 *
 * <p>The X9.63 KDF predates {@link javax.crypto.spec.HKDFParameterSpec}
 * (JDK 22) and doesn't have a JDK-supplied carrier, so we provide one.
 * Same shape and rules as {@link HKDFKeySpec} — the only structural
 * difference is that X9.63 has no separate "salt" input (the
 * {@code sharedInfo} is appended after each iteration's counter, not
 * mixed in via an HMAC extract step).
 */
public class X963KDFKeySpec implements KeySpec
{
    private final byte[] z;
    private final byte[] sharedInfo;
    private final int outLengthBytes;
    private final String prf;

    /**
     * @param z               Secret value to derive from. Must be non-null and non-empty.
     * @param sharedInfo      Optional shared info. May be null or empty.
     * @param outLengthBytes  Required output length in bytes; must be &gt; 0.
     * @param digestAlgorithm Hash algorithm (e.g. "SHA-256"). Resolved through
     *                        {@link DigestUtil#getCanonicalDigestName}.
     */
    public X963KDFKeySpec(byte[] z, byte[] sharedInfo, int outLengthBytes, String digestAlgorithm)
    {
        if (z == null)
        {
            throw new IllegalArgumentException("z is null");
        }
        if (z.length == 0)
        {
            throw new IllegalArgumentException("z is empty");
        }
        if (outLengthBytes <= 0)
        {
            throw new IllegalArgumentException("outLengthBytes must be positive");
        }
        if (digestAlgorithm == null)
        {
            throw new IllegalArgumentException("digestAlgorithm is null");
        }
        this.z = Arrays.clone(z);
        this.sharedInfo = Arrays.clone(sharedInfo);
        this.outLengthBytes = outLengthBytes;
        this.prf = DigestUtil.getCanonicalDigestName(digestAlgorithm);
    }

    /** Defensive copy. Never null. */
    public byte[] getZ()
    {
        return Arrays.clone(z);
    }

    /** Defensive copy. May be null. */
    public byte[] getSharedInfo()
    {
        return Arrays.clone(sharedInfo);
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
