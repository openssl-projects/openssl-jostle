/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

/**
 * DH domain parameters carrying the subgroup order q — the X9.42 form.
 *
 * <p>{@code javax.crypto.spec.DHParameterSpec} has no q, so it can only
 * describe PKCS#3 parameters. q decides two things a caller can observe:
 *
 * <ul>
 *   <li><b>The encoding.</b> A key generated from these parameters encodes as
 *       X9.42 {@code dhpublicnumber} (1.2.840.10046.2.1); one generated from a
 *       plain {@link DHParameterSpec} encodes as PKCS#3
 *       {@code dhKeyAgreement} (1.2.840.113549.1.3.1).</li>
 *   <li><b>Whether a FIPS module will agree with the key at all.</b> The
 *       validated modules require q for their SP 800-56A key check and refuse
 *       {@code derive} without it.</li>
 * </ul>
 *
 * <p>Named to match BouncyCastle's {@code org.bouncycastle.jcajce.spec.DHDomainParameterSpec}
 * for caller familiarity, but it is a DIFFERENT class: a BC spec handed to
 * Jostle presents only as {@link DHParameterSpec}, so its q is not seen and
 * the result is PKCS#3. Use this class with the Jostle provider.
 *
 * <p>The X9.42 {@code j} cofactor and validation parameters are not carried.
 * They survive a DER round trip — OpenSSL preserves what it decoded — but
 * Jostle never generates them.
 */
public class DHDomainParameterSpec extends DHParameterSpec
{
    private final BigInteger q;

    /**
     * @param p prime modulus.
     * @param q subgroup order. Must not be null; use {@link DHParameterSpec}
     *          for the PKCS#3 form.
     * @param g generator.
     */
    public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g)
    {
        this(p, q, g, 0);
    }

    /**
     * @param l private-value length in bits, or 0 for unspecified.
     */
    public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g, int l)
    {
        super(p, g, l);
        if (q == null)
        {
            throw new IllegalArgumentException("q is null; use DHParameterSpec for PKCS#3 parameters");
        }
        this.q = q;
    }

    /** The subgroup order. Never null. */
    public BigInteger getQ()
    {
        return q;
    }
}
