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

package org.openssl.jostle.jcajce.provider.dh;

import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;
import org.openssl.jostle.util.asn1.Der;

import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * Diffie-Hellman {@code AlgorithmParameters}, encoding BOTH forms in house.
 *
 * <pre>
 *   DHParameter    ::= SEQUENCE { prime INTEGER, base INTEGER,
 *                                 privateValueLength INTEGER OPTIONAL }   -- PKCS#3
 *   DomainParameters ::= SEQUENCE { p INTEGER, g INTEGER, q INTEGER,
 *                                 j INTEGER OPTIONAL,
 *                                 validationParms ValidationParms OPTIONAL } -- X9.42
 * </pre>
 *
 * <p>The delegating version could only produce PKCS#3, which has no q field, so
 * the subgroup order was lost on every encode. That is the defect this fixes.
 * BouncyCastle's registered "DH" parameters are PKCS#3-only in both directions
 * and keep X9.42 on OID-disambiguated paths; Jostle deliberately goes further,
 * so the ambiguity is owned here explicitly.
 *
 * <p><b>Emit</b>: q-presence selects the form. State carrying q emits X9.42;
 * without q it emits PKCS#3, byte-exact against the platform provider
 * (measured, including that {@code l} is emitted iff non-zero). There is no
 * caller-request mechanism — this mirrors the fromdata rule where q presence
 * selects the DH vs DHX keymgmt, so the project has one design language for
 * the split.
 *
 * <p><b>Decode</b>: both forms are accepted. A three-INTEGER SEQUENCE is
 * genuinely ambiguous — PKCS#3 {@code {p,g,l}} against X9.42 {@code {p,g,q}} —
 * and is resolved on the THIRD integer's bit length: see
 * {@link #Q_DISCRIMINATOR_BITS}.
 */
public class DHAlgorithmParameters
    extends AlgorithmParametersSpi
{
    /**
     * A third INTEGER of at least this many bits is read as X9.42 q; below it,
     * as a PKCS#3 privateValueLength.
     *
     * <p>The two cannot collide in practice and the gap is enormous: q is a
     * subgroup order, never below 160 bits for any real parameter set, while
     * l is a bit COUNT — even an absurd 2^32-bit private value is a 33-bit
     * integer. 64 sits in the middle of a gap of roughly a hundred bits.
     *
     * <p>Deliberately not a divisibility test on {@code (p-1) mod q == 0} as
     * the primary rule: that has a false-positive path for small l whenever
     * p is congruent to 1 modulo 2^l. It is sound only as a secondary check
     * once the third integer has already been read as q.
     *
     * <p>The split is three-way, not two, and the middle band is deliberate
     * (measured at every boundary):
     *
     * <pre>
     *   bitLength 1..31    -> privateValueLength (PKCS#3)
     *   bitLength 32..63   -> REJECTED
     *   bitLength &gt;= 64    -> q (X9.42)
     * </pre>
     *
     * l is a bit COUNT and must fit an {@code int}, so 32 bits is already
     * absurd for it; q is never that small. The middle band holds neither, so
     * input landing there is malformed and is refused rather than guessed at.
     */
    private static final int Q_DISCRIMINATOR_BITS = 64;

    private BigInteger p;
    private BigInteger g;
    private BigInteger q;
    private BigInteger j;
    private int l;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (!(paramSpec instanceof DHParameterSpec))
        {
            throw new InvalidParameterSpecException(
                    "DH parameters require a DHParameterSpec, got "
                            + (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        DHParameterSpec spec = (DHParameterSpec) paramSpec;
        if (spec.getP() == null || spec.getG() == null)
        {
            throw new InvalidParameterSpecException("DH parameters require p and g");
        }
        this.p = spec.getP();
        this.g = spec.getG();
        this.l = spec.getL();
        this.q = (spec instanceof DHDomainParameterSpec) ? ((DHDomainParameterSpec) spec).getQ() : null;
        this.j = null;
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        if (params == null)
        {
            throw new IOException("null DH parameters");
        }
        Der.Reader r = new Der.Reader(params);
        Der.Reader seq = r.readTLV(Der.SEQUENCE, "DH parameters SEQUENCE");
        r.requireEnd("trailing bytes after DH parameters");

        BigInteger rp = seq.readInteger("DH p");
        BigInteger rg = seq.readInteger("DH g");
        BigInteger rq = null;
        BigInteger rj = null;
        int rl = 0;

        if (!seq.atEnd())
        {
            BigInteger third = seq.readInteger("DH third INTEGER (q or privateValueLength)");
            if (third.bitLength() >= Q_DISCRIMINATOR_BITS)
            {
                rq = third;
                if (!seq.atEnd())
                {
                    // X9.42 j, retained so a re-encode reproduces the input.
                    rj = seq.readInteger("DomainParameters j");
                }
            }
            else
            {
                if (third.bitLength() > 31)
                {
                    // Neither interpretation fits, so say so rather than pick one.
                    throw new IOException(
                            "DH parameters: third INTEGER is " + third.bitLength() + " bits — too large for a"
                                    + " PKCS#3 privateValueLength (a bit count, must fit an int) and too small"
                                    + " for an X9.42 subgroup order q (never below 160 bits). Re-encode as"
                                    + " PKCS#3 DHParameter { p, g, privateValueLength } or as X9.42"
                                    + " DomainParameters { p, g, q }.");
                }
                rl = third.intValue();
                if (!seq.atEnd())
                {
                    throw new IOException("unexpected fourth element in PKCS#3 DHParameter");
                }
            }
        }
        // validationParms is not modelled; anything past j is refused rather
        // than silently dropped, since a re-encode could not reproduce it.
        seq.requireEnd("unsupported trailing elements in DH parameters");

        this.p = rp;
        this.g = rg;
        this.q = rq;
        this.j = rj;
        this.l = rl;
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            engineInit(params);
            return;
        }
        throw new IOException("unsupported DH parameters format: " + format);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
        requireInitialised();
        if (paramSpec == null)
        {
            throw new InvalidParameterSpecException("null parameter spec class");
        }
        if (q != null && paramSpec.isAssignableFrom(DHDomainParameterSpec.class))
        {
            // Answered for a plain DHParameterSpec request too: the domain spec
            // IS one, and downgrading would drop the q this class exists to keep.
            return (T) new DHDomainParameterSpec(p, q, g, l);
        }
        if (paramSpec.isAssignableFrom(DHParameterSpec.class))
        {
            return (T) new DHParameterSpec(p, g, l);
        }
        throw new InvalidParameterSpecException("unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        if (p == null)
        {
            throw new IOException("DH parameters not initialised");
        }
        if (q != null)
        {
            if (j != null)
            {
                return Der.sequence(Der.integer(p), Der.integer(g), Der.integer(q), Der.integer(j));
            }
            return Der.sequence(Der.integer(p), Der.integer(g), Der.integer(q));
        }
        if (l != 0)
        {
            return Der.sequence(Der.integer(p), Der.integer(g), Der.integer(l));
        }
        return Der.sequence(Der.integer(p), Der.integer(g));
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            return engineGetEncoded();
        }
        throw new IOException("unsupported DH parameters format: " + format);
    }

    @Override
    protected String engineToString()
    {
        if (p == null)
        {
            return "DH parameters (uninitialised)";
        }
        return (q != null ? "X9.42 DomainParameters" : "PKCS#3 DHParameter")
                + " [p=" + p.bitLength() + " bits" + (q != null ? ", q=" + q.bitLength() + " bits" : "") + "]";
    }

    private void requireInitialised() throws InvalidParameterSpecException
    {
        if (p == null)
        {
            throw new InvalidParameterSpecException("DH parameters not initialised");
        }
    }
}
