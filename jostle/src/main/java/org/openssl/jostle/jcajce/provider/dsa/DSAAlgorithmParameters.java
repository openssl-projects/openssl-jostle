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

package org.openssl.jostle.jcajce.provider.dsa;

import org.openssl.jostle.util.asn1.Der;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * DSA {@code AlgorithmParameters} — the domain parameters, encoded in house.
 *
 * <pre>
 *   Dss-Parms ::= SEQUENCE { p INTEGER, q INTEGER, g INTEGER }   -- RFC 3279 s2.3.2
 * </pre>
 *
 * <p>Previously delegated to a non-Jostle provider's DSA
 * {@code AlgorithmParameters}, resolved by walking the installed providers and
 * skipping Jostle by package prefix so {@code getInstance("DSA")} could not
 * recurse into this class. The codec is three integers; there was nothing to
 * delegate, and with the delegate gone the recursion hazard goes with it.
 */
public class DSAAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (!(paramSpec instanceof DSAParameterSpec))
        {
            throw new InvalidParameterSpecException(
                    "DSA parameters require a DSAParameterSpec, got "
                            + (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        DSAParameterSpec spec = (DSAParameterSpec) paramSpec;
        if (spec.getP() == null || spec.getQ() == null || spec.getG() == null)
        {
            throw new InvalidParameterSpecException("DSA parameters require p, q and g");
        }
        this.p = spec.getP();
        this.q = spec.getQ();
        this.g = spec.getG();
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        if (params == null)
        {
            throw new IOException("null DSA parameters");
        }
        Der.Reader r = new Der.Reader(params);
        Der.Reader seq = r.readTLV(Der.SEQUENCE, "Dss-Parms SEQUENCE");
        r.requireEnd("trailing bytes after Dss-Parms");

        BigInteger rp = seq.readInteger("Dss-Parms p");
        BigInteger rq = seq.readInteger("Dss-Parms q");
        BigInteger rg = seq.readInteger("Dss-Parms g");
        seq.requireEnd("trailing bytes inside Dss-Parms");

        this.p = rp;
        this.q = rq;
        this.g = rg;
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
        throw new IOException("unsupported DSA parameters format: " + format);
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
        if (paramSpec.isAssignableFrom(DSAParameterSpec.class))
        {
            return (T) new DSAParameterSpec(p, q, g);
        }
        throw new InvalidParameterSpecException("unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        if (p == null)
        {
            throw new IOException("DSA parameters not initialised");
        }
        return Der.sequence(Der.integer(p), Der.integer(q), Der.integer(g));
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            return engineGetEncoded();
        }
        throw new IOException("unsupported DSA parameters format: " + format);
    }

    @Override
    protected String engineToString()
    {
        return p == null ? "Dss-Parms (uninitialised)" : "Dss-Parms [p=" + p.bitLength() + " bits, q=" + q.bitLength() + " bits]";
    }

    private void requireInitialised() throws InvalidParameterSpecException
    {
        if (p == null)
        {
            throw new InvalidParameterSpecException("DSA parameters not initialised");
        }
    }
}
