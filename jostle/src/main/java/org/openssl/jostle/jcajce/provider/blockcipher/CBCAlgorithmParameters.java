/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;

import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;

import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * CBC {@code AlgorithmParameters} — the IV, encoded in house.
 *
 * <pre>
 *   AES-IV ::= OCTET STRING (SIZE(16))
 * </pre>
 *
 * <p>Registered under the AES-CBC OIDs so OID-driven callers (BC's PBES2 /
 * PKCS#8 / PKCS#12 decryptors) can recover the IV. A bare OCTET STRING, not a
 * SEQUENCE — RFC 3565 s4.1, and what the JDK emits, measured.
 *
 * <p>Previously delegated to {@code AlgorithmParameters.getInstance("AES")},
 * which resolved to whichever provider happened to answer first. The block
 * size is fixed by the OID this SPI is registered under, so there was never
 * anything to look up.
 */
public class CBCAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private static final int IV_LEN = 16;

    private byte[] iv;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (!(paramSpec instanceof IvParameterSpec))
        {
            throw new InvalidParameterSpecException(
                    "CBC parameters require an IvParameterSpec, got "
                            + (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        byte[] v = ((IvParameterSpec) paramSpec).getIV();
        if (v == null || v.length != IV_LEN)
        {
            throw new InvalidParameterSpecException(
                    "CBC IV must be " + IV_LEN + " bytes (got " + (v == null ? "null" : v.length) + ")");
        }
        this.iv = Arrays.clone(v);
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        if (params == null)
        {
            throw new IOException("null CBC parameters");
        }
        Der.Reader r = new Der.Reader(params);
        byte[] v = r.readTLV(Der.OCTET_STRING, "AES-IV OCTET STRING").remaining();
        r.requireEnd("trailing bytes after AES-IV");
        if (v.length != IV_LEN)
        {
            throw new IOException("CBC IV must be " + IV_LEN + " bytes (got " + v.length + ")");
        }
        this.iv = v;
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
        throw new IOException("unsupported CBC parameters format: " + format);
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
        if (paramSpec.isAssignableFrom(IvParameterSpec.class))
        {
            return (T) new IvParameterSpec(Arrays.clone(iv));
        }
        throw new InvalidParameterSpecException("unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        if (iv == null)
        {
            throw new IOException("CBC parameters not initialised");
        }
        return Der.octetString(iv);
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            return engineGetEncoded();
        }
        throw new IOException("unsupported CBC parameters format: " + format);
    }

    @Override
    protected String engineToString()
    {
        return iv == null ? "AES-IV (uninitialised)" : "AES-IV [" + iv.length + " bytes]";
    }

    private void requireInitialised() throws InvalidParameterSpecException
    {
        if (iv == null)
        {
            throw new InvalidParameterSpecException("CBC parameters not initialised");
        }
    }
}
