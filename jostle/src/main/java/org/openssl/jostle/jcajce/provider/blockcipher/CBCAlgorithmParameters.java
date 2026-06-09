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

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * {@code AlgorithmParameters} for AES-CBC, registered under the AES-CBC OIDs so
 * that callers which resolve the IV parameters by OID through this provider —
 * notably BouncyCastle's PBES2 / PKCS#8 / PKCS#12 decryptors, which do
 * {@code helper.createAlgorithmParameters(<aes-cbc-oid>)} to parse the stored IV
 * {@code OCTET STRING} — can obtain a working instance from "JSL". The ASN.1
 * codec and the {@link javax.crypto.spec.IvParameterSpec} translation are
 * delegated to the JDK's own "AES" {@code AlgorithmParameters}.
 * <p>
 * Mirrors {@link GCMAlgorithmParameters}: the delegate is looked up via
 * {@code AlgorithmParameters.getInstance("AES")} (no provider), and this class
 * is deliberately registered only by OID — never under the bare name "AES" —
 * so the delegate lookup keeps resolving to the JDK provider and cannot recurse
 * back into this class.
 */
public class CBCAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private final AlgorithmParameters delegate;

    public CBCAlgorithmParameters()
    {
        try
        {
            this.delegate = AlgorithmParameters.getInstance("AES");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("no AES AlgorithmParameters available from the platform", e);
        }
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        delegate.init(paramSpec);
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        delegate.init(params);
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException
    {
        delegate.init(params, format);
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
        return delegate.getParameterSpec(paramSpec);
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        return delegate.getEncoded();
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        return delegate.getEncoded(format);
    }

    @Override
    protected String engineToString()
    {
        return delegate.toString();
    }
}
