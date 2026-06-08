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
 * {@code AlgorithmParameters} for AES-GCM, registered under the AES-GCM OIDs so
 * that callers which resolve parameters by OID (notably the CMS EnvelopedData
 * decryption path, which does {@code AlgorithmParameters.getInstance(<aes-gcm-oid>, "JSL")}
 * then loads the stored {@code GCMParameters} to recover the nonce/ICV length)
 * can obtain a working instance from this provider. The ASN.1 codec and the
 * {@code GCMParameterSpec} translation are delegated to the JDK's own "GCM"
 * {@code AlgorithmParameters}.
 * <p>
 * Deliberately NOT registered under the bare name "GCM": the delegate is looked
 * up via {@code AlgorithmParameters.getInstance("GCM")} (no provider), so
 * claiming that name here could resolve back to this class and recurse. Resolving
 * only by OID keeps the delegate pointing at the JDK provider.
 */
public class GCMAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private final AlgorithmParameters delegate;

    public GCMAlgorithmParameters()
    {
        try
        {
            this.delegate = AlgorithmParameters.getInstance("GCM");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("no GCM AlgorithmParameters available from the platform", e);
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
