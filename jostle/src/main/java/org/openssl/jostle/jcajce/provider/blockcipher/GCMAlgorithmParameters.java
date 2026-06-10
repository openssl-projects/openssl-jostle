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

import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * {@code AlgorithmParameters} for AES-GCM, registered under the bare name
 * {@code "GCM"} and the AES-GCM OIDs so callers can resolve GCM parameters from
 * this provider either way — by OID (notably the CMS EnvelopedData decryption
 * path, {@code AlgorithmParameters.getInstance(<aes-gcm-oid>, "JSL")}, recovering
 * the stored nonce/ICV length) or by name (a JSL-bound helper doing
 * {@code helper.createAlgorithmParameters("GCM")}). The ASN.1 codec and the
 * {@code GCMParameterSpec} translation are delegated to a platform GCM
 * {@code AlgorithmParameters} (SunJCE on a standard JDK).
 *
 * <p>Because this IS registered under the bare name {@code "GCM"}, the delegate
 * must be resolved from a provider that is NOT Jostle, or
 * {@code getInstance("GCM")} could route back into this class and recurse.
 * {@link #resolveDelegate()} walks the installed providers and skips Jostle for
 * exactly that reason — the same approach as
 * {@link org.openssl.jostle.jcajce.provider.ec.ECAlgorithmParameters}.
 */
public class GCMAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private final AlgorithmParameters delegate;

    public GCMAlgorithmParameters()
    {
        this.delegate = resolveDelegate();
    }

    /**
     * Find a platform GCM {@code AlgorithmParameters} that is not this
     * provider's, so delegation cannot recurse into this class.
     */
    private static AlgorithmParameters resolveDelegate()
    {
        for (Provider p : Security.getProviders())
        {
            if (JostleProvider.PROVIDER_NAME.equals(p.getName()))
            {
                continue;
            }
            if (p.getService("AlgorithmParameters", "GCM") == null)
            {
                continue;
            }
            try
            {
                return AlgorithmParameters.getInstance("GCM", p);
            }
            catch (NoSuchAlgorithmException e)
            {
                // Service advertised but not constructible from this
                // provider — keep looking.
            }
        }
        throw new IllegalStateException(
                "no non-Jostle AlgorithmParameters(\"GCM\") available from the platform");
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
