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

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * {@code AlgorithmParameters} for DSA. Encodes/decodes the X9.57
 * {@code Dss-Parms ::= SEQUENCE \{ p, q, g \}} structure and
 * translates to/from {@link java.security.spec.DSAParameterSpec}.
 *
 * <p>The ASN.1 codec and the spec translation are delegated to a
 * platform DSA {@code AlgorithmParameters} (the SUN provider on a
 * standard JDK) — the same delegation pattern as
 * {@link org.openssl.jostle.jcajce.provider.ec.ECAlgorithmParameters}.
 * Because this class IS registered under the bare name {@code "DSA"},
 * the delegate must be resolved from a provider that is NOT Jostle, or
 * {@code getInstance("DSA")} could resolve back to this class and
 * recurse. {@link #resolveDelegate()} walks the installed providers
 * and skips Jostle for exactly that reason.
 */
public class DSAAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private final AlgorithmParameters delegate;

    public DSAAlgorithmParameters()
    {
        this.delegate = resolveDelegate();
    }

    /**
     * Find a platform DSA {@code AlgorithmParameters} that is not this
     * provider's, so delegation cannot recurse into this class.
     */
    private static AlgorithmParameters resolveDelegate()
    {
        for (Provider p : Security.getProviders())
        {
            // Skip any provider whose "DSA" AlgorithmParameters SPI is a
            // Jostle class. This SPI is registered under BOTH "JSL" and
            // "JSLFIPS", so a provider-name check that skipped only "JSL"
            // would let a JSLFIPS-first deployment resolve getInstance
            // back into this class and recurse to StackOverflowError.
            // Match by SPI package, not provider name, so every current
            // and future Jostle-derived provider is guarded (the
            // registered class-name string is not always the concrete
            // class, so a package-prefix test is used, not exact match).
            Provider.Service svc = p.getService("AlgorithmParameters", "DSA");
            if (svc == null)
            {
                continue;
            }
            String svcClass = svc.getClassName();
            if (svcClass != null && svcClass.startsWith("org.openssl.jostle."))
            {
                continue;
            }
            try
            {
                return AlgorithmParameters.getInstance("DSA", p);
            }
            catch (NoSuchAlgorithmException e)
            {
                // Service advertised but not constructible from this
                // provider — keep looking.
            }
        }
        throw new IllegalStateException(
                "no non-Jostle AlgorithmParameters(\"DSA\") available from the platform");
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
