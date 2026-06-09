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

import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * {@code AlgorithmParameters} for EC. Lets callers resolve EC domain
 * parameters from this provider by name ({@code "EC"}) or by the
 * id-ecPublicKey OID — notably BouncyCastle's TLS layer, whose
 * {@code JceTlsECDomain} obtains curve parameters via
 * {@code helper.createAlgorithmParameters("EC")} on the JSL-bound helper
 * before any NIST-curve TLS group can be negotiated.
 *
 * <p>The ASN.1 codec and the {@code ECParameterSpec}/{@code ECGenParameterSpec}
 * translation are delegated to a platform EC {@code AlgorithmParameters}
 * (SunEC on a standard JDK) — this provider has no curve list of its own.
 *
 * <p>Unlike {@link org.openssl.jostle.jcajce.provider.blockcipher.GCMAlgorithmParameters}
 * (which dodges recursion by NOT registering its bare name and resolving
 * its delegate via {@code getInstance("GCM")}), this class IS registered
 * under the bare name {@code "EC"} because the TLS path needs that name.
 * The delegate must therefore be resolved from a provider that is NOT
 * Jostle, or {@code getInstance("EC")} could resolve back to this class
 * and recurse. {@link #resolveDelegate()} walks the installed providers
 * and skips Jostle for exactly that reason.
 */
public class ECAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private final AlgorithmParameters delegate;

    public ECAlgorithmParameters()
    {
        this.delegate = resolveDelegate();
    }

    /**
     * Find a platform EC {@code AlgorithmParameters} that is not this
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
            if (p.getService("AlgorithmParameters", "EC") == null)
            {
                continue;
            }
            try
            {
                return AlgorithmParameters.getInstance("EC", p);
            }
            catch (NoSuchAlgorithmException e)
            {
                // Service advertised but not constructible from this
                // provider — keep looking.
            }
        }
        throw new IllegalStateException(
                "no non-Jostle AlgorithmParameters(\"EC\") available from the platform");
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec instanceof ECGenParameterSpec)
        {
            // SunEC's ECParameters accepts only some aliases of a curve
            // name (e.g. "secp256r1" but not "P-256" on some JDKs). Try
            // each known alias against the delegate so any standard name
            // for a curve resolves. Resolving against the (non-Jostle)
            // delegate — never via getInstance("EC") — keeps this off the
            // path that could route back into this class and recurse.
            String name = ((ECGenParameterSpec) paramSpec).getName();
            InvalidParameterSpecException last = null;
            for (String candidate : ECComponents.aliasesFor(name))
            {
                try
                {
                    delegate.init(new ECGenParameterSpec(candidate));
                    return;
                }
                catch (InvalidParameterSpecException e)
                {
                    last = e;
                }
            }
            if (last != null)
            {
                throw last;
            }
            throw new InvalidParameterSpecException("unsupported EC curve: " + name);
        }
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
