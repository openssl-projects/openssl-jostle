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

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * {@code AlgorithmParameters} for DH. Encodes/decodes the PKCS#3
 * {@code DHParameter ::= SEQUENCE \{ prime, base, privateValueLength
 * OPTIONAL \}} structure and translates to/from
 * {@link javax.crypto.spec.DHParameterSpec}.
 *
 * <p>The ASN.1 codec and the spec translation are delegated to a
 * platform DH {@code AlgorithmParameters} (SunJCE on a standard JDK) —
 * the same delegation pattern as the DSA/EC parameters classes.
 * Because this class IS registered under the bare name {@code "DH"},
 * the delegate must be resolved from a provider that is NOT Jostle, or
 * {@code getInstance("DH")} could resolve back to this class and
 * recurse. {@link #resolveDelegate()} walks the installed providers
 * and skips Jostle for exactly that reason.
 *
 * <p><b>PKCS#3 only.</b> The delegate encodes {@code DHParameter}, which has
 * no place for the subgroup order q, so a
 * {@link org.openssl.jostle.jcajce.spec.DHDomainParameterSpec} passed to
 * {@code engineInit} loses q and {@code engineGetParameterSpec} returns a
 * plain {@code DHParameterSpec}. KEYS carry q correctly in both directions —
 * that is where the X9.42 form is decided. Emitting X9.42
 * {@code DomainParameters} here would need its own ASN.1 codec rather than a
 * delegate, and no caller has needed it: pass the domain parameters as a spec
 * or carry them on a key.
 */
public class DHAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private final AlgorithmParameters delegate;

    public DHAlgorithmParameters()
    {
        this.delegate = resolveDelegate();
    }

    /**
     * Find a platform DH {@code AlgorithmParameters} that is not this
     * provider's, so delegation cannot recurse into this class.
     */
    private static AlgorithmParameters resolveDelegate()
    {
        for (Provider p : Security.getProviders())
        {
            // Skip any provider whose "DH" AlgorithmParameters SPI is a
            // Jostle class. This SPI is registered under BOTH "JSL" and
            // "JSLFIPS", so a provider-name check that skipped only "JSL"
            // would let a JSLFIPS-first deployment resolve getInstance
            // back into this class and recurse to StackOverflowError.
            // Match by SPI package, not provider name, so every current
            // and future Jostle-derived provider is guarded. A package
            // prefix, not an exact class match: several Jostle classes
            // serve this type and a new one must be skipped too.
            Provider.Service svc = p.getService("AlgorithmParameters", "DH");
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
                return AlgorithmParameters.getInstance("DH", p);
            }
            catch (NoSuchAlgorithmException e)
            {
                // Service advertised but not constructible from this
                // provider — keep looking.
            }
        }
        throw new IllegalStateException(
                "no non-Jostle AlgorithmParameters(\"DH\") available from the platform");
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
