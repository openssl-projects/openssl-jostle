/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.cert;

import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;

/**
 * X.509 CertificateFactory for the JSL provider.
 *
 * <p>Parsing X.509 certificates / CRLs / CertPaths is ASN.1 structure work, not a
 * cryptographic operation, so this delegates to the JDK's built-in "SUN" X.509
 * factory rather than re-implementing it. It exists so that consumers (notably the
 * PKIX/CMS layer's {@code JcaX509CertificateConverter} and the various
 * {@code setProvider("JSL")} helpers) can resolve {@code CertificateFactory.X.509}
 * against the JSL provider.</p>
 *
 * <p>The delegate is fetched explicitly from the {@code SUN} provider to avoid
 * recursing back into this factory if JSL happens to be highest in the provider
 * search order.</p>
 */
public class X509CertificateFactorySpi
    extends CertificateFactorySpi
{
    private final CertificateFactory delegate;
    /** One fact, one field — see {@link ProviderBinding}. */
    private final ProviderBinding binding;
    private final boolean providerBound;

    public X509CertificateFactorySpi()
    {
        this(JostleProvider.PROVIDER_NAME, false);
    }

    /**
     * Name-only form, kept for callers outside this tree. Prefer the
     * {@link Provider} form: a name is re-resolvable, so the keys this factory
     * returns can come from a different instance than the caller asked for.
     *
     * @param providerName  the Jostle provider certificates' keys are re-derived
     *                      through (see {@link JSLKeyX509Certificate}).
     * @param providerBound when true, never fall back outside {@code providerName}:
     *                      key re-derivation failure is a loud error instead of a
     *                      JDK-key fallback, and one-argument verify is pinned to
     *                      the provider. Used by the FIPS registration.
     */
    public X509CertificateFactorySpi(String providerName, boolean providerBound)
    {
        this.binding = ProviderBinding.ofName(providerName);
        this.providerBound = providerBound;
        this.delegate = jdkDelegate();
    }

    /**
     * @param providerInstance the provider this factory belongs to. The
     *                         certificates it returns carry keys decoded by
     *                         THIS instance: a name is re-resolvable, and a key
     *                         from another instance is refused by MT-14's
     *                         isolation check on first use, so the factory
     *                         would hand back what its own provider rejects.
     * @param providerBound    see the name-only form.
     */
    public X509CertificateFactorySpi(Provider providerInstance, boolean providerBound)
    {
        if (providerInstance == null)
        {
            throw new IllegalArgumentException(
                    "X509CertificateFactorySpi requires the provider it belongs to;"
                            + " use the name-only constructor when there is none");
        }
        this.binding = ProviderBinding.of(providerInstance);
        this.providerBound = providerBound;
        this.delegate = jdkDelegate();
    }

    /**
     * The JDK's X.509 parser, by NAME on purpose: we want whichever object
     * answers to SUN, and naming it avoids recursing back into this factory
     * when JSL sits highest in the search order.
     */
    private static CertificateFactory jdkDelegate()
    {
        try
        {
            return CertificateFactory.getInstance("X.509", "SUN");
        }
        catch (CertificateException | NoSuchProviderException e)
        {
            throw new IllegalStateException("unable to obtain a JDK X.509 CertificateFactory: " + e.getMessage(), e);
        }
    }

    public Certificate engineGenerateCertificate(InputStream inStream)
        throws CertificateException
    {
        return wrap(delegate.generateCertificate(inStream));
    }

    public Collection<? extends Certificate> engineGenerateCertificates(InputStream inStream)
        throws CertificateException
    {
        Collection<? extends Certificate> certs = delegate.generateCertificates(inStream);
        if (certs == null || certs.isEmpty())
        {
            return certs;
        }
        List<Certificate> wrapped = new ArrayList<>(certs.size());
        for (Certificate c : certs)
        {
            wrapped.add(wrap(c));
        }
        return wrapped;
    }

    /**
     * Re-wrap an X.509 certificate so its getPublicKey() returns a key from this
     * factory's provider (its Signature SPIs require their own key types).
     * Non-X.509 results pass through.
     */
    private Certificate wrap(Certificate c)
    {
        // Fast-path: already wrapped with this factory's policy — return
        // unchanged. A wrapper carrying a different provider or binding (e.g. a
        // lenient JSL-wrapped cert flowing into the provider-bound FIPS factory
        // via engineGenerateCertPath(List)) is re-wrapped from its delegate so
        // this factory's policy always governs what it returns.
        if (c instanceof JSLKeyX509Certificate)
        {
            JSLKeyX509Certificate wrapped = (JSLKeyX509Certificate) c;
            if (wrapped.hasPolicy(binding, providerBound))
            {
                return c;
            }
            return new JSLKeyX509Certificate(wrapped.unwrap(), binding, providerBound);
        }

        if (c instanceof X509Certificate)
        {
            return new JSLKeyX509Certificate((X509Certificate) c, binding, providerBound);
        }
        return c;
    }

    public CRL engineGenerateCRL(InputStream inStream)
        throws CRLException
    {
        return delegate.generateCRL(inStream);
    }

    public Collection<? extends CRL> engineGenerateCRLs(InputStream inStream)
        throws CRLException
    {
        return delegate.generateCRLs(inStream);
    }

    // The three engineGenerateCertPath overloads below rebuild the path from
    // wrapped certificates via delegate.generateCertPath(List). This relies on
    // the SUN delegate's CertPath retaining the supplied Certificate instances
    // verbatim in getCertificates() — sun.security.provider.certpath.X509CertPath
    // stores the list as-is rather than re-parsing — so the JSL wrappers survive
    // and getPublicKey() yields JSL keys. testGenerateCertPath_* guard this; if a
    // future delegate re-parsed instead, those tests would fail loudly.
    public CertPath engineGenerateCertPath(InputStream inStream)
        throws CertificateException
    {
        CertPath parsed = delegate.generateCertPath(inStream);
        List<? extends Certificate> certs = parsed.getCertificates();
        if (certs == null || certs.isEmpty())
        {
            return parsed;
        }
        List<Certificate> wrapped = new ArrayList<>(certs.size());
        for (Certificate c : certs)
        {
            wrapped.add(wrap(c));
        }
        return delegate.generateCertPath(wrapped);
    }

    public CertPath engineGenerateCertPath(InputStream inStream, String encoding)
        throws CertificateException
    {
        CertPath parsed = delegate.generateCertPath(inStream, encoding);
        List<? extends Certificate> certs = parsed.getCertificates();
        if (certs == null || certs.isEmpty())
        {
            return parsed;
        }
        List<Certificate> wrapped = new ArrayList<>(certs.size());
        for (Certificate c : certs)
        {
            wrapped.add(wrap(c));
        }
        return delegate.generateCertPath(wrapped);
    }

    public CertPath engineGenerateCertPath(List<? extends Certificate> certificates)
        throws CertificateException
    {
        if (certificates == null || certificates.isEmpty())
        {
            return delegate.generateCertPath(certificates);
        }
        List<Certificate> wrapped = new ArrayList<>(certificates.size());
        for (Certificate c : certificates)
        {
            wrapped.add(wrap(c));
        }
        return delegate.generateCertPath(wrapped);
    }

    public java.util.Iterator<String> engineGetCertPathEncodings()
    {
        return delegate.getCertPathEncodings();
    }
}
