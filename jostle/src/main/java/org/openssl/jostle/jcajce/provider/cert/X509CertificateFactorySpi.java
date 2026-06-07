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

    public X509CertificateFactorySpi()
    {
        try
        {
            this.delegate = CertificateFactory.getInstance("X.509", "SUN");
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
     * Re-wrap an X.509 certificate so its getPublicKey() returns a JSL-provider key
     * (JSL Signature SPIs require their own key types). Non-X.509 results pass through.
     */
    private static Certificate wrap(Certificate c)
    {
        // Fast-path: if it's already our wrapper, return unchanged to avoid double-wrapping.
        if (c instanceof JSLKeyX509Certificate)
        {
            return c;
        }

        if (c instanceof X509Certificate)
        {
            return new JSLKeyX509Certificate((X509Certificate) c, JostleProvider.PROVIDER_NAME);
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
