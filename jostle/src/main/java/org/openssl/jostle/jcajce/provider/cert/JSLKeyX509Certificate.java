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

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Wraps a JDK-parsed {@link X509Certificate} and re-derives its public key through
 * the JSL provider's KeyFactory, so that JSL's Signature SPIs (which require their
 * own key types) accept the certificate's public key. Everything else delegates to
 * the wrapped certificate.
 */
class JSLKeyX509Certificate
    extends X509Certificate
{
    private final X509Certificate delegate;
    private final String providerName;

    JSLKeyX509Certificate(X509Certificate delegate, String providerName)
    {
        this.delegate = delegate;
        this.providerName = providerName;
    }

    public PublicKey getPublicKey()
    {
        PublicKey key = delegate.getPublicKey();
        try
        {
            KeyFactory kf = KeyFactory.getInstance(key.getAlgorithm(), providerName);
            return kf.generatePublic(new X509EncodedKeySpec(key.getEncoded()));
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | java.security.spec.InvalidKeySpecException e)
        {
            // The JSL provider has no KeyFactory for this algorithm (or can't import
            // it); fall back to the JDK-provided key.
            return key;
        }
    }

    // --- everything else delegates ---

    public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        delegate.checkValidity();
    }

    public void checkValidity(Date date)
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        delegate.checkValidity(date);
    }

    public int getVersion()
    {
        return delegate.getVersion();
    }

    public java.math.BigInteger getSerialNumber()
    {
        return delegate.getSerialNumber();
    }

    public Principal getIssuerDN()
    {
        return delegate.getIssuerDN();
    }

    public Principal getSubjectDN()
    {
        return delegate.getSubjectDN();
    }

    public javax.security.auth.x500.X500Principal getIssuerX500Principal()
    {
        return delegate.getIssuerX500Principal();
    }

    public javax.security.auth.x500.X500Principal getSubjectX500Principal()
    {
        return delegate.getSubjectX500Principal();
    }

    public Date getNotBefore()
    {
        return delegate.getNotBefore();
    }

    public Date getNotAfter()
    {
        return delegate.getNotAfter();
    }

    public byte[] getTBSCertificate()
        throws CertificateEncodingException
    {
        return delegate.getTBSCertificate();
    }

    public byte[] getSignature()
    {
        return delegate.getSignature();
    }

    public String getSigAlgName()
    {
        return delegate.getSigAlgName();
    }

    public String getSigAlgOID()
    {
        return delegate.getSigAlgOID();
    }

    public byte[] getSigAlgParams()
    {
        return delegate.getSigAlgParams();
    }

    public boolean[] getIssuerUniqueID()
    {
        return delegate.getIssuerUniqueID();
    }

    public boolean[] getSubjectUniqueID()
    {
        return delegate.getSubjectUniqueID();
    }

    public boolean[] getKeyUsage()
    {
        return delegate.getKeyUsage();
    }

    public List<String> getExtendedKeyUsage()
        throws CertificateParsingException
    {
        return delegate.getExtendedKeyUsage();
    }

    public int getBasicConstraints()
    {
        return delegate.getBasicConstraints();
    }

    public Collection<List<?>> getSubjectAlternativeNames()
        throws CertificateParsingException
    {
        return delegate.getSubjectAlternativeNames();
    }

    public Collection<List<?>> getIssuerAlternativeNames()
        throws CertificateParsingException
    {
        return delegate.getIssuerAlternativeNames();
    }

    public byte[] getEncoded()
        throws CertificateEncodingException
    {
        return delegate.getEncoded();
    }

    public void verify(PublicKey key)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
    {
        delegate.verify(key);
    }

    public void verify(PublicKey key, String sigProvider)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
    {
        delegate.verify(key, sigProvider);
    }

    public String toString()
    {
        return delegate.toString();
    }

    // --- X509Extension ---

    public boolean hasUnsupportedCriticalExtension()
    {
        return delegate.hasUnsupportedCriticalExtension();
    }

    public Set<String> getCriticalExtensionOIDs()
    {
        return delegate.getCriticalExtensionOIDs();
    }

    public Set<String> getNonCriticalExtensionOIDs()
    {
        return delegate.getNonCriticalExtensionOIDs();
    }

    public byte[] getExtensionValue(String oid)
    {
        return delegate.getExtensionValue(oid);
    }
}
