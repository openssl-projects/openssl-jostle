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
import java.security.Provider;
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
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            return key;
        }

        // Prefer the algorithm OID carried in the SubjectPublicKeyInfo over the
        // JDK key's getAlgorithm() string. The OID is the canonical algorithm
        // identifier, and the JSL provider registers its KeyFactories under the
        // SPKI OID aliases (e.g. 1.2.840.113549.1.1.1 for RSA, 1.2.840.10045.2.1
        // for EC), whereas getAlgorithm() returns a provider-specific name that
        // may not match any registered KeyFactory.
        PublicKey jslKey = importKey(subjectPublicKeyInfoAlgorithmOid(encoded), encoded);
        if (jslKey == null)
        {
            // No KeyFactory registered under the OID (e.g. an algorithm JSL only
            // registers by name) — fall back to the JDK key's algorithm name.
            jslKey = importKey(key.getAlgorithm(), encoded);
        }
        // The JSL provider has no KeyFactory for this algorithm (or can't import
        // it); fall back to the JDK-provided key.
        return jslKey != null ? jslKey : key;
    }

    /**
     * Re-derive a JSL public key from its X.509 encoding via the JSL provider's
     * KeyFactory for {@code algorithm}, or {@code null} if the algorithm is
     * {@code null}, has no JSL KeyFactory, or the encoding can't be imported.
     */
    private PublicKey importKey(String algorithm, byte[] encoded)
    {
        if (algorithm == null)
        {
            return null;
        }
        try
        {
            KeyFactory kf = KeyFactory.getInstance(algorithm, providerName);
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | java.security.spec.InvalidKeySpecException e)
        {
            return null;
        }
    }

    /**
     * Extract the algorithm OID from an X.509 SubjectPublicKeyInfo encoding.
     *
     * <pre>
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *     algorithm        AlgorithmIdentifier,
     *     subjectPublicKey BIT STRING }
     * AlgorithmIdentifier ::= SEQUENCE {
     *     algorithm        OBJECT IDENTIFIER,
     *     parameters       ANY DEFINED BY algorithm OPTIONAL }
     * </pre>
     *
     * @return the dotted-decimal OID string, or {@code null} if the bytes can't
     * be parsed as a SubjectPublicKeyInfo (the caller then falls back to the JDK
     * key's algorithm name).
     */
    private static String subjectPublicKeyInfoAlgorithmOid(byte[] spki)
    {
        try
        {
            int[] pos = {0};
            readTag(spki, pos, 0x30);   // SubjectPublicKeyInfo SEQUENCE
            readLength(spki, pos);
            readTag(spki, pos, 0x30);   // AlgorithmIdentifier SEQUENCE
            readLength(spki, pos);
            readTag(spki, pos, 0x06);   // algorithm OBJECT IDENTIFIER
            int oidLen = readLength(spki, pos);
            return decodeObjectIdentifier(spki, pos[0], oidLen);
        }
        catch (RuntimeException e)
        {
            return null;
        }
    }

    private static void readTag(byte[] data, int[] pos, int expected)
    {
        if (pos[0] >= data.length || (data[pos[0]] & 0xFF) != expected)
        {
            throw new IllegalArgumentException("unexpected ASN.1 tag");
        }
        pos[0]++;
    }

    private static int readLength(byte[] data, int[] pos)
    {
        if (pos[0] >= data.length)
        {
            throw new IllegalArgumentException("truncated ASN.1 length");
        }
        int b = data[pos[0]++] & 0xFF;
        if ((b & 0x80) == 0)
        {
            return b;
        }
        int count = b & 0x7F;
        if (count == 0 || count > 4)
        {
            throw new IllegalArgumentException("unsupported ASN.1 length");
        }
        int len = 0;
        for (int i = 0; i < count; i++)
        {
            if (pos[0] >= data.length)
            {
                throw new IllegalArgumentException("truncated ASN.1 length");
            }
            len = (len << 8) | (data[pos[0]++] & 0xFF);
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("ASN.1 length out of range");
        }
        return len;
    }

    private static String decodeObjectIdentifier(byte[] data, int off, int len)
    {
        if (len <= 0 || off < 0 || off + len > data.length)
        {
            throw new IllegalArgumentException("invalid OID encoding");
        }
        StringBuilder sb = new StringBuilder();
        long value = 0;
        boolean first = true;
        for (int i = 0; i < len; i++)
        {
            int b = data[off + i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0)
            {
                if (first)
                {
                    long firstArc = value / 40 > 2 ? 2 : value / 40;
                    sb.append(firstArc).append('.').append(value - firstArc * 40);
                    first = false;
                }
                else
                {
                    sb.append('.').append(value);
                }
                value = 0;
            }
        }
        if (!first && value == 0)
        {
            return sb.toString();
        }
        // A trailing sub-identifier whose high bit was still set means the OID
        // was truncated.
        throw new IllegalArgumentException("truncated OID encoding");
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

    /**
     * Provider-instance overload (no {@code NoSuchProviderException}, since the
     * provider is supplied directly). The base {@link java.security.cert.Certificate}
     * default throws {@code UnsupportedOperationException}, so this must be
     * overridden to delegate — otherwise callers that pass a {@link Provider}
     * instance (rather than a provider name) break against the wrapped cert.
     */
    public void verify(PublicKey key, Provider sigProvider)
        throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
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
