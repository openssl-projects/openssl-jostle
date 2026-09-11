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

package org.openssl.jostle.jcajce.provider.certpath;

import org.openssl.jostle.util.Arrays;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Marshals a path for {@link CertPathNI#ni_verify}: anchors first, then the
 * intermediates in issuer order, then the target last, then the CRLs.
 */
final class CertPathCall
{
    /**
     * The bridge's own ceilings, mirrored here so a caller-controlled count
     * is refused TYPED. Reaching the bridge yields JO_INPUT_TOO_LONG_INT32,
     * which baseErrorHandler turns into an OverflowException — a
     * RuntimeException for what is an ordinary parameter error.
     */
    static final int MAX_CERTS = 256;
    static final int MAX_CRLS = 256;

    final byte[] der;
    final int[] sizes;
    final int count;
    final int crlCount;
    final int anchorCount;
    /** CertStore certificates marshalled after the anchors, for CRL issuers. */
    final int extraCount;
    final long timeSecs;
    final int revocation;
    final byte[] chainOut;
    final int[] outInfo;

    private CertPathCall(byte[] der, int[] sizes, int count, int crlCount, int anchorCount,
                         int extraCount, long timeSecs, int revocation, int certBytes)
    {
        this.der = der;
        this.sizes = sizes;
        this.count = count;
        this.crlCount = crlCount;
        this.anchorCount = anchorCount;
        this.extraCount = extraCount;
        this.timeSecs = timeSecs;
        this.revocation = revocation;
        // The built chain can only be a subset of the CERTIFICATES supplied,
        // so their combined length is a sound and cheap bound — the CRL bytes
        // in `der` can never appear in it.
        this.chainOut = new byte[certBytes];
        this.outInfo = new int[count + CertPathNI.OUT_INFO_HEADER];
    }

    /**
     * Refuse a certificate or CRL count the bridge cannot take, as a
     * parameter error rather than as the bridge's overflow code.
     */
    private static void refuseOversizedInputs(int certCount, int crlCount)
            throws InvalidAlgorithmParameterException
    {
        if (certCount > MAX_CERTS)
        {
            throw new InvalidAlgorithmParameterException(
                    "too many certificates: " + certCount + " exceeds the limit of " + MAX_CERTS
                            + " (trust anchors, path and CertStore certificates together)");
        }
        if (crlCount > MAX_CRLS)
        {
            throw new InvalidAlgorithmParameterException(
                    "too many CRLs: " + crlCount + " exceeds the limit of " + MAX_CRLS);
        }
    }

    /** Gathered only with revocation on: with it off nothing reads them. */
    static List<X509CRL> crlsFrom(PKIXParameters pkix) throws InvalidAlgorithmParameterException
    {
        List<X509CRL> out = new ArrayList<X509CRL>();
        if (!pkix.isRevocationEnabled())
        {
            return out;
        }
        for (CertStore store : pkix.getCertStores())
        {
            Collection<? extends CRL> found;
            try
            {
                found = store.getCRLs(null);
            }
            catch (CertStoreException e)
            {
                throw new InvalidAlgorithmParameterException("a CertStore could not be read: " + e);
            }
            for (CRL c : found)
            {
                if (!(c instanceof X509CRL))
                {
                    throw new InvalidAlgorithmParameterException(
                            "a CertStore holds a non-X509CRL: " + c.getClass().getName());
                }
                out.add((X509CRL) c);
            }
        }
        return out;
    }

    /**
     * Concatenate the certificates and then the CRLs into one buffer. Returns
     * the assembled call; the certificate bytes are measured separately
     * because they alone bound the built chain.
     */
    private static CertPathCall assemble(List<byte[]> certs, List<byte[]> crls,
                                         int anchors, int extras, PKIXParameters pkix)
    {
        int certBytes = 0;
        for (byte[] b : certs)
        {
            certBytes += b.length;
        }
        int total = certBytes;
        for (byte[] b : crls)
        {
            total += b.length;
        }
        byte[] der = new byte[total];
        int[] sizes = new int[certs.size() + crls.size()];
        int off = 0;
        int i = 0;
        for (byte[] b : certs)
        {
            System.arraycopy(b, 0, der, off, b.length);
            sizes[i++] = b.length;
            off += b.length;
        }
        for (byte[] b : crls)
        {
            System.arraycopy(b, 0, der, off, b.length);
            sizes[i++] = b.length;
            off += b.length;
        }
        long when = pkix.getDate() == null
                ? CertPathNI.TIME_NOW : pkix.getDate().getTime() / 1000L;
        return new CertPathCall(der, sizes, certs.size(), crls.size(), anchors, extras, when,
                pkix.isRevocationEnabled() ? 1 : 0, certBytes);
    }

    private static List<byte[]> encodeCrls(List<X509CRL> crls) throws CertPathValidatorException
    {
        List<byte[]> out = new ArrayList<byte[]>();
        try
        {
            for (X509CRL c : crls)
            {
                out.add(c.getEncoded());
            }
        }
        catch (CRLException e)
        {
            throw new CertPathValidatorException("a CRL could not be encoded", e);
        }
        return out;
    }

    static CertPathCall build(PKIXParameters pkix, List<? extends Certificate> certs,
                              List<X509CRL> crls, List<? extends Certificate> extras)
            throws CertPathValidatorException, InvalidAlgorithmParameterException
    {
        refuseOversizedInputs(pkix.getTrustAnchors().size() + certs.size() + extras.size(),
                crls.size());
        List<byte[]> encoded = new ArrayList<byte[]>();
        int anchors = 0;
        try
        {
            for (TrustAnchor anchor : pkix.getTrustAnchors())
            {
                encoded.add(anchor.getTrustedCert().getEncoded());
                anchors++;
            }
            // CertPath is target-first; the native side wants the target last.
            // The extras sit between the intermediates and the target, never
            // ahead of them: OpenSSL takes the FIRST time-valid issuer in
            // stack order, so a store copy placed earlier would outrank the
            // path's own certificate.
            for (int i = certs.size() - 1; i >= 1; i--)
            {
                encoded.add(certs.get(i).getEncoded());
            }
            for (Certificate c : extras)
            {
                encoded.add(c.getEncoded());
            }
            encoded.add(certs.get(0).getEncoded());
        }
        catch (CertificateEncodingException e)
        {
            throw new CertPathValidatorException("a certificate could not be encoded", e);
        }
        return assemble(encoded, encodeCrls(crls), anchors, extras.size(), pkix);
    }

    /**
     * The CertStores' CERTIFICATES, which an indirect CRL issuer needs.
     * <p>
     * They are marshalled AFTER the path's intermediates. OpenSSL's issuer
     * search returns the first time-valid candidate in untrusted-stack order
     * (x509_vfy.c {@code get0_best_issuer_sk}, 3.5.8 :391-421), so a
     * re-issued copy of a path CA - same subject and key, different bytes -
     * must not sit ahead of the path's own copy.
     * <p>
     * Filtering them out BY SUBJECT instead was tried and is WRONG: PKITS's
     * Separate-Keys CRL signer carries the SAME subject as its CA (measured,
     * both are "CN=Separate Certificate and CRL Keys CA1"), so a subject
     * filter drops the certificate 4.4.19, 4.4.20 and 4.4.21 need and turns
     * them into "no CRL for an issuer in the path". Ordering is what makes
     * this safe; subject is not a usable discriminator.
     * <p>
     * Gathered only with revocation on, for the same reason as the CRLs.
     */
    static List<X509Certificate> extraCertsFrom(PKIXParameters pkix,
                                                List<? extends Certificate> path)
            throws InvalidAlgorithmParameterException
    {
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        if (!pkix.isRevocationEnabled())
        {
            return out;
        }
        for (CertStore store : pkix.getCertStores())
        {
            Collection<? extends Certificate> found;
            try
            {
                found = store.getCertificates(null);
            }
            catch (CertStoreException e)
            {
                throw new InvalidAlgorithmParameterException("a CertStore could not be read: " + e);
            }
            for (Certificate c : found)
            {
                if (!(c instanceof X509Certificate))
                {
                    throw new InvalidAlgorithmParameterException(
                            "a CertStore holds a non-X509Certificate: " + c.getClass().getName());
                }
                out.add((X509Certificate) c);
            }
        }
        return out;
    }

    /**
     * Map a native index back to the caller's CertPath index.
     * <p>
     * Layout: anchors, the path's intermediates REVERSED, the CertStore
     * extras, then the target last. So {@code anchorCount + k} is path element
     * {@code pathSize - 1 - k} for the intermediates, and {@code count - 1} is
     * the target, path element 0. An index in the anchor or extras block
     * belongs to no path element and maps to -1, which is what
     * CertPathValidatorException expects for "not attributable to a
     * certificate in the path".
     */
    int toPathIndex(int nativeIndex, int pathSize)
    {
        if (nativeIndex == count - 1)
        {
            return 0;
        }
        int k = nativeIndex - anchorCount;
        if (k < 0 || k >= pathSize - 1)
        {
            return -1;
        }
        return pathSize - 1 - k;
    }

    /**
     * The builder's variant: anchors, then every untrusted certificate, then
     * the target last. Unlike {@link #build} there is no caller-supplied order
     * to preserve — OpenSSL chooses the chain.
     */
    static CertPathCall forBuild(PKIXParameters pkix, List<? extends Certificate> untrusted,
                                 Certificate target, List<X509CRL> crls)
            throws CertPathValidatorException, InvalidAlgorithmParameterException
    {
        refuseOversizedInputs(pkix.getTrustAnchors().size() + untrusted.size() + 1, crls.size());
        List<byte[]> encoded = new ArrayList<byte[]>();
        int anchors = 0;
        try
        {
            for (TrustAnchor a : pkix.getTrustAnchors())
            {
                encoded.add(a.getTrustedCert().getEncoded());
                anchors++;
            }
            for (Certificate c : untrusted)
            {
                encoded.add(c.getEncoded());
            }
            encoded.add(target.getEncoded());
        }
        catch (CertificateEncodingException e)
        {
            throw new CertPathValidatorException("a certificate could not be encoded", e);
        }
        return assemble(encoded, encodeCrls(crls), anchors, 0, pkix);
    }

    /**
     * The built chain as certificates, target first, anchor last.
     *
     * @param cf the caller's factory. These certificates become the SPI's
     *           RESULT, so the provider that decodes them is the SPI's own,
     *           not whatever JCA order offers; the SPI resolves it once and
     *           reuses it for the CertPath.
     */
    List<java.security.cert.X509Certificate> builtCertificates(
            java.security.cert.CertificateFactory cf)
            throws java.security.cert.CertificateException
    {
        List<java.security.cert.X509Certificate> out =
                new ArrayList<java.security.cert.X509Certificate>();
        for (byte[] der : builtChain())
        {
            out.add((java.security.cert.X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(der)));
        }
        return out;
    }

    /** The built chain, target first, as the caller's CertPath is ordered. */
    private List<byte[]> builtChain()
    {
        List<byte[]> out = new ArrayList<byte[]>();
        int off = 0;
        for (int i = 0; i < outInfo[2]; i++)
        {
            int len = outInfo[CertPathNI.OUT_INFO_HEADER + i];
            out.add(java.util.Arrays.copyOfRange(chainOut, off, off + len));
            off += len;
        }
        return out;
    }

    /**
     * P4: the validator validates the path it was GIVEN. OpenSSL builds its own
     * chain from the certificates supplied, and if that chain contains a
     * certificate the caller did not supply, or takes them out of order, then
     * the path verified was not the path asked about.
     * <p>
     * The test is ordered SUBSEQUENCE, not equality, and the difference is
     * load-bearing: a SELF-ISSUED certificate in the path may be legitimately
     * omitted from the built chain — RFC 5280 6.1 treats self-issued
     * certificates specially and they do not lengthen a path. Measured on
     * PKITS 4.5.4 and 4.5.6, where the omitted certificate is self-issued
     * (subject equals issuer) and both cases are expected to VALIDATE. Exact
     * equality failed them, which would have been our own assertion inventing
     * a divergence rather than OpenSSL producing one.
     */
    void assertBuiltChainMatches(List<? extends Certificate> certs, CertPath path)
            throws CertPathValidatorException
    {
        List<byte[]> built = builtChain();
        if (built.isEmpty())
        {
            throw new CertPathValidatorException("OpenSSL returned no chain", null, path, -1);
        }
        // The last built element is the anchor, which the CertPath excludes.
        int builtCerts = built.size() - 1;
        int given = 0;
        try
        {
            for (int i = 0; i < builtCerts; i++)
            {
                byte[] want = built.get(i);
                boolean found = false;
                while (given < certs.size())
                {
                    byte[] have = certs.get(given).getEncoded();
                    given++;
                    if (Arrays.areEqual(have, want))
                    {
                        found = true;
                        break;
                    }
                    if (!isSelfIssued(certs.get(given - 1)))
                    {
                        throw new CertPathValidatorException(
                                "OpenSSL skipped a certificate the path supplied at index "
                                        + (given - 1) + ", and it is not self-issued",
                                null, path, given - 1);
                    }
                }
                if (!found)
                {
                    throw new CertPathValidatorException(
                            "the chain OpenSSL built contains a certificate the path did not "
                                    + "supply, at chain index " + i, null, path, -1);
                }
            }
        }
        catch (CertificateEncodingException e)
        {
            throw new CertPathValidatorException("a certificate could not be encoded", e);
        }
    }

    /** Self-issued: subject equals issuer. RFC 5280 6.1. */
    private static boolean isSelfIssued(Certificate cert)
    {
        if (!(cert instanceof java.security.cert.X509Certificate))
        {
            return false;
        }
        java.security.cert.X509Certificate x = (java.security.cert.X509Certificate) cert;
        return x.getSubjectX500Principal().equals(x.getIssuerX500Principal());
    }

    /**
     * P3: the anchor is the store certificate OpenSSL actually terminated at,
     * matched back to the caller's set by encoding rather than assumed to be
     * the only one supplied.
     */
    TrustAnchor resolveAnchor(PKIXParameters pkix) throws CertPathValidatorException
    {
        List<byte[]> built = builtChain();
        if (built.isEmpty())
        {
            throw new CertPathValidatorException("OpenSSL returned no chain");
        }
        byte[] last = built.get(built.size() - 1);
        for (TrustAnchor anchor : pkix.getTrustAnchors())
        {
            try
            {
                if (Arrays.areEqual(anchor.getTrustedCert().getEncoded(), last))
                {
                    return anchor;
                }
            }
            catch (CertificateEncodingException e)
            {
                throw new CertPathValidatorException("a trust anchor could not be encoded", e);
            }
        }
        throw new CertPathValidatorException(
                "the chain terminated at a certificate that is not one of the supplied anchors");
    }
}
