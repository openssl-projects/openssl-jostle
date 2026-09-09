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

import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.List;

/**
 * Marshals a path for {@link CertPathNI#ni_verify}: anchors first, then the
 * intermediates in issuer order, then the target last.
 */
final class CertPathCall
{
    final byte[] der;
    final int[] sizes;
    final int count;
    final int anchorCount;
    final long timeSecs;
    final byte[] chainOut;
    final int[] outInfo;

    private CertPathCall(byte[] der, int[] sizes, int count, int anchorCount, long timeSecs)
    {
        this.der = der;
        this.sizes = sizes;
        this.count = count;
        this.anchorCount = anchorCount;
        this.timeSecs = timeSecs;
        // The built chain can only be a subset of what was supplied, so the
        // input's length is a sound and cheap bound for the output.
        this.chainOut = new byte[der.length];
        this.outInfo = new int[count + CertPathNI.OUT_INFO_HEADER];
    }

    static CertPathCall build(PKIXParameters pkix, List<? extends Certificate> certs)
            throws CertPathValidatorException
    {
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
            for (int i = certs.size() - 1; i >= 0; i--)
            {
                encoded.add(certs.get(i).getEncoded());
            }
        }
        catch (CertificateEncodingException e)
        {
            throw new CertPathValidatorException("a certificate could not be encoded", e);
        }

        int total = 0;
        for (byte[] b : encoded)
        {
            total += b.length;
        }
        byte[] der = new byte[total];
        int[] sizes = new int[encoded.size()];
        int off = 0;
        for (int i = 0; i < encoded.size(); i++)
        {
            byte[] b = encoded.get(i);
            System.arraycopy(b, 0, der, off, b.length);
            sizes[i] = b.length;
            off += b.length;
        }

        long when = pkix.getDate() == null
                ? CertPathNI.TIME_NOW : pkix.getDate().getTime() / 1000L;
        return new CertPathCall(der, sizes, encoded.size(), anchors, when);
    }

    /**
     * Map a native index back to the caller's CertPath index.
     * <p>
     * The marshalled array is anchors first, then the path REVERSED (target
     * last), so index {@code anchorCount + k} is path element
     * {@code size - 1 - k}. An index inside the anchor block belongs to no path
     * element and maps to -1, which is what CertPathValidatorException expects
     * for "not attributable to a certificate in the path".
     */
    int toPathIndex(int nativeIndex, int pathSize)
    {
        if (nativeIndex < anchorCount || nativeIndex >= count)
        {
            return -1;
        }
        int k = nativeIndex - anchorCount;
        int idx = pathSize - 1 - k;
        return idx >= 0 && idx < pathSize ? idx : -1;
    }

    /**
     * The builder's variant: anchors, then every untrusted certificate, then
     * the target last. Unlike {@link #build} there is no caller-supplied order
     * to preserve — OpenSSL chooses the chain.
     */
    static CertPathCall forBuild(PKIXParameters pkix, List<? extends Certificate> untrusted,
                                 Certificate target) throws CertPathValidatorException
    {
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

        int total = 0;
        for (byte[] b : encoded)
        {
            total += b.length;
        }
        byte[] der = new byte[total];
        int[] sizes = new int[encoded.size()];
        int off = 0;
        for (int i = 0; i < encoded.size(); i++)
        {
            byte[] b = encoded.get(i);
            System.arraycopy(b, 0, der, off, b.length);
            sizes[i] = b.length;
            off += b.length;
        }
        long when = pkix.getDate() == null
                ? CertPathNI.TIME_NOW : pkix.getDate().getTime() / 1000L;
        return new CertPathCall(der, sizes, encoded.size(), anchors, when);
    }

    /** The built chain as certificates, target first, anchor last. */
    List<java.security.cert.X509Certificate> builtCertificates()
            throws java.security.cert.CertificateException
    {
        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");
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
