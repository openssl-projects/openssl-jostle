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

import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;
import org.openssl.jostle.util.asn1.oids.X509ObjectIdentifiers;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/**
 * The one order in which the supplied CRLs are handed to OpenSSL, for the validator and the builder alike, so
 * the caller's store order never decides between CRLs OpenSSL scores equal.
 *
 * <p>OpenSSL (x509_vfy.c, 3.5.9) keeps the FIRST of equally scored full CRLs unless a later one has a strictly
 * newer lastUpdate (get_crl_sk), never reads a full CRL's number, verifies only the chosen CRL's signature, and
 * takes the FIRST delta that fits the base before checking its times (get_delta_sk). The order, a total one:
 * <ol>
 * <li>current at the validation time first (thisUpdate at or before it, and before nextUpdate where present), so
 * a delta not yet valid at a past date is not met first;</li>
 * <li>thisUpdate, newest first;</li>
 * <li>for the validator only, within one thisUpdate: a CRL listing the serial number of a certificate of the path
 * first, so a tie between a clean and a revoking CRL is decided towards revoked;</li>
 * <li>CRL number, highest first (absent last);</li>
 * <li>the encoding.</li>
 * </ol>
 * A CRL the provider cannot decode goes after all the others, by encoding; OpenSSL still decodes every one and
 * reports a failure. Nothing is dropped and nothing is decided here: OpenSSL scores, verifies and decides.
 *
 * <p>The builder has no path before its call, so it omits key 4 and confirms a built path whose CRLs hold a tie
 * group with the validator's call (see {@link #hasTieGroup}). A forged CRL with a newer thisUpdate and the
 * issuer's name is met first, chosen by OpenSSL on unauthenticated fields and fails its signature: a refusal,
 * never an acceptance. Dropping CRLs this provider cannot verify would remove that, and would also drop a genuine
 * revoking CRL in a signature algorithm it does not serve, so nothing is dropped.
 *
 * <p>The issuer takes no part. OpenSSL compares issuer names after converting every directory string to UTF8 and
 * folding case and spacing for every attribute, and Java's canonical form folds less (no BMPString, T61String,
 * IA5String or UniversalString, and an attribute without a keyword is compared as its encoding), so any issuer
 * test here would miss ties OpenSSL makes. So a tie group is any two decodable CRLs with one thisUpdate, a superset
 * of OpenSSL's ties, and the listing key matches by serial alone; order between CRLs OpenSSL does not tie decides
 * nothing. This also groups indirect CRLs of different issuers at one thisUpdate.
 */
final class CrlOrder
{
    private static final String CRL_NUMBER = X509ObjectIdentifiers.id_ce_cRLNumber.getId();

    private static final class Entry
    {
        final X509CRL callers;
        final X509CRL ours;
        final byte[] der;
        final boolean current;
        final long thisUpdate;
        final BigInteger number;

        Entry(X509CRL callers, X509CRL ours, byte[] der, long time)
        {
            this.callers = callers;
            this.ours = ours;
            this.der = der;
            if (ours == null)
            {
                current = false;
                thisUpdate = 0;
                number = null;
                return;
            }
            Date next = ours.getNextUpdate();
            thisUpdate = ours.getThisUpdate().getTime();
            current = thisUpdate <= time && (next == null || time < next.getTime());
            number = crlNumber(ours.getExtensionValue(CRL_NUMBER));
        }

        boolean ties(Entry o)
        {
            return ours != null && o.ours != null && thisUpdate == o.thisUpdate;
        }
    }

    private final List<Entry> entries = new ArrayList<Entry>();
    private final boolean tieGroup;

    /**
     * @param binding the provider whose factory decodes the CRLs
     * @param pkix    the parameters; their date, or now, is the validation time
     * @param crls    the CRLs as the caller's stores returned them
     */
    CrlOrder(ProviderBinding binding, PKIXParameters pkix, List<X509CRL> crls) throws CertPathValidatorException
    {
        long time = pkix.getDate() == null ? System.currentTimeMillis() : pkix.getDate().getTime();
        CertificateFactory cf = null;
        if (!crls.isEmpty())
        {
            try
            {
                cf = VerifiedOrder.factoryFor(binding);
            }
            catch (CertificateException e)
            {
                cf = null;
            }
        }
        for (X509CRL c : crls)
        {
            byte[] der;
            try
            {
                der = c.getEncoded();
            }
            catch (CRLException e)
            {
                throw new CertPathValidatorException("a CRL could not be encoded", e);
            }
            X509CRL ours = null;
            if (cf != null)
            {
                try
                {
                    ours = (X509CRL) cf.generateCRL(new ByteArrayInputStream(der));
                }
                catch (CRLException e)
                {
                    ours = null;
                }
                catch (RuntimeException e)
                {
                    ours = null;
                }
            }
            entries.add(new Entry(c, ours, der, time));
        }
        boolean tie = false;
        for (int i = 0; i < entries.size() && !tie; i++)
        {
            for (int j = i + 1; j < entries.size() && !tie; j++)
            {
                tie = entries.get(i).ties(entries.get(j));
            }
        }
        this.tieGroup = tie;
    }

    /**
     * Whether two decoded CRLs share a thisUpdate, whatever their issuers: a superset of the CRLs OpenSSL can tie,
     * and the only case where the validator's listing key can order differently from the builder's.
     */
    boolean hasTieGroup()
    {
        return tieGroup;
    }

    /** The validator's order for this path (target first, as a CertPath holds it). */
    List<X509CRL> forPath(List<? extends Certificate> path)
    {
        return sorted(path);
    }

    /** The builder's order, before any path exists: keys 1, 2, 3, 5 and 6. */
    List<X509CRL> withoutPath()
    {
        return sorted(Collections.<Certificate>emptyList());
    }

    private List<X509CRL> sorted(List<? extends Certificate> path)
    {
        final Map<Entry, Boolean> lists = new IdentityHashMap<Entry, Boolean>();
        for (Entry e : entries)
        {
            lists.put(e, e.ours != null && !path.isEmpty() && listsOnePathCert(e, path));
        }
        List<Entry> order = new ArrayList<Entry>(entries);
        Collections.sort(order, new Comparator<Entry>()
        {
            public int compare(Entry x, Entry y)
            {
                int d = Boolean.compare(y.ours != null, x.ours != null);
                if (d != 0 || x.ours == null)
                {
                    return d != 0 ? d : VerifiedOrder.compareDer(x.der, y.der);
                }
                d = Boolean.compare(y.current, x.current);
                if (d != 0)
                {
                    return d;
                }
                d = Long.compare(y.thisUpdate, x.thisUpdate);
                if (d != 0)
                {
                    return d;
                }
                d = Boolean.compare(lists.get(y), lists.get(x));
                if (d != 0)
                {
                    return d;
                }
                if (x.number != null || y.number != null)
                {
                    if (x.number == null || y.number == null)
                    {
                        return x.number == null ? 1 : -1;
                    }
                    d = y.number.compareTo(x.number);
                    if (d != 0)
                    {
                        return d;
                    }
                }
                return VerifiedOrder.compareDer(x.der, y.der);
            }
        });
        List<X509CRL> out = new ArrayList<X509CRL>(order.size());
        for (Entry e : order)
        {
            out.add(e.callers);
        }
        return out;
    }

    /**
     * Whether the CRL lists the serial number of a certificate of the path, whoever issued it: a name test here
     * would be narrower than OpenSSL's (see the class description), and the key orders, never decides.
     */
    private static boolean listsOnePathCert(Entry e, List<? extends Certificate> path)
    {
        for (Certificate c : path)
        {
            if (e.ours.getRevokedCertificate(((X509Certificate) c).getSerialNumber()) != null)
            {
                return true;
            }
        }
        return false;
    }

    /** The CRL number from the extension's encoding (an OCTET STRING holding an INTEGER); null when unreadable. */
    static BigInteger crlNumber(byte[] ext)
    {
        if (ext == null)
        {
            return null;
        }
        int[] at = new int[]{0};
        if (contentLength(ext, at, 0x04) < 0)
        {
            return null;
        }
        int len = contentLength(ext, at, 0x02);
        if (len <= 0)
        {
            return null;
        }
        byte[] v = new byte[len];
        System.arraycopy(ext, at[0], v, 0, len);
        return new BigInteger(v);
    }

    /**
     * Reads a tag and a definite length at at[0], leaving at[0] on the content; the content length, or -1 when the
     * tag differs or the length is malformed or runs past the end.
     */
    private static int contentLength(byte[] b, int[] at, int tag)
    {
        int i = at[0];
        if (i + 2 > b.length || (b[i] & 0xff) != tag)
        {
            return -1;
        }
        int len = b[i + 1] & 0xff;
        i += 2;
        if (len > 0x7f)
        {
            int n = len & 0x7f;
            if (n == 0 || n > 3 || i + n > b.length)
            {
                return -1;
            }
            len = 0;
            for (int k = 0; k < n; k++)
            {
                len = (len << 8) | (b[i++] & 0xff);
            }
        }
        if (i + len > b.length)
        {
            return -1;
        }
        at[0] = i;
        return len;
    }
}
