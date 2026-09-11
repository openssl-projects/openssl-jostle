package org.openssl.jostle.test.certpath;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Loads the committed PKITS corpus from the classpath.
 * <p>
 * The whole distribution is committed — 405 certificates and 173 CRLs — so a
 * name the case table cannot resolve is a missing-file failure that names
 * itself, rather than a subset silently offering the wrong file.
 */
public final class PkitsCertificates
{
    public static final String ANCHOR = "TrustAnchorRootCertificate.crt";

    private static final String BASE = "/pkits/";
    private static final Map<String, byte[]> CACHE = new HashMap<String, byte[]>();

    /**
     * One PKITS row: the case number, its expected outcome, its path, and the
     * CRLs the specification lists for it.
     */
    public static final class Case
    {
        public final String number;
        public final boolean expectValid;
        public final String endEntity;
        public final List<String> intermediates;
        public final List<String> crls;

        Case(String number, boolean expectValid, String endEntity, List<String> intermediates,
             List<String> crls)
        {
            this.number = number;
            this.expectValid = expectValid;
            this.endEntity = endEntity;
            this.intermediates = Collections.unmodifiableList(intermediates);
            this.crls = Collections.unmodifiableList(crls);
        }

        /** The section this case belongs to, e.g. "4.14" for 4.14.30. */
        public String section()
        {
            int last = number.lastIndexOf('.');
            return number.substring(0, last);
        }

        @Override
        public String toString()
        {
            return number;
        }
    }

    private PkitsCertificates()
    {
    }

    public static synchronized byte[] der(String name) throws IOException
    {
        return read("certs/", name);
    }

    /** A CRL's DER, by the file name the case table carries. */
    public static synchronized byte[] crlDer(String name) throws IOException
    {
        return read("crls/", name);
    }

    public static X509CRL crl(String name) throws IOException, CRLException, CertificateException
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlDer(name)));
    }

    private static byte[] read(String dir, String name) throws IOException
    {
        byte[] cached = CACHE.get(dir + name);
        if (cached != null)
        {
            return cached;
        }
        InputStream in = PkitsCertificates.class.getResourceAsStream(BASE + dir + name);
        if (in == null)
        {
            throw new IOException("PKITS file not on the classpath: " + dir + name
                    + " — the whole corpus is committed under src/test/resources/pkits");
        }
        try
        {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0)
            {
                out.write(buf, 0, n);
            }
            byte[] der = out.toByteArray();
            CACHE.put(dir + name, der);
            return der;
        }
        finally
        {
            in.close();
        }
    }

    public static X509Certificate certificate(String name) throws IOException, CertificateException
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der(name)));
    }

    /**
     * The certification path for a row: chained from the END ENTITY by issuer
     * NAME plus key identifier, dropping any certificate the chain never
     * reaches.
     *
     * <p>PKITS rows list CRL-SIGNING certificates in the same bullets as the
     * path members, so "every certificate in the row, reversed" puts a non-CA
     * at path index 1. Measured: that is what made 4.5.4 and 4.5.6 look like
     * provider divergences when the JDK and BouncyCastle were both right to
     * refuse the path we had built.
     *
     * <p>Selection is by key identifier, not by signature: sections 4.1.2,
     * 4.1.3 and 4.1.6 exist precisely to carry BROKEN signatures, so a
     * signature-verifying chainer cannot reach the anchor for them. It is not
     * by name alone either: 4.13.19's self-issued certificate shares its
     * subject with the real CA, and only the key identifier separates them.
     */
    public static List<X509Certificate> chain(Case c) throws Exception
    {
        List<X509Certificate> pool = new ArrayList<X509Certificate>();
        for (String n : c.intermediates)
        {
            pool.add(certificate(n));
        }
        X509Certificate anchor = certificate(ANCHOR);

        List<X509Certificate> chain = new ArrayList<X509Certificate>();
        X509Certificate current = certificate(c.endEntity);
        chain.add(current);
        while (!issuedBy(current, anchor))
        {
            X509Certificate issuer = null;
            for (X509Certificate cand : pool)
            {
                if (!chain.contains(cand) && issuedBy(current, cand))
                {
                    issuer = cand;
                    break;
                }
            }
            if (issuer == null)
            {
                // A row whose DEFECT IS THE CHAIN cannot be chained: section
                // 4.3 breaks name chaining on purpose, so 4.3.1's end entity
                // names an issuer no supplied certificate matches. PKITS lists
                // a row's certificates in path order, anchor first, so the
                // remainder in reverse row order IS the intended path — and it
                // is what a caller who read the specification would build.
                for (int i = c.intermediates.size() - 1; i >= 0; i--)
                {
                    X509Certificate rest = certificate(c.intermediates.get(i));
                    if (!chain.contains(rest))
                    {
                        chain.add(rest);
                    }
                }
                return chain;
            }
            chain.add(issuer);
            current = issuer;
        }
        return chain;
    }

    /**
     * Issuer name matches, and where both carry key identifiers those match
     * too. A certificate with no AKID falls back to the name, which is all
     * RFC 5280 requires of it.
     */
    static boolean issuedBy(X509Certificate cert, X509Certificate issuer)
    {
        if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()))
        {
            return false;
        }
        byte[] akid = authorityKeyId(cert);
        byte[] skid = subjectKeyId(issuer);
        if (akid == null || skid == null)
        {
            return true;
        }
        return java.util.Arrays.equals(akid, skid);
    }

    /** SKID (2.5.29.14): OCTET STRING wrapping an OCTET STRING. */
    static byte[] subjectKeyId(X509Certificate cert)
    {
        byte[] inner = extensionContent(cert, "2.5.29.14");
        if (inner == null || inner.length == 0 || (inner[0] & 0xff) != 0x04)
        {
            return null;
        }
        return derValue(inner, 0);
    }

    /**
     * AKID (2.5.29.35): OCTET STRING wrapping a SEQUENCE whose first element,
     * when present, is the keyIdentifier as [0] IMPLICIT OCTET STRING.
     */
    static byte[] authorityKeyId(X509Certificate cert)
    {
        byte[] inner = extensionContent(cert, "2.5.29.35");
        if (inner == null || inner.length == 0 || (inner[0] & 0xff) != 0x30)
        {
            return null;
        }
        int[] pos = new int[1];
        byte[] seq = derValue(inner, 0, pos);
        if (seq == null || seq.length == 0 || (seq[0] & 0xff) != 0x80)
        {
            return null;
        }
        return derValue(seq, 0);
    }

    /** The bytes INSIDE the extension's own OCTET STRING wrapper. */
    private static byte[] extensionContent(X509Certificate cert, String oid)
    {
        byte[] raw = cert.getExtensionValue(oid);
        if (raw == null || raw.length == 0 || (raw[0] & 0xff) != 0x04)
        {
            return null;
        }
        return derValue(raw, 0);
    }

    private static byte[] derValue(byte[] der, int off)
    {
        return derValue(der, off, new int[1]);
    }

    /** The VALUE of the TLV at {@code off}; {@code end[0]} gets the next offset. */
    private static byte[] derValue(byte[] der, int off, int[] end)
    {
        int i = off + 1;
        if (i >= der.length)
        {
            return null;
        }
        int len = der[i++] & 0xff;
        if (len > 0x80)
        {
            int n = len - 0x80;
            if (n > 4 || i + n > der.length)
            {
                return null;
            }
            len = 0;
            for (int k = 0; k < n; k++)
            {
                len = (len << 8) | (der[i++] & 0xff);
            }
        }
        else if (len == 0x80)
        {
            return null;
        }
        if (len < 0 || i + len > der.length)
        {
            return null;
        }
        end[0] = i + len;
        byte[] out = new byte[len];
        System.arraycopy(der, i, out, 0, len);
        return out;
    }

    /**
     * The case table, read from the same {@code cases.txt} that was generated
     * from PKITS.pdf — so the expected column is the specification's rather
     * than anything restated here.
     */
    public static List<Case> cases() throws IOException
    {
        InputStream in = PkitsCertificates.class.getResourceAsStream(BASE + "cases.txt");
        if (in == null)
        {
            throw new IOException("pkits/cases.txt is not on the classpath");
        }
        List<Case> out = new ArrayList<Case>();
        try
        {
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(in, "UTF-8"));
            String line;
            while ((line = r.readLine()) != null)
            {
                if (line.trim().isEmpty())
                {
                    continue;
                }
                // -1 keeps a trailing empty field, so a case with no CRL
                // still parses as five columns rather than four.
                String[] f = line.split("\\|", -1);
                List<String> inter = new ArrayList<String>();
                if (f.length > 3 && !f[3].isEmpty())
                {
                    for (String s : f[3].split(","))
                    {
                        if (!ANCHOR.equals(s))
                        {
                            inter.add(s);
                        }
                    }
                }
                List<String> crls = new ArrayList<String>();
                if (f.length > 4 && !f[4].isEmpty())
                {
                    Collections.addAll(crls, f[4].split(","));
                }
                out.add(new Case(f[0], "PASS".equals(f[1]), f[2], inter, crls));
            }
        }
        finally
        {
            in.close();
        }
        return out;
    }
}
