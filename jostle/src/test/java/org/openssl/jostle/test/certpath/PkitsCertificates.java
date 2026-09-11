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
