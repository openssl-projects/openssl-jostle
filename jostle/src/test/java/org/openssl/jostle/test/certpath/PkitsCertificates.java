package org.openssl.jostle.test.certpath;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Loads the committed PKITS subset from the classpath.
 * <p>
 * One class, so phase 2 extends it rather than duplicating it — CRLs will load
 * the same way from the same directory.
 */
public final class PkitsCertificates
{
    public static final String ANCHOR = "TrustAnchorRootCertificate.crt";

    private static final String BASE = "/pkits/";
    private static final Map<String, byte[]> CACHE = new HashMap<String, byte[]>();

    /** One PKITS row: the case number, its expected outcome, and its path. */
    public static final class Case
    {
        public final String number;
        public final boolean expectValid;
        public final String endEntity;
        public final List<String> intermediates;

        Case(String number, boolean expectValid, String endEntity, List<String> intermediates)
        {
            this.number = number;
            this.expectValid = expectValid;
            this.endEntity = endEntity;
            this.intermediates = Collections.unmodifiableList(intermediates);
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
        byte[] cached = CACHE.get(name);
        if (cached != null)
        {
            return cached;
        }
        InputStream in = PkitsCertificates.class.getResourceAsStream(BASE + "certs/" + name);
        if (in == null)
        {
            throw new IOException("PKITS certificate not on the classpath: " + name
                    + " — the phase 1 subset is committed under src/test/resources/pkits/certs");
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
            CACHE.put(name, der);
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
                String[] f = line.split("\\|");
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
                out.add(new Case(f[0], "PASS".equals(f[1]), f[2], inter));
            }
        }
        finally
        {
            in.close();
        }
        return out;
    }
}
