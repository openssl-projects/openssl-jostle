package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * NIST PKITS, the 50 cases of sections 4.1, 4.2, 4.3, 4.5, 4.6 and 4.7 that
 * need neither revocation nor policy processing.
 * <p>
 * The expected outcomes come from {@code cases.txt}, generated from PKITS.pdf's
 * own "Expected Result" text, so this class restates nothing. Two cases are
 * expected to DIVERGE and are pinned separately, by name, in
 * {@link PkitsDivergenceTest} — they are excluded here rather than silently
 * tolerated.
 */
public class PkitsPhase1Test
{
    /** Documented divergences, each pinned with its reason in its own test. */
    static final List<String> PINNED_DIVERGENCES =
            java.util.Arrays.asList("4.1.5", "4.6.4");

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    static CertPath path(PkitsCertificates.Case c) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> chain = new ArrayList<X509Certificate>();
        chain.add(PkitsCertificates.certificate(c.endEntity));
        for (int i = c.intermediates.size() - 1; i >= 0; i--)
        {
            chain.add(PkitsCertificates.certificate(c.intermediates.get(i)));
        }
        return cf.generateCertPath(chain);
    }

    static PKIXParameters params() throws Exception
    {
        PKIXParameters p = new PKIXParameters(Collections.singleton(
                new TrustAnchor(PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)));
        // Phase 1 has no revocation, and the SPI refuses the default rather
        // than silently dropping it.
        p.setRevocationEnabled(false);
        return p;
    }

    static boolean validates(CertPath cp, PKIXParameters p) throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME).validate(cp, p);
            return true;
        }
        catch (CertPathValidatorException e)
        {
            return false;
        }
    }

    /**
     * Every case agrees with the specification, and the run is reported as one
     * list rather than failing at the first — a module or OpenSSL change reads
     * as one legible diff instead of a fix-one-rerun-repeat loop.
     */
    @Test
    public void everyPhase1CaseAgreesWithPkits() throws Exception
    {
        List<PkitsCertificates.Case> cases = PkitsCertificates.cases();
        Assertions.assertEquals(50, cases.size(), "the committed case table must hold 50 rows");

        List<String> failures = new ArrayList<String>();
        int checked = 0;
        for (PkitsCertificates.Case c : cases)
        {
            if (PINNED_DIVERGENCES.contains(c.number))
            {
                continue;
            }
            checked++;
            boolean got = validates(path(c), params());
            if (got != c.expectValid)
            {
                failures.add(c.number + ": PKITS expects "
                        + (c.expectValid ? "valid" : "invalid") + ", got "
                        + (got ? "valid" : "invalid"));
            }
        }
        Assertions.assertEquals(48, checked, "50 cases minus the 2 pinned divergences");
        Assertions.assertTrue(failures.isEmpty(), "PKITS disagreements: " + failures);
    }

    /** The table must not drift into naming a certificate that is not committed. */
    @Test
    public void everyCertificateTheTableNamesIsPresent() throws Exception
    {
        List<String> missing = new ArrayList<String>();
        for (PkitsCertificates.Case c : PkitsCertificates.cases())
        {
            List<String> names = new ArrayList<String>(c.intermediates);
            names.add(c.endEntity);
            for (String n : names)
            {
                try
                {
                    PkitsCertificates.der(n);
                }
                catch (Exception e)
                {
                    missing.add(c.number + " -> " + n);
                }
            }
        }
        PkitsCertificates.der(PkitsCertificates.ANCHOR);
        Assertions.assertTrue(missing.isEmpty(), "case table names uncommitted certificates: " + missing);
    }
}
