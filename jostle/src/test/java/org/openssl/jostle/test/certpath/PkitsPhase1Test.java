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
 * <p>
 * Since phase 2 the table also carries the revocation sections, so this class
 * SELECTS its own rows. {@link PkitsPhase2Test} asserts that the two
 * selections partition the table exactly, which is what stops a row from
 * being claimed twice or by neither.
 */
public class PkitsPhase1Test
{
    /** Documented divergences, each pinned with its reason in its own test. */
    static final List<String> PINNED_DIVERGENCES =
            java.util.Arrays.asList("4.1.5", "4.6.4");

    /** The sections whose cases need no revocation processing. */
    static final List<String> SECTIONS =
            java.util.Arrays.asList("4.1", "4.2", "4.3", "4.5", "4.6", "4.7");

    /**
     * Revocation in disguise: these sit in phase 1's sections but their
     * outcome turns on a CRL, so phase 2 owns them.
     */
    static final List<String> REVOCATION_IN_DISGUISE =
            java.util.Arrays.asList("4.5.2", "4.5.5", "4.5.7", "4.7.4", "4.7.5");

    /** The rows this class owns. */
    static List<PkitsCertificates.Case> selected() throws Exception
    {
        List<PkitsCertificates.Case> out = new ArrayList<PkitsCertificates.Case>();
        for (PkitsCertificates.Case c : PkitsCertificates.cases())
        {
            if (SECTIONS.contains(c.section()) && !REVOCATION_IN_DISGUISE.contains(c.number))
            {
                out.add(c);
            }
        }
        return out;
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The shared chainer, not a naive reverse of the row. A row's certificate
     * list includes CRL-signing certificates that are NOT path members, and
     * reversing it put one at path index 1 — which the JDK and BouncyCastle
     * both rightly refused while we accepted it. See
     * {@link PkitsCertificates#chain}.
     */
    static CertPath path(PkitsCertificates.Case c) throws Exception
    {
        return CertificateFactory.getInstance("X.509")
                .generateCertPath(PkitsCertificates.chain(c));
    }

    static PKIXParameters params() throws Exception
    {
        PKIXParameters p = new PKIXParameters(Collections.singleton(
                new TrustAnchor(PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)));
        // These cases are not about revocation, so it is turned off
        // explicitly. Since phase 2 that is an opt-out rather than the only
        // accepted setting, and the expected outcomes below are the ones
        // PKITS gives for the path alone.
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
        List<PkitsCertificates.Case> cases = selected();
        Assertions.assertEquals(50, cases.size(), "phase 1 must select 50 rows from the table");

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
            for (String n : c.crls)
            {
                try
                {
                    PkitsCertificates.crlDer(n);
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
