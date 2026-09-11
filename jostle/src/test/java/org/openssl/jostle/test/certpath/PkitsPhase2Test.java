package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * NIST PKITS revocation: 4.4 Basic Certificate Revocation (21), 4.14
 * Distribution Points (35), 4.15 Delta-CRLs (10), plus the five cases that sit
 * in phase 1's sections but turn on a CRL — 71 rows.
 * <p>
 * The CRLs come from a {@code CertStore}, which is where a real caller puts
 * them, and revocation is left at its JCE default of ON.
 *
 * <h2>What is not run here, and why</h2>
 * <b>4.15.4 and 4.15.5 are HELD.</b> They are the only two cases whose outcome
 * depends on whether delta CRLs are honoured, and that is an open ruling.
 * Measured: OpenSSL under {@code X509_V_FLAG_USE_DELTAS} gets both RIGHT where
 * the JDK gets both WRONG, so honouring deltas moves us towards PKITS and away
 * from JDK parity. Until the ruling lands the flag is off and these two are
 * neither run nor pinned — an unheld case asserting today's answer would have
 * to be rewritten by the ruling either way.
 * <p>
 * <b>4.14.30 is a pinned divergence</b>, in
 * {@link PkitsRevocationDivergenceTest} with its mechanism.
 */
public class PkitsPhase2Test
{
    /** The revocation sections. */
    static final List<String> SECTIONS = java.util.Arrays.asList("4.4", "4.14", "4.15");

    /**
     * Held pending the delta-CRL ruling. Named rather than counted, so the
     * two that are missing from the sweep are the two that were meant to be.
     */
    static final List<String> HELD_PENDING_DELTA_RULING =
            java.util.Arrays.asList("4.15.4", "4.15.5");

    /** Divergences pinned by name, each with its measured mechanism. */
    static final List<String> PINNED_DIVERGENCES = java.util.Arrays.asList("4.14.30");

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** The rows this class owns: its own sections plus phase 1's five. */
    static List<PkitsCertificates.Case> selected() throws Exception
    {
        List<PkitsCertificates.Case> out = new ArrayList<PkitsCertificates.Case>();
        for (PkitsCertificates.Case c : PkitsCertificates.cases())
        {
            if (SECTIONS.contains(c.section())
                    || PkitsPhase1Test.REVOCATION_IN_DISGUISE.contains(c.number))
            {
                out.add(c);
            }
        }
        return out;
    }

    static PkitsCertificates.Case find(String number) throws Exception
    {
        for (PkitsCertificates.Case c : PkitsCertificates.cases())
        {
            if (c.number.equals(number))
            {
                return c;
            }
        }
        throw new IllegalStateException("case " + number + " is not in the committed table");
    }

    /**
     * The certification path, chained from the END ENTITY by SIGNATURE.
     *
     * <p>PKITS lists CRL-SIGNING certificates in the same bullets as the path
     * members, so "every certificate in the row, reversed" puts a non-CA at
     * path index 1 — measured, that failed 4.4.19 and 4.14.24/25/28/29.
     * Selection is by WHICH KEY VERIFIED the signature, not by name: a
     * self-issued certificate shares a subject with the real CA, so a name
     * match picks by file order.
     */
    static CertPath path(PkitsCertificates.Case c) throws Exception
    {
        List<X509Certificate> pool = new ArrayList<X509Certificate>();
        for (String n : c.intermediates)
        {
            pool.add(PkitsCertificates.certificate(n));
        }
        X509Certificate anchor = PkitsCertificates.certificate(PkitsCertificates.ANCHOR);

        List<X509Certificate> chain = new ArrayList<X509Certificate>();
        X509Certificate current = PkitsCertificates.certificate(c.endEntity);
        chain.add(current);
        while (!signedBy(current, anchor))
        {
            X509Certificate issuer = null;
            for (X509Certificate cand : pool)
            {
                if (!chain.contains(cand) && signedBy(current, cand))
                {
                    issuer = cand;
                    break;
                }
            }
            Assertions.assertNotNull(issuer,
                    c.number + ": no supplied certificate signed "
                            + current.getSubjectX500Principal()
                            + " — the case table or this chaining is wrong");
            chain.add(issuer);
            current = issuer;
        }
        return CertificateFactory.getInstance("X.509").generateCertPath(chain);
    }

    private static boolean signedBy(X509Certificate cert, X509Certificate issuer)
    {
        if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()))
        {
            return false;
        }
        try
        {
            cert.verify(issuer.getPublicKey());
            return true;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    /**
     * Everything the row names that is NOT a path member — the CRL-signing
     * certificates. A real caller has these in a store, and an indirect CRL
     * cannot be validated without them.
     */
    static List<X509Certificate> extras(PkitsCertificates.Case c) throws Exception
    {
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        List<? extends java.security.cert.Certificate> inPath = path(c).getCertificates();
        for (String n : c.intermediates)
        {
            X509Certificate cand = PkitsCertificates.certificate(n);
            if (!inPath.contains(cand))
            {
                out.add(cand);
            }
        }
        return out;
    }

    /**
     * Revocation ON — the JCE default, left alone — with the case's own CRLs
     * and its non-path certificates in a CertStore, which is where a caller
     * holds them.
     */
    static PKIXParameters params(PkitsCertificates.Case c) throws Exception
    {
        PKIXParameters p = new PKIXParameters(Collections.singleton(
                new TrustAnchor(PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)));
        Assertions.assertTrue(p.isRevocationEnabled(),
                "these cases are ABOUT revocation; the JCE default must still be on");
        List<Object> contents = new ArrayList<Object>();
        for (String name : c.crls)
        {
            contents.add(PkitsCertificates.crl(name));
        }
        contents.addAll(extras(c));
        p.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(contents)));
        return p;
    }

    /** The last refusal seen by {@link #validates}, for the failure report. */
    private static final ThreadLocal<String> LAST_REFUSAL = new ThreadLocal<String>();

    static boolean validates(PkitsCertificates.Case c) throws Exception
    {
        CertPath cp = path(c);
        try
        {
            CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME)
                    .validate(cp, params(c));
            LAST_REFUSAL.set(null);
            return true;
        }
        catch (CertPathValidatorException e)
        {
            // A disagreement must say WHY. Reporting only valid/invalid makes
            // a wrong path construction and a wrong verdict look identical.
            LAST_REFUSAL.set(e.getReason() + " / " + e.getMessage());
            return false;
        }
    }

    /**
     * Every revocation case agrees with the specification, reported as one
     * list rather than failing at the first.
     */
    @Test
    public void everyRevocationCaseAgreesWithPkits() throws Exception
    {
        List<PkitsCertificates.Case> cases = selected();
        Assertions.assertEquals(71, cases.size(), "phase 2 must select 71 rows from the table");

        List<String> failures = new ArrayList<String>();
        int checked = 0;
        for (PkitsCertificates.Case c : cases)
        {
            if (HELD_PENDING_DELTA_RULING.contains(c.number)
                    || PINNED_DIVERGENCES.contains(c.number))
            {
                continue;
            }
            checked++;
            boolean got = validates(c);
            if (got != c.expectValid)
            {
                failures.add(c.number + ": PKITS expects "
                        + (c.expectValid ? "valid" : "invalid") + ", got "
                        + (got ? "valid" : "invalid")
                        + (got ? "" : " [" + LAST_REFUSAL.get() + "]"));
            }
        }
        Assertions.assertEquals(68, checked,
                "71 cases minus the 2 held for the delta ruling and the 1 pinned divergence");
        Assertions.assertTrue(failures.isEmpty(), "PKITS disagreements: " + failures);
    }

    /**
     * The vacuity guard on the table itself. A selection that silently
     * narrowed — a section renamed, a row dropped by the generator — would
     * make the sweep above pass over fewer cases with nothing to say so, so
     * the two phases must PARTITION the table: every row claimed, none twice.
     */
    @Test
    public void thePhasesPartitionTheCaseTableExactly() throws Exception
    {
        List<PkitsCertificates.Case> all = PkitsCertificates.cases();
        Assertions.assertEquals(121, all.size(), "the committed table must hold 121 rows");

        Set<String> phase1 = new HashSet<String>();
        for (PkitsCertificates.Case c : PkitsPhase1Test.selected())
        {
            phase1.add(c.number);
        }
        Set<String> phase2 = new HashSet<String>();
        for (PkitsCertificates.Case c : selected())
        {
            phase2.add(c.number);
        }

        Set<String> both = new HashSet<String>(phase1);
        both.retainAll(phase2);
        Assertions.assertTrue(both.isEmpty(), "a case is claimed by both phases: " + both);

        Set<String> unclaimed = new HashSet<String>();
        for (PkitsCertificates.Case c : all)
        {
            if (!phase1.contains(c.number) && !phase2.contains(c.number))
            {
                unclaimed.add(c.number);
            }
        }
        Assertions.assertTrue(unclaimed.isEmpty(), "a case is claimed by neither phase: " + unclaimed);
        Assertions.assertEquals(50, phase1.size());
        Assertions.assertEquals(71, phase2.size());
    }

    /**
     * The CRL column is populated and every name in it decodes.
     *
     * <p>Deliberately NOT one CRL per intermediate: an indirect CRL covers
     * certificates it did not issue, so that rule flags thirteen correct
     * rows. What holds without inventing a rule is that every case names a
     * CRL, every name resolves, and the column is not vacuous.
     */
    @Test
    public void everyRevocationCaseNamesCrlsThatResolve() throws Exception
    {
        List<String> bare = new ArrayList<String>();
        Set<String> distinct = new HashSet<String>();
        for (PkitsCertificates.Case c : selected())
        {
            if (c.crls.isEmpty())
            {
                bare.add(c.number);
            }
            for (String n : c.crls)
            {
                PkitsCertificates.crl(n);   // throws if it is not a CRL
                distinct.add(n);
            }
        }
        Assertions.assertTrue(bare.isEmpty(), "revocation cases naming no CRL at all: " + bare);
        // A column that lost its content would still satisfy the two checks
        // above on an empty table; 71 revocation cases cannot share a handful.
        Assertions.assertTrue(distinct.size() >= 40,
                "only " + distinct.size() + " distinct CRLs across 71 revocation cases — "
                        + "the CRL column looks truncated");
    }

    /**
     * The held pair is held, not forgotten: both must still be in the table,
     * so the delta ruling has something to land on.
     */
    @Test
    public void theHeldDeltaCasesAreStillInTheTable() throws Exception
    {
        for (String n : HELD_PENDING_DELTA_RULING)
        {
            PkitsCertificates.Case c = find(n);
            Assertions.assertFalse(c.crls.isEmpty(), n + " must carry its CRLs");
        }
        // 4.15.6 is the control: the rest of 4.15 agrees whether or not
        // deltas are honoured, so the section is not skipped wholesale.
        Assertions.assertFalse(validates(find("4.15.6")),
                "4.15.6 is expected to fail whatever the delta ruling");
    }
}
