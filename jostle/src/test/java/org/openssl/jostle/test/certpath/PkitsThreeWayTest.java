package org.openssl.jostle.test.certpath;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXParameters;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Every PKITS row against its expected outcome, on this provider, the JDK's
 * SUN and BouncyCastle. The phase classes ask whether WE agree with the
 * specification; only three providers side by side say whether a disagreement
 * is ours or the corpus's.
 *
 * <p>The fixture is decoded by JCA-default X.509, so all three get the same
 * objects and this measures validation alone. One path builder for every row,
 * so a third construction site cannot drift from the phase classes; those
 * differ only in parameters, which is where this class branches.
 *
 * <p>BouncyCastle's disagreements are prose, never assertions: a bcprov fix
 * must not turn this suite red.
 */
public class PkitsThreeWayTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String SUN = "SUN";
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String[] PROVIDERS = {JSL, SUN, BC};

    /**
     * The reference BouncyCastle, stamped so a bump is loud rather than
     * silent — every exclusion below is a measurement against THIS version.
     * {@code getVersionStr()} is Java 9+ and this source set compiles at
     * release 8, so the version is read as the numeric form beside the info
     * string; neither alone is specific enough to name a release.
     */
    private static final double BCPROV_VERSION = 1.8502;
    private static final String BCPROV_INFO = "BouncyCastle Security Provider v1.85.2";

    /**
     * Held pending the delta-CRL ruling, on every provider. The SAME list
     * PkitsPhase2Test holds, never a copy, so that commit moves both at once.
     * Both rows currently agree three ways while disagreeing with PKITS, so
     * running them would assert an answer nobody defends. At the ruling they
     * leave HELD and become FOUR FOREIGN exclusions, not ours: under
     * X509_V_FLAG_USE_DELTAS OpenSSL gets both rows right and the JDK gets
     * both wrong, so it is SUN and BC that then need sanctioning on each.
     */
    static final List<String> HELD_PENDING_DELTA_RULING =
            PkitsPhase2Test.HELD_PENDING_DELTA_RULING;

    /** A single (case, provider, measured reason) sanction. */
    private static final class Exclusion
    {
        final String number;
        final String provider;
        final String reason;

        Exclusion(String number, String provider, String reason)
        {
            this.number = number;
            this.provider = provider;
            this.reason = reason;
        }
    }

    /**
     * The measured divergences, one per (case, provider). Scoped to the
     * provider that diverges and no wider: a flat list of case numbers would
     * excuse a row for all three and silently stop checking the two that were
     * right. 4.14.30 needs two entries for exactly that reason — we and
     * BouncyCastle both miss it, for unrelated causes.
     *
     * <p>Every reason is the text that provider actually produced, measured
     * 2026-09-12 on the corrected paths (reviews/three-way-reprobe-2026-09-12.md).
     */
    private static final List<Exclusion> EXCLUSIONS = new ArrayList<Exclusion>();

    static
    {
        // Ours. Both are pinned with their mechanism, in both halves, in
        // PkitsDivergenceTest — this entry defers to that pin rather than
        // repeating it.
        EXCLUSIONS.add(new Exclusion("4.1.5", JSL,
                "DSA parameter inheritance is unimplemented in OpenSSL; error 20 at depth 0. "
                        + "Pinned in PkitsDivergenceTest."));
        EXCLUSIONS.add(new Exclusion("4.6.4", JSL,
                "non-critical basicConstraints refused under X509_V_FLAG_X509_STRICT; error 89. "
                        + "Pinned in PkitsDivergenceTest."));
        EXCLUSIONS.add(new Exclusion("4.14.30", JSL,
                "recursive indirect-CRL resolution refused by check_crl_path; error 54. "
                        + "Pinned in PkitsRevocationDivergenceTest."));

        // BouncyCastle's. Prose only.
        EXCLUSIONS.add(new Exclusion("4.3.2", BC,
                "BC accepts a path PKITS, SUN and this provider all refuse; SUN names "
                        + "\"subject/issuer name chaining check failed\", we return error 20"));
        EXCLUSIONS.add(new Exclusion("4.14.28", BC,
                "BC: \"No match for certificate CRL issuing distribution point name to "
                        + "cRLIssuer CRL distribution\""));
        EXCLUSIONS.add(new Exclusion("4.14.29", BC,
                "BC: \"No match for certificate CRL issuing distribution point name to "
                        + "cRLIssuer CRL distribution\""));
        EXCLUSIONS.add(new Exclusion("4.14.30", BC,
                "BC: \"No CRLs found for issuer ... indirectCRL CA4\" — a different miss from "
                        + "ours on the same row, which is why the row carries two entries"));
        EXCLUSIONS.add(new Exclusion("4.14.31", BC,
                "BC returns valid where PKITS, SUN and this provider all report the "
                        + "certificate revoked (KEY_COMPROMISE)"));
        EXCLUSIONS.add(new Exclusion("4.14.32", BC,
                "BC returns valid where PKITS, SUN and this provider all report the "
                        + "certificate revoked (KEY_COMPROMISE)"));
    }

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        // No network, ever. Setting a property is not the same as it being in
        // force — a misspelled name is a default in disguise — so each is read
        // back below. Read sites, measured from source rather than assumed:
        //   ocsp.enable  JDK 25 (zulu 25.0.0)
        //       sun.security.provider.certpath.RevocationChecker:187, Security.getProperty
        //   com.sun.security.enableCRLDP  JDK 25 (zulu 25.0.0)
        //       sun.security.provider.certpath.RevocationChecker:194, Boolean.getBoolean
        //       (NOT DistributionPointFetcher, which reads neither)
        //   org.bouncycastle.x509.enableCRLDP  bcprov-jdk18on 1.85.2
        //       org.bouncycastle.util.Properties holds the literal (and a
        //       META-INF/versions/9 copy); read in
        //       org.bouncycastle.jce.provider.CertPathValidatorUtilities via isOverrideSet
        System.setProperty("com.sun.security.enableCRLDP", "false");
        System.setProperty("org.bouncycastle.x509.enableCRLDP", "false");
        Security.setProperty("ocsp.enable", "false");

        requireSystemProperty("com.sun.security.enableCRLDP");
        requireSystemProperty("org.bouncycastle.x509.enableCRLDP");
        Assertions.assertEquals("false", Security.getProperty("ocsp.enable"),
                "ocsp.enable did not read back false");
    }

    private static void requireSystemProperty(String name)
    {
        Assertions.assertEquals("false", System.getProperty(name),
                name + " did not read back false");
    }

    /** True when the row is validated without revocation processing. */
    private static boolean isPhase1(PkitsCertificates.Case c)
    {
        return PkitsPhase1Test.SECTIONS.contains(c.section())
                && !PkitsPhase1Test.REVOCATION_IN_DISGUISE.contains(c.number);
    }

    private static CertPath path(PkitsCertificates.Case c) throws Exception
    {
        return PkitsPhase2Test.path(c);
    }

    /**
     * A FRESH PKIXParameters for every provider on every row. The object is
     * mutable and a validator may set state on it, so sharing one across the
     * three would make the third measurement depend on the first two.
     */
    private static PKIXParameters params(PkitsCertificates.Case c) throws Exception
    {
        return isPhase1(c) ? PkitsPhase1Test.params() : PkitsPhase2Test.params(c);
    }

    /**
     * Validity as the JCE reports it. Only a CertPathValidatorException means
     * "invalid" — anything else is a broken fixture and must propagate rather
     * than be recorded as a verdict.
     */
    private static boolean validates(String provider, PkitsCertificates.Case c) throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", provider).validate(path(c), params(c));
            return true;
        }
        catch (CertPathValidatorException e)
        {
            return false;
        }
    }

    private static String reasonFor(String number, String provider)
    {
        for (Exclusion x : EXCLUSIONS)
        {
            if (x.number.equals(number) && x.provider.equals(provider))
            {
                return x.reason;
            }
        }
        return null;
    }

    /** Every raw verdict, keyed case -> provider -> valid. Filled by the sweep. */
    private static Map<String, Map<String, Boolean>> sweep() throws Exception
    {
        Map<String, Map<String, Boolean>> raw = new LinkedHashMap<String, Map<String, Boolean>>();
        for (PkitsCertificates.Case c : PkitsCertificates.cases())
        {
            if (HELD_PENDING_DELTA_RULING.contains(c.number))
            {
                continue;
            }
            Map<String, Boolean> byProvider = new LinkedHashMap<String, Boolean>();
            for (String p : PROVIDERS)
            {
                byProvider.put(p, Boolean.valueOf(validates(p, c)));
            }
            raw.put(c.number, byProvider);
        }
        return raw;
    }

    /**
     * The substantive sweep: every provider agrees with PKITS on every row,
     * except where an exclusion sanctions it by name. Reported as one list
     * rather than failing at the first.
     */
    @Test
    public void everyRowAgreesWithPkitsOnEveryProviderExceptWhereSanctioned() throws Exception
    {
        List<PkitsCertificates.Case> cases = PkitsCertificates.cases();
        Map<String, Map<String, Boolean>> raw = sweep();

        List<String> failures = new ArrayList<String>();
        Map<String, Integer> checkedPerProvider = new LinkedHashMap<String, Integer>();
        for (String p : PROVIDERS)
        {
            checkedPerProvider.put(p, Integer.valueOf(0));
        }

        for (PkitsCertificates.Case c : cases)
        {
            Map<String, Boolean> byProvider = raw.get(c.number);
            if (byProvider == null)
            {
                continue;   // held
            }
            for (String p : PROVIDERS)
            {
                if (reasonFor(c.number, p) != null)
                {
                    continue;
                }
                checkedPerProvider.put(p,
                        Integer.valueOf(checkedPerProvider.get(p).intValue() + 1));
                boolean got = byProvider.get(p).booleanValue();
                if (got != c.expectValid)
                {
                    failures.add(c.number + " on " + p + ": PKITS expects "
                            + (c.expectValid ? "valid" : "invalid")
                            + ", got " + (got ? "valid" : "invalid"));
                }
            }
        }

        // Vacuity: the sweep must have seen the whole table, and each
        // provider must have been measured on every row not sanctioned for
        // it. A count that silently shrank would make the assertion above
        // pass over fewer rows with nothing to say so.
        Assertions.assertEquals(cases.size() - HELD_PENDING_DELTA_RULING.size(), raw.size(),
                "the sweep must cover every row that is not held");
        for (String p : PROVIDERS)
        {
            int expected = raw.size() - excludedRowCount(p);
            Assertions.assertEquals(expected, checkedPerProvider.get(p).intValue(),
                    p + " was measured on the wrong number of rows");
            Assertions.assertTrue(checkedPerProvider.get(p).intValue() > 100,
                    p + " was measured on only " + checkedPerProvider.get(p)
                            + " rows — the sweep has been hollowed out");
        }

        Assertions.assertTrue(failures.isEmpty(),
                "three-way PKITS disagreements (" + failures.size() + "): " + failures);
    }

    private static int excludedRowCount(String provider)
    {
        int n = 0;
        for (Exclusion x : EXCLUSIONS)
        {
            if (x.provider.equals(provider) && !HELD_PENDING_DELTA_RULING.contains(x.number))
            {
                n++;
            }
        }
        return n;
    }

    /**
     * Every exclusion names a real row, exactly once, with a reason. An entry
     * matching nothing reads exactly like a justified one, so count 0 fails.
     */
    @Test
    public void everyExclusionMatchesARealRowExactlyOnce() throws Exception
    {
        List<String> known = new ArrayList<String>();
        for (PkitsCertificates.Case c : PkitsCertificates.cases())
        {
            known.add(c.number);
        }

        List<String> seen = new ArrayList<String>();
        for (Exclusion x : EXCLUSIONS)
        {
            Assertions.assertTrue(known.contains(x.number),
                    "exclusion names a case that is not in the table: " + x.number);
            String key = x.number + "/" + x.provider;
            Assertions.assertFalse(seen.contains(key), "duplicate exclusion: " + key);
            seen.add(key);
            Assertions.assertNotNull(x.reason, key + " has no reason");
            Assertions.assertTrue(x.reason.length() > 20,
                    key + " has a reason too short to be one: " + x.reason);
        }
        Assertions.assertFalse(EXCLUSIONS.isEmpty(), "the exclusion list is empty");

        for (String n : HELD_PENDING_DELTA_RULING)
        {
            Assertions.assertTrue(known.contains(n),
                    "a held case is not in the table: " + n);
            for (String p : PROVIDERS)
            {
                Assertions.assertNull(reasonFor(n, p),
                        n + " is HELD; it must not also carry an exclusion, and it "
                                + "carries one for " + p);
            }
        }
    }

    /**
     * A foreign provider that starts agreeing must be reported — a silent pass
     * leaves a stale sanction indistinguishable from a justified one. Separate
     * from the sweep so a bcprov fix reddens this cell alone. Ours are pinned
     * in PkitsDivergenceTest and PkitsRevocationDivergenceTest; BC's half of
     * 4.14.30 belongs here, a foreign divergence like any other.
     */
    @Test
    public void theForeignExclusionsAreStillEarnt() throws Exception
    {
        List<String> caughtUp = new ArrayList<String>();
        int checked = 0;
        for (Exclusion x : EXCLUSIONS)
        {
            if (JSL.equals(x.provider))
            {
                continue;
            }
            checked++;
            PkitsCertificates.Case c = find(x.number);
            if (validates(x.provider, c) == c.expectValid)
            {
                caughtUp.add(x.provider + " now agrees with PKITS on " + x.number
                        + "; delete that line from EXCLUSIONS");
            }
        }
        Assertions.assertTrue(checked > 0,
                "no foreign exclusions were checked — this cell is measuring nothing");
        Assertions.assertTrue(caughtUp.isEmpty(), caughtUp.toString());
    }

    /**
     * The instrument can discriminate: at least one row on which the three
     * providers genuinely differ from each other.
     *
     * <p>Measured over the RAW verdicts, BEFORE exclusions. After them the
     * guard would be hollow by construction — every genuine disagreement is
     * precisely what an exclusion removes, so it would pass on an instrument
     * that discriminated nothing at all.
     */
    @Test
    public void theProvidersGenuinelyDisagreeSomewhere() throws Exception
    {
        List<String> split = new ArrayList<String>();
        for (Map.Entry<String, Map<String, Boolean>> e : sweep().entrySet())
        {
            Map<String, Boolean> v = e.getValue();
            if (!(v.get(JSL).equals(v.get(SUN)) && v.get(SUN).equals(v.get(BC))))
            {
                split.add(e.getKey());
            }
        }
        Assertions.assertFalse(split.isEmpty(),
                "no row separates the three providers; the sweep cannot discriminate anything");
    }

    /**
     * The three names resolve to three DIFFERENT providers.
     *
     * <p>Compared by provider identity, not by class: the JCE hands back the
     * {@code java.security.cert.CertPathValidator} wrapper for every provider
     * alike, so a class-name check reports the same string three times and
     * would pass while measuring one implementation thrice.
     */
    @Test
    public void theThreeNamesResolveToThreeDistinctProviders() throws Exception
    {
        List<Provider> seen = new ArrayList<Provider>();
        for (String p : PROVIDERS)
        {
            Provider resolved = CertPathValidator.getInstance("PKIX", p).getProvider();
            Assertions.assertEquals(p, resolved.getName(),
                    "asked for " + p + " and got " + resolved.getName());
            for (Provider other : seen)
            {
                Assertions.assertNotSame(other, resolved,
                        "two of the three names resolve to the same provider instance");
            }
            seen.add(resolved);
        }
        Assertions.assertEquals(3, seen.size());
    }

    /**
     * The reference BouncyCastle is the one the exclusions were measured
     * against. A bump must be read, not absorbed silently: BC's rows may have
     * moved, and {@link #theForeignExclusionsAreStillEarnt} only reports the
     * ones that started AGREEING.
     */
    @Test
    public void theBouncyCastleReferenceIsTheMeasuredVersion()
    {
        Provider bc = Security.getProvider(BC);
        Assertions.assertNotNull(bc, "BouncyCastle must be registered");
        Assertions.assertEquals(BCPROV_VERSION, bc.getVersion(), 0.00001d,
                "bcprov version moved; re-measure the BC exclusions before updating this literal");
        Assertions.assertEquals(BCPROV_INFO, bc.getInfo(),
                "bcprov info string moved; re-measure the BC exclusions");
    }

    private static PkitsCertificates.Case find(String number) throws Exception
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
}
