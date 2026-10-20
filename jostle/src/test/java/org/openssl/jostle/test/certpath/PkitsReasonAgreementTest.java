package org.openssl.jostle.test.certpath;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXReason;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The reason and index a refusal carries, on every PKITS row, against the
 * JDK's SUN validator, whose reasons this provider follows. BouncyCastle sets
 * no reason; its half is pinned where a divergence is.
 *
 * <p>Witnessed codes and their rows are measured; a mapped code no PKITS row
 * produces is UNWITNESSED and mapped by family: 2, 18, 19, 21, 27 (no trust
 * anchor), 29, 30, 31 (name chaining), 32, 39, 92 (key usage), 37 (not a CA)
 * and 49, 51, 52, 53 (name constraints). 89 is reached by 4.6.4 alone, which
 * SUN accepts, so its NOT_CA_CERT is unwitnessed too; it is pinned in
 * PkitsDivergenceAgreementTest.
 */
public class PkitsReasonAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String SUN = "SUN";
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final Pattern CODE = Pattern.compile("failed: (\\d+) ");

    /** The rows that produce each code this class pins, measured on both bridges. */
    private static final Map<Integer, Set<String>> WITNESSED = new TreeMap<Integer, Set<String>>();

    static
    {
        witness(25, "4.6.5 4.6.6 4.6.9 4.6.10 4.6.11 4.6.12 4.6.16");
        witness(34, "4.16.2");
        witness(42, "4.10.7 4.10.8");
        witness(43, "4.8.1#3 4.8.2#2 4.8.3#2 4.8.3#3 4.8.4 4.8.5 4.8.6#3 4.8.7 4.8.8 4.8.9 4.8.12 4.8.14#2"
                + " 4.9.3 4.9.5 4.9.7 4.9.8 4.10.1#2 4.10.1#3 4.10.2#1 4.10.2#2 4.10.3#1 4.10.4 4.10.5#2"
                + " 4.10.6#2 4.10.10 4.11.1 4.11.3 4.11.5 4.11.6 4.11.8 4.11.9 4.11.10 4.11.11 4.12.1"
                + " 4.12.3#2 4.12.4 4.12.5 4.12.6 4.12.8 4.12.10 4.8.6#bc3 4.8.14#bc2 4.8.15#bc2"
                + " 4.10.1#bc2 4.10.3#bc1 4.10.5#bc2 4.10.6#bc2");
        witness(47, "4.13.2 4.13.3 4.13.12 4.13.13 4.13.20 4.13.22 4.13.24 4.13.28 4.13.29 4.13.31"
                + " 4.13.35 4.13.38");
        witness(48, "4.13.7 4.13.8 4.13.9 4.13.10 4.13.15 4.13.16 4.13.17 4.13.26 4.13.33 4.13.37");
        witness(79, "4.5.8 4.6.1 4.6.2 4.6.3 4.7.1 4.7.2");
    }

    /** Rows whose reason differs from SUN's, each pinned in its own cell. */
    private static final Set<String> REASON_DIVERGENCES = new LinkedHashSet<String>(Arrays.asList(
            "4.3.1", "4.3.2",   // below
            "4.4.8"));          // CertPathAgreementTest: SUN is not self-consistent on code 36

    private static void witness(int code, String rows)
    {
        WITNESSED.put(Integer.valueOf(code), new LinkedHashSet<String>(Arrays.asList(rows.split(" "))));
    }

    /** One provider's answer on one row: null when it validates. */
    private static final class Refusal
    {
        final int code;
        final int index;
        final CertPathValidatorException.Reason reason;

        Refusal(int code, int index, CertPathValidatorException.Reason reason)
        {
            this.code = code;
            this.index = index;
            this.reason = reason;
        }
    }

    private static Map<String, Map<String, Refusal>> sweep;

    @BeforeAll
    static void before() throws Exception
    {
        PkitsThreeWayAgreementTest.before();
    }

    private static Refusal refusal(String provider, PkitsCertificates.Case c) throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", provider)
                    .validate(PkitsPhase2Test.path(c), PkitsThreeWayAgreementTest.params(c));
            return null;
        }
        catch (CertPathValidatorException e)
        {
            int code = -1;
            if (JSL.equals(provider))
            {
                Matcher m = CODE.matcher(e.getMessage());
                Assertions.assertTrue(m.find(), "no X509 code in: " + e.getMessage());
                code = Integer.parseInt(m.group(1));
            }
            return new Refusal(code, e.getIndex(), e.getReason());
        }
    }

    /** Every row on all three providers, measured once. */
    private static synchronized Map<String, Map<String, Refusal>> sweep() throws Exception
    {
        if (sweep == null)
        {
            Map<String, Map<String, Refusal>> all = new LinkedHashMap<String, Map<String, Refusal>>();
            for (PkitsCertificates.Case c : PkitsThreeWayAgreementTest.allCases())
            {
                Map<String, Refusal> row = new LinkedHashMap<String, Refusal>();
                row.put(JSL, refusal(JSL, c));
                row.put(SUN, refusal(SUN, c));
                row.put(BC, refusal(BC, c));
                all.put(c.number, row);
            }
            sweep = all;
        }
        return sweep;
    }

    /** The rows each pinned code comes from, as a set: OpenSSL raises it on exactly these. */
    @Test
    public void eachPinnedCodeComesFromExactlyItsMeasuredRows() throws Exception
    {
        Map<Integer, Set<String>> seen = new TreeMap<Integer, Set<String>>();
        for (Map.Entry<String, Map<String, Refusal>> e : sweep().entrySet())
        {
            Refusal ours = e.getValue().get(JSL);
            if (ours != null && WITNESSED.containsKey(Integer.valueOf(ours.code)))
            {
                Integer k = Integer.valueOf(ours.code);
                if (!seen.containsKey(k))
                {
                    seen.put(k, new LinkedHashSet<String>());
                }
                seen.get(k).add(e.getKey());
            }
        }
        Assertions.assertEquals(WITNESSED, seen);
    }

    /**
     * Where this provider and SUN both refuse, the reasons agree, except on
     * the rows pinned below. Reported as one list.
     */
    @Test
    public void everyRefusalCarriesSunsReason() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        int compared = 0;
        for (Map.Entry<String, Map<String, Refusal>> e : sweep().entrySet())
        {
            Refusal ours = e.getValue().get(JSL);
            Refusal sun = e.getValue().get(SUN);
            if (ours == null || sun == null || REASON_DIVERGENCES.contains(e.getKey()))
            {
                continue;
            }
            compared++;
            if (ours.reason != sun.reason)
            {
                failures.add(e.getKey() + " code " + ours.code + ": ours " + ours.reason + ", SUN " + sun.reason);
            }
        }
        Assertions.assertEquals(137, compared, "rows where both refuse, less the pinned three");
        Assertions.assertTrue(failures.isEmpty(), "reason disagreements: " + failures);
    }

    /** Code 79 is one OpenSSL code for two JDK reasons; three rows of each. */
    @Test
    public void invalidCaFollowsTheCertificateOpenSslNames() throws Exception
    {
        for (String row : new String[]{"4.5.8", "4.7.1", "4.7.2"})
        {
            assertReason(row, 79, PKIXReason.INVALID_KEY_USAGE);
        }
        for (String row : new String[]{"4.6.1", "4.6.2", "4.6.3"})
        {
            assertReason(row, 79, PKIXReason.NOT_CA_CERT);
        }
    }

    private static void assertReason(String row, int code, CertPathValidatorException.Reason want)
            throws Exception
    {
        Refusal ours = sweep().get(row).get(JSL);
        Refusal sun = sweep().get(row).get(SUN);
        Assertions.assertNotNull(ours, row + " must be refused");
        Assertions.assertEquals(code, ours.code, row);
        Assertions.assertEquals(want, ours.reason, row);
        Assertions.assertNotNull(sun, row + " must be refused by SUN");
        Assertions.assertEquals(want, sun.reason, row + " on SUN");
        Assertions.assertEquals(sun.index, ours.index, row + " index");
    }

    /**
     * Code 43 names no certificate, so the index is -1: never SUN's 0, 1 or
     * 2, which is the depth at which its policy tree went null. BouncyCastle
     * sets no reason here.
     */
    @Test
    public void noExplicitPolicyReportsNoIndex() throws Exception
    {
        Set<Integer> sunIndexes = new TreeSet<Integer>();
        for (String row : WITNESSED.get(Integer.valueOf(43)))
        {
            Refusal ours = sweep().get(row).get(JSL);
            Refusal sun = sweep().get(row).get(SUN);
            Refusal bc = sweep().get(row).get(BC);
            Assertions.assertEquals(-1, ours.index, row);
            Assertions.assertEquals(PKIXReason.INVALID_POLICY, ours.reason, row);
            Assertions.assertEquals(PKIXReason.INVALID_POLICY, sun.reason, row + " on SUN");
            Assertions.assertTrue(sun.index >= 0, row + " on SUN names a certificate");
            sunIndexes.add(Integer.valueOf(sun.index));
            Assertions.assertNotNull(bc, row + " must be refused by BC");
            Assertions.assertEquals(CertPathValidatorException.BasicReason.UNSPECIFIED, bc.reason, row + " on BC");
        }
        Assertions.assertEquals(new TreeSet<Integer>(Arrays.asList(0, 1, 2)), sunIndexes,
                "SUN's indexes on the code-43 rows");
    }

    /**
     * Code 25: OpenSSL reports the certificate past the limit, SUN the CA
     * whose pathLenConstraint it breaks. Same reason, different index.
     */
    @Test
    public void pathLengthIndexDivergesFromSun() throws Exception
    {
        Map<String, Integer> ours = new LinkedHashMap<String, Integer>();
        for (String row : WITNESSED.get(Integer.valueOf(25)))
        {
            Refusal r = sweep().get(row).get(JSL);
            Refusal sun = sweep().get(row).get(SUN);
            Assertions.assertEquals(PKIXReason.PATH_TOO_LONG, r.reason, row);
            Assertions.assertEquals(PKIXReason.PATH_TOO_LONG, sun.reason, row + " on SUN");
            Assertions.assertEquals(1, sun.index, row + " on SUN");
            ours.put(row, Integer.valueOf(r.index));
        }
        Map<String, Integer> want = new LinkedHashMap<String, Integer>();
        for (String row : new String[]{"4.6.5", "4.6.6", "4.6.9", "4.6.10"})
        {
            want.put(row, Integer.valueOf(2));
        }
        for (String row : new String[]{"4.6.11", "4.6.12", "4.6.16"})
        {
            want.put(row, Integer.valueOf(3));
        }
        Assertions.assertEquals(want, ours);
    }

    /**
     * 4.3.1 and 4.3.2: OpenSSL finds no issuer (code 20, NO_TRUST_ANCHOR)
     * where SUN reports NAME_CHAINING. BouncyCastle refuses 4.3.1 with no
     * reason and accepts 4.3.2 (sanctioned in PkitsThreeWayAgreementTest).
     */
    @Test
    public void nameChainingRowsReportNoTrustAnchor() throws Exception
    {
        for (String row : new String[]{"4.3.1", "4.3.2"})
        {
            Refusal ours = sweep().get(row).get(JSL);
            Refusal sun = sweep().get(row).get(SUN);
            Assertions.assertEquals(20, ours.code, row);
            Assertions.assertEquals(PKIXReason.NO_TRUST_ANCHOR, ours.reason, row);
            Assertions.assertEquals(PKIXReason.NAME_CHAINING, sun.reason, row + " on SUN");
        }
        Refusal bc431 = sweep().get("4.3.1").get(BC);
        Assertions.assertNotNull(bc431, "4.3.1 must be refused by BC");
        Assertions.assertEquals(CertPathValidatorException.BasicReason.UNSPECIFIED, bc431.reason);
        Assertions.assertNull(sweep().get("4.3.2").get(BC), "BC accepts 4.3.2");
    }
}
