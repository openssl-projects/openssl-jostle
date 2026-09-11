package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The revocation error table, by measurement over the PKITS cases that fail.
 * The JDK has one message for every CRL fault and a per-case {@code Reason},
 * so reasons are compared against it and messages against each other.
 *
 * <p>Two rows are excluded by NAME because they are pinned elsewhere:
 * {@code 4.14.30}, a verdict divergence, in
 * {@link PkitsRevocationDivergenceTest}; and {@code 4.4.8}, a reason
 * divergence, pinned below.
 */
public class CertPathRevocationErrorTableTest
{
    private static final Pattern CODE = Pattern.compile("failed: (\\d+) ");

    /** X509_V_* codes that mean "revocation status could not be determined". */
    private static final Set<Integer> CRL_FAULTS = new HashSet<Integer>(
            java.util.Arrays.asList(3, 8, 11, 12, 33, 35, 36, 44, 54));

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static String refusal(String provider, PkitsCertificates.Case c) throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", provider)
                    .validate(PkitsPhase2Test.path(c), PkitsPhase2Test.params(c));
            return null;
        }
        catch (CertPathValidatorException e)
        {
            return e.getReason() + "|" + e.getMessage();
        }
    }

    private static int codeOf(String refusal)
    {
        Matcher m = CODE.matcher(refusal);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    /**
     * Every CRL fault we report carries UNDETERMINED_REVOCATION_STATUS, and
     * the JDK agrees on the same case.
     */
    @Test
    public void everyCrlFaultReasonAgreesWithTheJdk() throws Exception
    {
        List<String> wrong = new ArrayList<String>();
        Set<Integer> seen = new HashSet<Integer>();
        int compared = 0;

        for (PkitsCertificates.Case c : PkitsPhase2Test.selected())
        {
            if (PkitsPhase2Test.HELD_PENDING_DELTA_RULING.contains(c.number)
                    || PkitsPhase2Test.PINNED_DIVERGENCES.contains(c.number)
                    || "4.4.8".equals(c.number))
            {
                continue;
            }
            String ours = refusal(JostleProvider.PROVIDER_NAME, c);
            if (ours == null)
            {
                continue;
            }
            int code = codeOf(ours);
            seen.add(code);
            if (!CRL_FAULTS.contains(code))
            {
                continue;   // a path fault, not a revocation one
            }
            compared++;
            if (!ours.startsWith("UNDETERMINED_REVOCATION_STATUS|"))
            {
                wrong.add(c.number + " code " + code + ": ours " + ours);
                continue;
            }
            String jdk = refusal("SUN", c);
            if (jdk == null || !jdk.startsWith("UNDETERMINED_REVOCATION_STATUS|"))
            {
                wrong.add(c.number + " code " + code + ": ours UNDETERMINED, JDK " + jdk);
            }
        }

        // Vacuity: a selection that reached no CRL fault would report clean.
        Assertions.assertTrue(compared >= 20,
                "only " + compared + " CRL-fault cases compared — the sweep is not reaching them");
        Assertions.assertTrue(seen.size() >= 5,
                "only " + seen + " distinct X509_V codes observed — the table is not exercised");
        Assertions.assertTrue(wrong.isEmpty(), "reason disagreements with the JDK: " + wrong);
    }

    /**
     * Our messages are DISTINCT per code. This is the half the JDK cannot
     * provide: it has one string for all of these, so if ours collapsed to a
     * shared "X509_V error" nothing else in the suite would notice — the
     * reason would still be right and every verdict unchanged.
     */
    @Test
    public void everyCrlFaultCodeHasItsOwnMessage() throws Exception
    {
        Map<Integer, String> byCode = new HashMap<Integer, String>();
        for (PkitsCertificates.Case c : PkitsPhase2Test.selected())
        {
            if (PkitsPhase2Test.HELD_PENDING_DELTA_RULING.contains(c.number))
            {
                continue;
            }
            String ours = refusal(JostleProvider.PROVIDER_NAME, c);
            if (ours == null)
            {
                continue;
            }
            int code = codeOf(ours);
            if (CRL_FAULTS.contains(code))
            {
                byCode.put(code, ours.substring(ours.indexOf('|') + 1));
            }
        }

        Assertions.assertTrue(byCode.size() >= 5,
                "only " + byCode.keySet() + " CRL-fault codes reached — cannot judge distinctness");
        Set<String> texts = new HashSet<String>(byCode.values());
        Assertions.assertEquals(byCode.size(), texts.size(),
                "two CRL faults share a message, so a caller cannot tell them apart: " + byCode);
        for (Map.Entry<Integer, String> e : byCode.entrySet())
        {
            Assertions.assertFalse(e.getValue().contains("X509_V error"),
                    "code " + e.getKey() + " fell through to the generic text: " + e.getValue());
        }
    }

    /**
     * Ruling 4, pinned in BOTH halves: the revocation DATE and REASON CODE
     * are out of phase 2.
     *
     * <p>The JDK attaches a {@link java.security.cert.CertificateRevokedException}
     * cause carrying the revocation date, the reason code and the authority;
     * we report {@code BasicReason.REVOKED} and no cause, because OpenSSL's
     * {@code X509_STORE_CTX} surfaces only the error code and depth and the
     * entry's own fields are not carried back across the bridge.
     *
     * <p>Both halves are asserted so this cannot drift silently in either
     * direction — if we start carrying a cause, or the JDK stops, this fails
     * rather than the difference quietly disappearing from the documentation.
     */
    @Test
    public void theRevocationDateAndReasonAreAbsentHereAndPresentInTheJdk() throws Exception
    {
        PkitsCertificates.Case c = PkitsPhase2Test.find("4.4.3");
        Assertions.assertFalse(c.expectValid, "4.4.3 is Invalid Revoked EE Test3");

        CertPathValidatorException ours = Assertions.assertThrows(
                CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME)
                        .validate(PkitsPhase2Test.path(c), PkitsPhase2Test.params(c)));
        Assertions.assertEquals(CertPathValidatorException.BasicReason.REVOKED, ours.getReason());
        Assertions.assertNull(ours.getCause(),
                "we carry no cause: the revocation date and reason code are out of phase 2");

        CertPathValidatorException jdk = Assertions.assertThrows(
                CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", "SUN")
                        .validate(PkitsPhase2Test.path(c), PkitsPhase2Test.params(c)));
        Assertions.assertEquals(CertPathValidatorException.BasicReason.REVOKED, jdk.getReason(),
                "the REASON is the half that agrees");
        Assertions.assertTrue(
                jdk.getCause() instanceof java.security.cert.CertificateRevokedException,
                "the JDK is expected to carry a CertificateRevokedException cause; if this "
                        + "changed, the documented difference has moved: " + jdk.getCause());
    }

    /**
     * 4.4.8, pinned in BOTH halves. All three code-36 cases — 4.4.8, 4.4.9,
     * 4.4.10 — are an unprocessable critical CRL extension, and we answer
     * UNDETERMINED_REVOCATION_STATUS for all three. The JDK answers
     * UNDETERMINED for 4.4.9 and 4.4.10 but UNSPECIFIED for 4.4.8, where its
     * own message names a "revoked CRL entry" rather than the CRL.
     *
     * <p>So no single mapping for code 36 matches the JDK on all three, and
     * ours is the self-consistent one. Both halves are asserted, so a JDK
     * release that makes 4.4.8 consistent with its siblings fails here rather
     * than silently invalidating this rationale.
     */
    @Test
    public void theUnhandledCriticalCrlExtensionReasonIsPinnedAgainstTheJdk() throws Exception
    {
        for (String n : new String[]{"4.4.8", "4.4.9", "4.4.10"})
        {
            PkitsCertificates.Case c = PkitsPhase2Test.find(n);
            String ours = refusal(JostleProvider.PROVIDER_NAME, c);
            Assertions.assertNotNull(ours, n + " must fail");
            Assertions.assertEquals(36, codeOf(ours), n + " must be code 36");
            Assertions.assertTrue(ours.startsWith("UNDETERMINED_REVOCATION_STATUS|"),
                    n + ": we answer the same reason for all three, got " + ours);
        }

        String jdk48 = refusal("SUN", PkitsPhase2Test.find("4.4.8"));
        Assertions.assertNotNull(jdk48, "the JDK must fail 4.4.8 too");
        Assertions.assertTrue(jdk48.startsWith("UNSPECIFIED|"),
                "the JDK is expected to answer UNSPECIFIED for 4.4.8; if this changed, the "
                        + "divergence has moved and the rationale needs re-reading: " + jdk48);
        for (String n : new String[]{"4.4.9", "4.4.10"})
        {
            String jdk = refusal("SUN", PkitsPhase2Test.find(n));
            Assertions.assertTrue(jdk != null && jdk.startsWith("UNDETERMINED_REVOCATION_STATUS|"),
                    n + ": the JDK is expected to answer UNDETERMINED here, got " + jdk);
        }
    }
}
