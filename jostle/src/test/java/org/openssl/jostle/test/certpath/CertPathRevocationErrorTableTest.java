package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;

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
 * The revocation error table, by measurement over the PKITS cases that fail:
 * every CRL fault is UNDETERMINED_REVOCATION_STATUS and each code has its own
 * text. The same cases against the JDK are in {@link CertPathAgreementTest}.
 *
 * <p>{@code 4.14.30}, a verdict divergence, is pinned in
 * {@link PkitsRevocationDivergenceAgreementTest}.
 */
public class CertPathRevocationErrorTableTest
{
    private static final Pattern CODE = Pattern.compile("failed: (\\d+) ");

    /** X509_V_* codes that mean "revocation status could not be determined". */
    static final Set<Integer> CRL_FAULTS = new HashSet<Integer>(
            java.util.Arrays.asList(3, 8, 11, 12, 33, 35, 36, 44, 54));

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    static String refusal(String provider, PkitsCertificates.Case c) throws Exception
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

    static int codeOf(String refusal)
    {
        Matcher m = CODE.matcher(refusal);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    /** Every CRL fault we report carries UNDETERMINED_REVOCATION_STATUS. */
    @Test
    public void everyCrlFaultIsUndeterminedRevocationStatus() throws Exception
    {
        List<String> wrong = new ArrayList<String>();
        Set<Integer> seen = new HashSet<Integer>();
        int compared = 0;

        for (PkitsCertificates.Case c : PkitsPhase2Test.selected())
        {
            if (PkitsPhase2Test.PINNED_DIVERGENCES.contains(c.number)
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
            }
        }

        // Vacuity: a selection that reached no CRL fault would report clean.
        Assertions.assertTrue(compared >= 20,
                "only " + compared + " CRL-fault cases compared — the sweep is not reaching them");
        Assertions.assertTrue(seen.size() >= 5,
                "only " + seen + " distinct X509_V codes observed — the table is not exercised");
        Assertions.assertTrue(wrong.isEmpty(), "CRL faults with another reason: " + wrong);
    }

    /**
     * Our messages are DISTINCT per code and are OpenSSL's own text for the
     * code. The JDK has one string for all of these, so if ours collapsed to a
     * shared text nothing else in the suite would notice.
     */
    @Test
    public void everyCrlFaultCodeHasItsOwnMessage() throws Exception
    {
        Map<Integer, String> byCode = new HashMap<Integer, String>();
        for (PkitsCertificates.Case c : PkitsPhase2Test.selected())
        {
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
            Assertions.assertEquals("certification path validation failed: " + e.getKey() + " "
                    + NISelector.CertPathNI.ni_errorText(e.getKey()),
                    e.getValue(), "code " + e.getKey() + " must carry the linked library's text");
        }
    }

    /**
     * We report {@code BasicReason.REVOKED} and no cause: OpenSSL's
     * {@code X509_STORE_CTX} surfaces only the error code and depth, and the
     * entry's own fields are not carried back across the bridge. The JDK's
     * half (a CertificateRevokedException cause) is in
     * {@link CertPathAgreementTest}.
     */
    @Test
    public void aRevokedCertificateCarriesNoCause() throws Exception
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
    }

    /**
     * All three code-36 cases (4.4.8, 4.4.9, 4.4.10) are an unprocessable
     * critical CRL extension, and we answer UNDETERMINED_REVOCATION_STATUS for
     * all three. The JDK's differing answer for 4.4.8 is pinned in
     * {@link CertPathAgreementTest}.
     */
    @Test
    public void theUnhandledCriticalCrlExtensionCasesShareOneReason() throws Exception
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
    }
}
