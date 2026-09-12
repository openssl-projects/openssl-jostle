package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;

/**
 * The revocation case this provider does NOT pass, pinned in both halves so
 * neither can drift unnoticed.
 */
public class PkitsRevocationDivergenceTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** The refusal a provider gives, or null if it validated. */
    private static CertPathValidatorException refusalFrom(String provider,
                                                          PkitsCertificates.Case c) throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", provider)
                    .validate(PkitsPhase2Test.path(c), PkitsPhase2Test.params(c));
            return null;
        }
        catch (CertPathValidatorException e)
        {
            return e;
        }
    }

    private static boolean validatesWith(String provider, PkitsCertificates.Case c) throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", provider)
                    .validate(PkitsPhase2Test.path(c), PkitsPhase2Test.params(c));
            return true;
        }
        catch (CertPathValidatorException e)
        {
            return false;
        }
    }

    /**
     * 4.14.30 Valid cRLIssuer Test30 needs a RECURSIVE indirect-CRL
     * resolution that OpenSSL refuses, and the refusal is structural rather
     * than a flag we could set.
     *
     * <p><b>Mechanism, measured with a verify callback</b> (not inferred):
     * {@code check_crl_path} (x509_vfy.c, 3.1.2 :1319, 3.5.8 :1476) verifies
     * the CRL ISSUER's own certificate in a child context and copies the
     * parameters across, flags included. So {@code CRL_CHECK_ALL} applies
     * inside that child verification, which then needs a CRL for the
     * cRLIssuer certificate; that CRL is the SAME indirect CRL, which would
     * need {@code check_crl_path} again, and recursion is refused by
     * {@code if (ctx->parent != NULL)} (3.1.2 :1325, 3.5.8 :1482). This is
     * the only case in the corpus with that shape: both the end entity AND
     * the certificate issued to the CRL issuer are covered by the indirect
     * CRL the CRL issuer issued.
     *
     * <p><b>Do not "fix" this by weakening the flags.</b> The trade was
     * measured over all 109 revocation cases: with {@code CRL_CHECK_ALL} we
     * agree on 108 and diverge here; without it we agree on 107 and diverge
     * on 4.4.2 and 4.4.21 — and 4.4.2 is <i>Invalid Revoked CA Test2</i>, a
     * REVOKED INTERMEDIATE that would then be accepted. Worse by count and
     * unsafe by kind, and wrong for JCA, where {@code revocationEnabled}
     * means the whole path.
     *
     * <p>Identical on 3.1.2 and 3.5.8. If a future OpenSSL relaxes the
     * recursion guard this pin fails loudly, which is the point.
     *
     * <p>The reference is the JDK, measured: BouncyCastle fails 4.14.30 too,
     * on unrelated grounds ("No CRLs found for issuer … Searched 0
     * PKIXCRLStore(s)"), so it cannot be the half pinned.
     */
    @Test
    public void recursiveIndirectCrlIsRefusedHereAndAcceptedByTheJdk() throws Exception
    {
        PkitsCertificates.Case c = PkitsPhase2Test.find("4.14.30");
        Assertions.assertTrue(c.expectValid, "PKITS expects 4.14.30 to validate");

        CertPathValidatorException e = Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME)
                        .validate(PkitsPhase2Test.path(c), PkitsPhase2Test.params(c)));
        // Anchored to the message shape: a bare contains("54") would also
        // match an index, a depth, or 154.
        Assertions.assertTrue(e.getMessage().matches("(?s).*failed: 54 .*"),
                "expected X509 error 54 CRL_PATH_VALIDATION_ERROR, got: " + e.getMessage());
        Assertions.assertEquals(
                CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS,
                e.getReason());

        Assertions.assertTrue(validatesWith("SUN", c),
                "the JDK is expected to accept the recursive indirect CRL; if this fails, "
                        + "the divergence has moved and the rationale needs re-reading");
    }

    /**
     * We are not merely different from the JDK here — on the neighbouring
     * indirect-CRL cases we agree with it where BOUNCYCASTLE does not.
     * Measured: BC refuses 4.14.28 and 4.14.29, which PKITS and the JDK pass,
     * and BC ACCEPTS 4.14.31, which PKITS and the JDK report revoked.
     *
     * <p>BC's answers are prose, not pinned: they are that provider's
     * defects, and pinning them turns a bcprov fix into a red suite here.
     */
    @Test
    public void theIndirectCrlNeighboursAgreeWithTheJdk() throws Exception
    {
        for (String n : new String[]{"4.14.28", "4.14.29", "4.14.31"})
        {
            PkitsCertificates.Case c = PkitsPhase2Test.find(n);
            Assertions.assertEquals(c.expectValid, validatesWith("SUN", c),
                    n + ": the JDK is the reference and must agree with PKITS");
            Assertions.assertEquals(c.expectValid,
                    validatesWith(JostleProvider.PROVIDER_NAME, c),
                    n + ": we must agree with PKITS and the JDK");
        }
    }

    /**
     * A control: the divergence is ONE shape, not indirect CRLs in general.
     * Its neighbours use indirect CRLs too and must behave.
     */
    @Test
    public void theNeighbouringIndirectCrlCasesStillBehave() throws Exception
    {
        for (String n : new String[]{"4.14.28", "4.14.29", "4.14.33"})
        {
            PkitsCertificates.Case c = PkitsPhase2Test.find(n);
            Assertions.assertEquals(c.expectValid,
                    validatesWith(JostleProvider.PROVIDER_NAME, c),
                    n + " must still agree with PKITS: the pin above is one shape, "
                            + "not a validator that refuses indirect CRLs");
        }
        for (String n : new String[]{"4.14.31", "4.14.32"})
        {
            PkitsCertificates.Case c = PkitsPhase2Test.find(n);
            Assertions.assertFalse(validatesWith(JostleProvider.PROVIDER_NAME, c),
                    n + " reports a revoked certificate through an indirect CRL");
        }
    }

    /**
     * 4.15.4: we honour delta CRLs and refuse, the JDK does not and accepts.
     *
     * <p>Measured from the corpus: the EE is serial 03, the base CRL lists only
     * 02, 04 and 05, and the DELTA revokes 03 keyCompromise. So the certificate
     * is revoked ONLY in the delta and the base does not list it at all.
     * Without {@code X509_V_FLAG_USE_DELTAS} the delta is carried in the store
     * and never paired with its base — {@code get_delta_sk} returns early
     * (x509_vfy.c, 3.1.2 :1177, 3.5.8 :1326) — so nothing lists the certificate
     * and the path is accepted. PKITS calls it invalid; we agree, the JDK
     * does not. Note this is NOT 4.15.5's shape: no hold is involved here.
     */
    @Test
    public void deltaRevocationIsSeenHereAndMissedByTheJdk() throws Exception
    {
        PkitsCertificates.Case c = PkitsPhase2Test.find("4.15.4");
        Assertions.assertFalse(c.expectValid, "PKITS expects 4.15.4 to FAIL");

        CertPathValidatorException e = Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME)
                        .validate(PkitsPhase2Test.path(c), PkitsPhase2Test.params(c)));
        Assertions.assertTrue(e.getMessage().matches("(?s).*failed: 23 .*"),
                "expected X509 error 23 CERT_REVOKED, got: " + e.getMessage());
        Assertions.assertEquals(CertPathValidatorException.BasicReason.REVOKED, e.getReason());
        // Measured: the path is [EE, deltaCRL CA1] and the delta revokes the
        // EE, so the fault is reported at index 0.
        Assertions.assertEquals(0, e.getIndex(), "the revoked certificate is the end entity");

        // The JDK half. A wrong ACCEPTANCE carries no message, so the pin is
        // that validate returns at all.
        Assertions.assertTrue(validatesWith("SUN", c),
                "the JDK is expected to miss the delta and accept 4.15.4; if this fails, "
                        + "the divergence has moved and the rationale needs re-reading");
    }

    /**
     * 4.15.5: the mirror. The base CRL holds the certificate and the delta
     * REMOVES it from hold, so the path is valid. We see the delta and accept;
     * the JDK sees only the hold and refuses.
     *
     * <p>The JDK's message carries a zone-formatted revocation date, so it is
     * pinned by class, reason and PREFIX — a whole-string pin fails in another
     * timezone.
     */
    @Test
    public void removalFromHoldIsSeenHereAndMissedByTheJdk() throws Exception
    {
        PkitsCertificates.Case c = PkitsPhase2Test.find("4.15.5");
        Assertions.assertTrue(c.expectValid, "PKITS expects 4.15.5 to PASS");

        Assertions.assertTrue(validatesWith(JostleProvider.PROVIDER_NAME, c),
                "we honour the delta that lifts the hold, so 4.15.5 must validate");

        CertPathValidatorException jdk = refusalFrom("SUN", c);
        Assertions.assertNotNull(jdk, "the JDK is expected to refuse 4.15.5");
        Assertions.assertEquals(CertPathValidatorException.BasicReason.REVOKED, jdk.getReason());
        Assertions.assertTrue(
                jdk.getMessage().startsWith("Certificate has been revoked, reason: CERTIFICATE_HOLD"),
                "the JDK's refusal must still name the hold, got: " + jdk.getMessage());
    }

    /**
     * A control: honouring deltas moved exactly the two rows above. The other
     * eight cases whose store carries a delta CRL must still agree with PKITS.
     */
    @Test
    public void theOtherDeltaCasesAreUnmovedByHonouringDeltas() throws Exception
    {
        String[] others = {"4.15.1", "4.15.2", "4.15.3", "4.15.6",
                           "4.15.7", "4.15.8", "4.15.9", "4.15.10"};
        for (String n : others)
        {
            PkitsCertificates.Case c = PkitsPhase2Test.find(n);
            Assertions.assertEquals(c.expectValid,
                    validatesWith(JostleProvider.PROVIDER_NAME, c),
                    n + " must still agree with PKITS: USE_DELTAS decides 4.15.4 and "
                            + "4.15.5 and must leave the rest of the section alone");
        }
    }
}
