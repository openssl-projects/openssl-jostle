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
}
