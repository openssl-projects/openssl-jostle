package org.openssl.jostle.test.certpath;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXParameters;

/**
 * The two PKITS cases this provider does NOT pass, each pinned in both halves —
 * our answer and BouncyCastle's — so neither can drift unnoticed and a bcprov
 * bump that moves the reference fails here rather than silently invalidating
 * the rationale.
 */
public class PkitsDivergenceTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
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

    private static boolean validatesWith(String provider, PkitsCertificates.Case c) throws Exception
    {
        CertPath cp = PkitsPhase1Test.path(c);
        PKIXParameters p = PkitsPhase1Test.params();
        try
        {
            CertPathValidator.getInstance("PKIX", provider).validate(cp, p);
            return true;
        }
        catch (CertPathValidatorException e)
        {
            return false;
        }
    }

    /**
     * 4.1.5 needs DSA PARAMETER INHERITANCE, which OpenSSL does not implement:
     * {@code X509_PUBKEY_get0} fails outright on the paramless dsaEncryption
     * SPKI (crypto/x509/x_pubkey.c), so the inherited-parameters CA has no
     * usable public key and is never a candidate issuer. The result is error 20
     * "unable to get local issuer certificate" at depth 0 — NOT a signature
     * failure, which is what makes the cause legible. A mainline limitation,
     * not a FIPS one: identical on mainline and both modules.
     */
    @Test
    public void dsaParameterInheritanceIsUnsupportedHereAndSupportedByBouncyCastle() throws Exception
    {
        PkitsCertificates.Case c = find("4.1.5");
        Assertions.assertTrue(c.expectValid, "PKITS expects 4.1.5 to validate");

        CertPathValidatorException e = Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME)
                        .validate(PkitsPhase1Test.path(c), PkitsPhase1Test.params()));
        // Anchored to the message prefix and the typed shape: a bare
        // contains("20") would also match an index, a depth, or 120.
        Assertions.assertTrue(e.getMessage().matches("(?s).*failed: 20 .*"),
                "expected X509 error 20, got: " + e.getMessage());
        Assertions.assertEquals(0, e.getIndex(), "error 20 is reported at depth 0, the EE");
        Assertions.assertEquals(CertPathValidatorException.BasicReason.UNSPECIFIED, e.getReason());

        Assertions.assertTrue(validatesWith(BouncyCastleProvider.PROVIDER_NAME, c),
                "BouncyCastle is expected to support DSA parameter inheritance; if this fails, "
                        + "the divergence has moved and the rationale needs re-reading");
    }

    /**
     * 4.6.4 has a CA whose basicConstraints is not marked critical. RFC 5280
     * 4.2.1.9 says a conforming CA MUST mark it critical, and
     * X509_V_FLAG_X509_STRICT enforces that on the relying side — so we refuse
     * with error 89 where BouncyCastle is lenient and accepts. We are the
     * conforming side; strict stays on (Megan, 2026-09-09).
     */
    @Test
    public void nonCriticalBasicConstraintsIsRefusedUnderStrictAndAcceptedByBouncyCastle() throws Exception
    {
        PkitsCertificates.Case c = find("4.6.4");
        Assertions.assertTrue(c.expectValid, "PKITS expects 4.6.4 to validate");

        CertPathValidatorException e = Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME)
                        .validate(PkitsPhase1Test.path(c), PkitsPhase1Test.params()));
        Assertions.assertTrue(e.getMessage().matches("(?s).*failed: 89 .*"),
                "expected X509 error 89, got: " + e.getMessage());
        Assertions.assertEquals(1, e.getIndex(), "depth 1 is the CA whose basicConstraints is not critical");
        Assertions.assertEquals(CertPathValidatorException.BasicReason.UNSPECIFIED, e.getReason());

        Assertions.assertTrue(validatesWith(BouncyCastleProvider.PROVIDER_NAME, c),
                "BouncyCastle is expected to accept a non-critical basicConstraints");
    }

    /**
     * A control: the divergences are specific, not a provider that refuses
     * everything. The neighbouring cases in both sections must still pass.
     */
    @Test
    public void theNeighbouringCasesStillValidate() throws Exception
    {
        for (String n : new String[]{"4.1.1", "4.1.4", "4.6.3"})
        {
            PkitsCertificates.Case c = find(n);
            if (!c.expectValid)
            {
                continue;
            }
            Assertions.assertTrue(validatesWith(JostleProvider.PROVIDER_NAME, c),
                    n + " must still validate: the pins above are specific divergences, "
                            + "not a validator that refuses everything");
        }
    }
}
