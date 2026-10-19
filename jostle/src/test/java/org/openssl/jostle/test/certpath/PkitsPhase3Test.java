package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * NIST PKITS sections 4.8 to 4.12: certificate policies, require explicit
 * policy, policy mappings, inhibit policy mapping and inhibit any policy.
 * <p>
 * One row per sub-variant from {@code cases_policy.txt}, generated from
 * PKITS.pdf with each variant's initial policy set and three policy flags. The
 * rows run with revocation on over the case's own CRLs, as phase 2's do; what
 * a row adds is its policy inputs.
 * <p>
 * Most of the FAIL rows turn on policy constraints the CERTIFICATES carry, at
 * default parameters: they fail only because policy processing runs on every
 * validation.
 */
public class PkitsPhase3Test
{
    private static final String NIST_POLICY_1 = "2.16.840.1.101.3.2.1.48.1";
    private static final String NIST_POLICY_2 = "2.16.840.1.101.3.2.1.48.2";

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** The rows this class owns: the whole policy table. */
    static List<PkitsCertificates.Case> selected() throws Exception
    {
        return PkitsCertificates.policyCases();
    }

    static PkitsCertificates.Case find(String number) throws Exception
    {
        for (PkitsCertificates.Case c : selected())
        {
            if (c.number.equals(number))
            {
                return c;
            }
        }
        throw new IllegalStateException("variant " + number + " is not in the policy table");
    }

    /** Phase 2's parameters, then the row's policy inputs. */
    static PKIXParameters params(PkitsCertificates.Case c) throws Exception
    {
        PKIXParameters p = PkitsPhase2Test.params(c);
        c.applyPolicy(p);
        return p;
    }

    /** The last refusal seen by {@link #validates}, for the failure report. */
    private static final ThreadLocal<String> LAST_REFUSAL = new ThreadLocal<String>();

    static boolean validates(String provider, CertPath cp, PKIXParameters p) throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", provider).validate(cp, p);
            LAST_REFUSAL.set(null);
            return true;
        }
        catch (CertPathValidatorException e)
        {
            LAST_REFUSAL.set(e.getReason() + " / " + e.getMessage());
            return false;
        }
    }

    private static boolean validates(PkitsCertificates.Case c) throws Exception
    {
        return validates(JostleProvider.PROVIDER_NAME, PkitsPhase2Test.path(c), params(c));
    }

    @Test
    public void everyPolicyVariantAgreesWithPkits() throws Exception
    {
        List<PkitsCertificates.Case> cases = selected();
        Assertions.assertEquals(86, cases.size(), "phase 3 must select 86 rows from the policy table");

        List<String> failures = new ArrayList<String>();
        int rejected = 0;
        for (PkitsCertificates.Case c : cases)
        {
            boolean got = validates(c);
            if (!got)
            {
                rejected++;
            }
            if (got != c.expectValid)
            {
                failures.add(c.number + ": PKITS expects "
                        + (c.expectValid ? "valid" : "invalid") + ", got "
                        + (got ? "valid" : "invalid")
                        + (got ? "" : " [" + LAST_REFUSAL.get() + "]"));
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "PKITS disagreements: " + failures);
        Assertions.assertEquals(42, rejected, "42 of the 86 policy variants must be rejected");
    }

    /**
     * The policy constraints the certificates carry are evaluated with every
     * parameter at its default. These rows set no policy input at all, and
     * PKITS rejects each of them.
     */
    @Test
    public void certificateBorneConstraintsAreEnforcedAtDefaultParameters() throws Exception
    {
        List<String> accepted = new ArrayList<String>();
        int checked = 0;
        for (PkitsCertificates.Case c : selected())
        {
            if (c.expectValid || !c.initialPolicies.isEmpty() || c.explicitPolicy || c.inhibitMapping
                    || c.inhibitAnyPolicy)
            {
                continue;
            }
            checked++;
            if (validates(c))
            {
                accepted.add(c.number);
            }
        }
        Assertions.assertEquals(29, checked, "29 default-parameter rows are must-reject in PKITS");
        Assertions.assertTrue(accepted.isEmpty(), "accepted against PKITS: " + accepted);
    }

    /**
     * An EMPTY initial policy set means any policy, under explicit policy too.
     * It reaches OpenSSL as the anyPolicy OID; as an empty list OpenSSL would
     * refuse this path with no explicit policy (error 43).
     */
    @Test
    public void anEmptyInitialPolicySetIsAnyPolicy() throws Exception
    {
        PkitsCertificates.Case c = find("4.8.1#1");
        PKIXParameters p = PkitsPhase2Test.params(c);
        p.setExplicitPolicyRequired(true);
        p.setInitialPolicies(Collections.<String>emptySet());
        Assertions.assertTrue(validates(JostleProvider.PROVIDER_NAME, PkitsPhase2Test.path(c), p),
                "4.8.1 with explicit policy and an empty initial set: " + LAST_REFUSAL.get());

        p.setInitialPolicies(Collections.singleton(NIST_POLICY_2));
        Assertions.assertFalse(validates(JostleProvider.PROVIDER_NAME, PkitsPhase2Test.path(c), p),
                "4.8.1 with explicit policy and only NIST-test-policy-2 must be refused");
    }

    /** Each parameter decides a verdict on its own: valid without it, refused with it. */
    @Test
    public void explicitPolicyRequiredIsHonoured() throws Exception
    {
        assertToggles("4.8.2#1", "4.8.2#2");
    }

    @Test
    public void theInitialPolicySetIsHonoured() throws Exception
    {
        PkitsCertificates.Case with1 = find("4.8.1#2");
        PkitsCertificates.Case with2 = find("4.8.1#3");
        Assertions.assertEquals(Collections.singleton(NIST_POLICY_1), with1.initialPolicies);
        Assertions.assertEquals(Collections.singleton(NIST_POLICY_2), with2.initialPolicies);
        assertToggles("4.8.1#2", "4.8.1#3");
    }

    @Test
    public void anyPolicyInhibitedIsHonoured() throws Exception
    {
        assertToggles("4.12.3#1", "4.12.3#2");
    }

    /**
     * PKITS gives 4.10.1 no variant with mapping allowed at any policy, so the
     * valid half is the same path and inputs with mapping allowed; the
     * reference provider's agreement is in CertPathAgreementTest.
     */
    @Test
    public void policyMappingInhibitedIsHonoured() throws Exception
    {
        PkitsCertificates.Case inhibited = find("4.10.1#3");
        Assertions.assertTrue(inhibited.inhibitMapping && !inhibited.expectValid);
        Assertions.assertFalse(validates(inhibited), "4.10.1#3 must be refused");
        Assertions.assertTrue(validates(JostleProvider.PROVIDER_NAME, PkitsPhase2Test.path(inhibited),
                mappingAllowed(inhibited)), "4.10.1 with mapping allowed: " + LAST_REFUSAL.get());
    }

    /** A row's parameters with policy mapping allowed. */
    static PKIXParameters mappingAllowed(PkitsCertificates.Case c) throws Exception
    {
        PKIXParameters p = params(c);
        p.setPolicyMappingInhibited(false);
        return p;
    }

    private static void assertToggles(String validRow, String refusedRow) throws Exception
    {
        PkitsCertificates.Case valid = find(validRow);
        PkitsCertificates.Case refused = find(refusedRow);
        Assertions.assertTrue(valid.expectValid, validRow + " is a PASS row");
        Assertions.assertFalse(refused.expectValid, refusedRow + " is a FAIL row");
        Assertions.assertEquals(valid.endEntity, refused.endEntity, "the two rows share one path");
        Assertions.assertTrue(validates(valid), validRow + ": " + LAST_REFUSAL.get());
        Assertions.assertFalse(validates(refused), refusedRow + " must be refused");
    }

    /**
     * The builder over every policy row and every 4.13 / 4.16 row: the selector
     * names the end entity, the store holds the row's certificates and CRLs,
     * and a path is built exactly where PKITS says the row validates.
     */
    @Test
    public void theBuilderAgreesWithPkitsOnEveryNewRow() throws Exception
    {
        List<PkitsCertificates.Case> rows = new ArrayList<PkitsCertificates.Case>(selected());
        for (PkitsCertificates.Case c : PkitsCertificates.cases())
        {
            if (c.section().equals("4.13") || c.section().equals("4.16"))
            {
                rows.add(c);
            }
        }
        Assertions.assertEquals(126, rows.size(), "86 policy variants plus 40 rows of 4.13 and 4.16");

        List<String> failures = new ArrayList<String>();
        for (PkitsCertificates.Case c : rows)
        {
            boolean built = builds(c);
            if (built != c.expectValid)
            {
                failures.add(c.number + ": PKITS expects " + (c.expectValid ? "valid" : "invalid")
                        + ", builder " + (built ? "built a path" : "refused"));
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "builder disagreements: " + failures);
    }

    private static boolean builds(PkitsCertificates.Case c) throws Exception
    {
        X509Certificate ee = PkitsCertificates.certificate(c.endEntity);
        List<Object> store = new ArrayList<Object>();
        store.add(ee);
        for (String n : c.intermediates)
        {
            store.add(PkitsCertificates.certificate(n));
        }
        for (String n : c.crls)
        {
            store.add(PkitsCertificates.crl(n));
        }
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(ee);
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(
                new TrustAnchor(PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)), sel);
        p.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(store)));
        c.applyPolicy(p);
        Set<String> initial = p.getInitialPolicies();
        Assertions.assertEquals(c.initialPolicies, initial);
        try
        {
            CertPathBuilder.getInstance("PKIX", JostleProvider.PROVIDER_NAME).build(p);
            return true;
        }
        catch (CertPathBuilderException e)
        {
            return false;
        }
    }
}
