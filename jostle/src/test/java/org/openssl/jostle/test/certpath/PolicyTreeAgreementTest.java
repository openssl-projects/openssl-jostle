package org.openssl.jostle.test.certpath;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.PolicyNode;
import java.security.cert.PolicyQualifierInfo;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * The valid policy tree, node by node, against SUN and BouncyCastle on every
 * PASS row of the policy table. A node is compared on its depth, valid
 * policy, criticality, expected set, qualifier DER and children; children are
 * compared as a set, because SUN keeps them in a HashSet and the JCA sets no
 * order.
 */
public class PolicyTreeAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String SUN = "SUN";
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    @BeforeAll
    static void before() throws Exception
    {
        PkitsThreeWayAgreementTest.before();
    }

    private static PolicyNode tree(String provider, PkitsCertificates.Case c) throws Exception
    {
        PKIXCertPathValidatorResult r = (PKIXCertPathValidatorResult) CertPathValidator
                .getInstance("PKIX", provider)
                .validate(PkitsPhase2Test.path(c), PkitsThreeWayAgreementTest.params(c));
        return r.getPolicyTree();
    }

    /** A node and its subtree as one string; null for no tree. */
    static String canonical(PolicyNode n)
    {
        if (n == null)
        {
            return "null";
        }
        Set<String> quals = new TreeSet<String>();
        for (PolicyQualifierInfo q : n.getPolicyQualifiers())
        {
            quals.add(Hex.toHexString(q.getEncoded()));
        }
        Set<String> children = new TreeSet<String>();
        for (Iterator<? extends PolicyNode> it = n.getChildren(); it.hasNext(); )
        {
            children.add(canonical(it.next()));
        }
        return "(" + n.getDepth() + " " + n.getValidPolicy() + " crit=" + n.isCritical()
                + " exp=" + new TreeSet<String>(n.getExpectedPolicies()) + " q=" + quals
                + " " + children + ")";
    }

    private static List<PkitsCertificates.Case> passRows() throws Exception
    {
        List<PkitsCertificates.Case> out = new ArrayList<PkitsCertificates.Case>();
        for (PkitsCertificates.Case c : PkitsCertificates.policyCases())
        {
            if (c.expectValid)
            {
                out.add(c);
            }
        }
        return out;
    }

    /** Every PASS row: our tree equals SUN's and BouncyCastle's. Reported as one list. */
    @Test
    public void everyPassRowsTreeMatchesSunAndBouncyCastle() throws Exception
    {
        Set<String> bcDivergent = new TreeSet<String>(BC_KEEPS_THE_ANY_POLICY_LEAF);
        List<String> failures = new ArrayList<String>();
        int trees = 0;
        int qualified = 0;
        int mapped = 0;
        List<PkitsCertificates.Case> rows = passRows();
        for (PkitsCertificates.Case c : rows)
        {
            PolicyNode ourTree = tree(JSL, c);
            String ours = canonical(ourTree);
            for (String p : new String[]{SUN, BC})
            {
                if (BC.equals(p) && bcDivergent.remove(c.number))
                {
                    continue;
                }
                String theirs = canonical(tree(p, c));
                if (!ours.equals(theirs))
                {
                    failures.add(c.number + " on " + p + ": ours " + ours + " theirs " + theirs);
                }
            }
            if (ourTree != null)
            {
                trees++;
                qualified += count(ourTree, true);
                mapped += count(ourTree, false);
            }
        }
        Assertions.assertEquals(63, rows.size(), "PASS rows of the policy table");
        Assertions.assertTrue(bcDivergent.isEmpty(), "pinned rows not in the table: " + bcDivergent);
        Assertions.assertTrue(failures.isEmpty(), "tree disagreements (" + failures.size() + "): " + failures);
        Assertions.assertTrue(trees > 40, "only " + trees + " rows returned a tree");
        Assertions.assertTrue(qualified > 0, "no row carried a qualifier");
        Assertions.assertTrue(mapped > 0, "no row carried a mapped expected set");
    }

    /** Nodes carrying qualifiers, or nodes whose expected set is not their own policy. */
    private static int count(PolicyNode n, boolean qualifiers)
    {
        int c = qualifiers
                ? (n.getPolicyQualifiers().isEmpty() ? 0 : 1)
                : (n.getExpectedPolicies().contains(n.getValidPolicy()) ? 0 : 1);
        for (Iterator<? extends PolicyNode> it = n.getChildren(); it.hasNext(); )
        {
            c += count(it.next(), qualifiers);
        }
        return c;
    }

    /** Rows where BouncyCastle's tree diverges, pinned below. */
    private static final Set<String> BC_KEEPS_THE_ANY_POLICY_LEAF =
            new TreeSet<String>(Arrays.asList("4.8.11#2", "4.8.11#bc2"));

    /**
     * 4.8.11 with initial set {NIST-test-policy-1} ends in an anyPolicy leaf.
     * RFC 5280 6.1.5 (g)(iii)(3) replaces that leaf with a node for the
     * initial policy, as we and SUN do; BouncyCastle keeps the anyPolicy leaf.
     */
    @Test
    public void bouncyCastleKeepsTheAnyPolicyLeafOnPkits4811() throws Exception
    {
        for (String row : BC_KEEPS_THE_ANY_POLICY_LEAF)
        {
            PkitsCertificates.Case c = PkitsPhase3Test.find(row);
            PolicyNode ours = leaf(tree(JSL, c));
            PolicyNode bc = leaf(tree(BC, c));
            Assertions.assertEquals(canonical(tree(SUN, c)), canonical(tree(JSL, c)), row + " ours against SUN");
            Assertions.assertEquals(c.initialPolicies, Collections.singleton(ours.getValidPolicy()), row);
            Assertions.assertEquals(2, ours.getDepth(), row);
            Assertions.assertEquals(tree(BC, c).getValidPolicy(), bc.getValidPolicy(),
                    row + ": BouncyCastle's leaf is anyPolicy");
            Assertions.assertEquals(2, bc.getDepth(), row);
        }
    }

    /**
     * PKITS 4.10.13's path with initial set {NIST-test-policy-2}, explicit
     * policy off. The CA requires explicit policy (requireExplicitPolicy 0),
     * asserts P1 and anyPolicy, and maps P1 to P2; the end entity asserts P2.
     * RFC 5280 6.1.5 (g)(iii)(2) deletes P1 and its P2 child, because P1 is
     * not in the initial set, step 4 prunes the rest, and a NULL tree with
     * explicit_policy 0 refuses (6.1.5 (g)). We and BouncyCastle refuse. SUN
     * removes P1 at depth 1 and then hangs the end entity's P2 under
     * anyPolicy, so it validates.
     */
    @Test
    public void sunValidatesAPathTheIntersectionEmptiesOnPkits41013() throws Exception
    {
        PkitsCertificates.Case c = PkitsPhase3Test.find("4.10.13");
        CertPathValidatorException ours = Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", JSL).validate(PkitsPhase2Test.path(c), onlyP2(c)));
        Assertions.assertTrue(ours.getMessage().matches("(?s).*failed: 43 .*"), ours.getMessage());
        Assertions.assertEquals(PKIXReason.INVALID_POLICY, ours.getReason());
        Assertions.assertEquals(-1, ours.getIndex());

        Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", BC).validate(PkitsPhase2Test.path(c), onlyP2(c)));

        PKIXCertPathValidatorResult sun = (PKIXCertPathValidatorResult) CertPathValidator
                .getInstance("PKIX", SUN).validate(PkitsPhase2Test.path(c), onlyP2(c));
        PolicyNode root = sun.getPolicyTree();
        PolicyNode leaf = leaf(root);
        Assertions.assertEquals(2, leaf.getDepth());
        Assertions.assertEquals(NIST_POLICY_2, leaf.getValidPolicy());
        Assertions.assertEquals(root.getValidPolicy(), leaf.getParent().getValidPolicy(),
                "SUN's P2 hangs under anyPolicy");
    }

    private static final String NIST_POLICY_2 = "2.16.840.1.101.3.2.1.48.2";

    private static PKIXParameters onlyP2(PkitsCertificates.Case c) throws Exception
    {
        PKIXParameters p = PkitsThreeWayAgreementTest.params(c);
        p.setInitialPolicies(Collections.singleton(NIST_POLICY_2));
        p.setExplicitPolicyRequired(false);
        return p;
    }

    /** A path asserting no policy has no tree, on all three. */
    @Test
    public void aPathWithNoPoliciesHasNoTree() throws Exception
    {
        PkitsCertificates.Case c = PkitsPhase3Test.find("4.8.2#1");
        for (String p : new String[]{JSL, SUN, BC})
        {
            Assertions.assertNull(tree(p, c), p);
        }
    }

    /** 4.8.15's user notice crosses as the certificate's own qualifier DER. */
    @Test
    public void aUserNoticeQualifierCrossesAsItsDer() throws Exception
    {
        PkitsCertificates.Case c = PkitsPhase3Test.find("4.8.15");
        PolicyNode leaf = leaf(tree(JSL, c));
        PolicyNode sunLeaf = leaf(tree(SUN, c));
        Assertions.assertEquals(1, leaf.getPolicyQualifiers().size());
        Assertions.assertArrayEquals(sunLeaf.getPolicyQualifiers().iterator().next().getEncoded(),
                leaf.getPolicyQualifiers().iterator().next().getEncoded());
    }

    private static PolicyNode leaf(PolicyNode n)
    {
        Iterator<? extends PolicyNode> it = n.getChildren();
        return it.hasNext() ? leaf(it.next()) : n;
    }

    /**
     * The builder's tree for the path it built equals SUN's validator tree:
     * a reference that cannot share our decode, unlike our own validator.
     */
    @Test
    public void theBuilderReturnsTheReferenceTree() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        for (PkitsCertificates.Case c : passRows())
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
            PKIXCertPathBuilderResult r = (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX", JSL)
                    .build(p);
            String built = canonical(r.getPolicyTree());
            String validated = canonical(tree(SUN, c));
            if (!built.equals(validated))
            {
                failures.add(c.number + ": built " + built + " SUN " + validated);
            }
        }
        Assertions.assertTrue(failures.isEmpty(), "builder trees differ from SUN's: " + failures);
    }

    /** The PolicyNode contract: immutable, rooted at depth 0, parents and depths consistent. */
    @Test
    public void thePolicyNodeIsImmutableAndConsistent() throws Exception
    {
        PolicyNode root = tree(JSL, PkitsPhase3Test.find("4.10.13"));
        Assertions.assertNotNull(root);
        Assertions.assertNull(root.getParent());
        Assertions.assertEquals(0, root.getDepth());
        Assertions.assertEquals(tree(SUN, PkitsPhase3Test.find("4.10.13")).getValidPolicy(), root.getValidPolicy());
        int seen = check(root);
        Assertions.assertEquals(3, seen, "4.10.13: anyPolicy, P1, P2");

        Iterator<? extends PolicyNode> it = root.getChildren();
        it.next();
        Assertions.assertThrows(UnsupportedOperationException.class, it::remove);
        Assertions.assertThrows(UnsupportedOperationException.class, () -> root.getExpectedPolicies().clear());
        Assertions.assertThrows(UnsupportedOperationException.class, () -> root.getPolicyQualifiers().clear());
    }

    private static int check(PolicyNode n)
    {
        int count = 1;
        for (Iterator<? extends PolicyNode> it = n.getChildren(); it.hasNext(); )
        {
            PolicyNode c = it.next();
            Assertions.assertSame(n, c.getParent());
            Assertions.assertEquals(n.getDepth() + 1, c.getDepth());
            Assertions.assertFalse(c.getExpectedPolicies().isEmpty());
            count += check(c);
        }
        return count;
    }
}
