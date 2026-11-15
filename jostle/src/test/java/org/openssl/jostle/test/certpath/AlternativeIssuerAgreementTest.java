/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.certpath;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The PKIX builder with more than one candidate issuer: a CA certified more than once, cross-certificate loops,
 * expired and revoked alternatives, pools stuffed with certificates that claim an issuer they cannot prove, and
 * the bounds. Every ordering of each pool reaches the builders through an order-keeping store, so a result that
 * depends on the stores' order cannot pass. JSL's outcome is pinned; SUN and BouncyCastle 1.87 are measured beside
 * it, and BouncyCastle's choice between two valid paths varies between runs, so only that it builds is required.
 */
public class AlternativeIssuerAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String[] PROVIDERS = {JSL, "SUN", BC};
    private static final String NO_PATH = "no path could be built to any matching target";
    /** More decoys than the per-target bound the search once had: the stuffing cells use this many. */
    private static final int MANY = 17;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** A build's outcome: the path as labels, target first, or the exception. */
    private static final class Outcome
    {
        final List<String> path;
        final Exception failure;

        Outcome(List<String> path, Exception failure)
        {
            this.path = path;
            this.failure = failure;
        }

        boolean built()
        {
            return path != null;
        }

        /** The cause's reason, when the failure carries a CertPathValidatorException. */
        CertPathValidatorException.Reason causeReason()
        {
            Throwable c = failure == null ? null : failure.getCause();
            return c instanceof CertPathValidatorException ? ((CertPathValidatorException) c).getReason() : null;
        }

        @Override
        public String toString()
        {
            return built() ? path.toString() : failure.getClass().getSimpleName() + ": " + failure.getMessage()
                    + " <- " + failure.getCause();
        }
    }

    private static Object decode(String provider, Object o) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        if (o instanceof X509CRL)
        {
            return cf.generateCRL(new ByteArrayInputStream(((X509CRL) o).getEncoded()));
        }
        return cf.generateCertificate(new ByteArrayInputStream(((X509Certificate) o).getEncoded()));
    }

    /**
     * Build to the target from the pool in the order given, through the provider's builder, every object
     * re-decoded by that provider's factory; ordered selects the order-keeping store, else the provider's own
     * Collection store. A negative maxPathLength leaves the default.
     */
    private static Outcome build(AlternativeIssuerFixtures f, String provider, X509Certificate anchor,
            List<X509Certificate> pool, X509Certificate target, List<X509CRL> crls, boolean ordered,
            int maxPathLength) throws Exception
    {
        List<Object> objects = new ArrayList<Object>();
        for (X509Certificate c : pool)
        {
            objects.add(decode(provider, c));
        }
        for (X509CRL c : crls)
        {
            objects.add(decode(provider, c));
        }
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate((X509Certificate) decode(provider, target));
        PKIXBuilderParameters p = new PKIXBuilderParameters(
                Collections.singleton(new TrustAnchor((X509Certificate) decode(provider, anchor), null)), sel);
        p.setRevocationEnabled(!crls.isEmpty());
        if (maxPathLength >= 0)
        {
            p.setMaxPathLength(maxPathLength);
        }
        p.addCertStore(ordered ? OrderedCertStores.ordered(objects)
                : CertStore.getInstance("Collection", new CollectionCertStoreParameters(objects), provider));
        try
        {
            CertPath path = CertPathBuilder.getInstance("PKIX", provider).build(p).getCertPath();
            return new Outcome(f.labels(path), null);
        }
        catch (CertPathBuilderException e)
        {
            return new Outcome(null, e);
        }
    }

    /** The JSL outcome pinned for each measured case. */
    private static Map<String, String> pinnedOutcomes(AlternativeIssuerFixtures f) throws Exception
    {
        String twoValid = compareDer(f.xByA.getEncoded(), f.xByA2.getEncoded()) <= 0 ? "X_byA" : "X_byA#2";
        Map<String, String> out = new LinkedHashMap<String, String>();
        out.put("two alternatives, one valid", "[leaf, X_byA]");
        out.put("three alternatives, one valid", "[leaf, X_byA]");
        out.put("a cross-certificate loop beside the trusted route", "[leaf, X_byA]");
        out.put("a cross-certificate loop with no trusted route", "fails NO_TRUST_ANCHOR");
        out.put("the trusted-route copy expired", "fails NO_TRUST_ANCHOR");
        out.put("the untrusted copy expired", "[leaf, X_byA]");
        out.put("two trusted-route copies, both valid", "[leaf, " + twoValid + "]");
        out.put("one trusted-route copy revoked", "[leaf, X_byA#2]");
        out.put("the trusted-route copy revoked, an untrusted alternative", "fails REVOKED");
        out.put("no valid alternative", "fails NO_TRUST_ANCHOR");
        return out;
    }

    private static int compareDer(byte[] a, byte[] b)
    {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++)
        {
            int d = (a[i] & 0xff) - (b[i] & 0xff);
            if (d != 0)
            {
                return d;
            }
        }
        return a.length - b.length;
    }

    private static String describe(Outcome o)
    {
        if (o.built())
        {
            return o.path.toString();
        }
        return "fails " + o.causeReason();
    }

    /**
     * Every measured case, every ordering of its pool: JSL gives one outcome on every ordering, the pinned one,
     * and builds exactly where SUN and BouncyCastle build. When two valid paths exist JSL takes the one with the
     * later notAfter, then the smaller encoding; SUN takes the first in store order; BouncyCastle's choice is
     * stable within a run and varies between runs.
     */
    @Test
    public void everyCaseHasOneOutcomeOnEveryOrderingAndAgrees() throws Exception
    {
        AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
        Map<String, String> pinned = pinnedOutcomes(f);
        Map<String, AlternativeIssuerFixtures.Case> cases = f.cases();
        Assertions.assertEquals(pinned.keySet(), cases.keySet());
        for (AlternativeIssuerFixtures.Case c : cases.values())
        {
            Set<String> ours = new TreeSet<String>();
            boolean[] othersBuilt = new boolean[PROVIDERS.length];
            boolean[] othersFailed = new boolean[PROVIDERS.length];
            for (List<X509Certificate> order : OrderedCertStores.permutations(c.pool))
            {
                for (int i = 0; i < PROVIDERS.length; i++)
                {
                    Outcome o = build(f, PROVIDERS[i], f.rootA, order, f.leaf, c.crls, true, -1);
                    if (i == 0)
                    {
                        ours.add(describe(o));
                        if (!o.built())
                        {
                            Assertions.assertEquals(NO_PATH, o.failure.getMessage(), c.name);
                        }
                    }
                    othersBuilt[i] |= o.built();
                    othersFailed[i] |= !o.built();
                }
            }
            Assertions.assertEquals(Collections.singleton(pinned.get(c.name)), ours, c.name);
            boolean builds = pinned.get(c.name).startsWith("[");
            for (int i = 1; i < PROVIDERS.length; i++)
            {
                Assertions.assertEquals(builds, othersBuilt[i], PROVIDERS[i] + " builds: " + c.name);
                Assertions.assertEquals(!builds, othersFailed[i], PROVIDERS[i] + " fails: " + c.name);
            }
        }
    }

    /** The case the review found, with the providers' own hash-ordered stores: JSL builds every time. */
    @Test
    public void theCrossCertifiedCaBuildsEveryTime() throws Exception
    {
        for (int trial = 0; trial < 100; trial++)
        {
            AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
            List<X509Certificate> pool = Arrays.asList(f.leaf, f.xByA, f.xByB);
            for (String p : PROVIDERS)
            {
                Outcome o = build(f, p, f.rootA, pool, f.leaf, Collections.<X509CRL>emptyList(), false, -1);
                Assertions.assertTrue(o.built(), p + " trial " + trial + ": " + o);
            }
            Assertions.assertEquals(Arrays.asList("leaf", "X_byA"),
                    build(f, JSL, f.rootA, pool, f.leaf, Collections.<X509CRL>emptyList(), false, -1).path);
        }
    }

    /** Orderings of a large pool: real first, real last, reversed, and seeded shuffles. */
    private static List<List<X509Certificate>> orderings(List<X509Certificate> pool, long seed)
    {
        List<List<X509Certificate>> out = new ArrayList<List<X509Certificate>>();
        out.add(new ArrayList<X509Certificate>(pool));
        List<X509Certificate> reversed = new ArrayList<X509Certificate>(pool);
        Collections.reverse(reversed);
        out.add(reversed);
        Random r = new Random(seed);
        for (int i = 0; i < 30; i++)
        {
            List<X509Certificate> s = new ArrayList<X509Certificate>(pool);
            Collections.shuffle(s, r);
            out.add(s);
        }
        return out;
    }

    private static void stuffedStillBuilds(String what, AlternativeIssuerFixtures f, List<X509Certificate> decoys,
            List<X509Certificate> route, List<String> expected) throws Exception
    {
        Assertions.assertEquals(MANY, decoys.size());
        List<X509Certificate> pool = new ArrayList<X509Certificate>();
        pool.add(f.leaf);
        pool.addAll(decoys);
        pool.addAll(route);
        long seed = new SecureRandom().nextLong();
        List<List<X509Certificate>> orders = orderings(pool, seed);
        List<X509Certificate> realFirst = new ArrayList<X509Certificate>(route);
        realFirst.add(f.leaf);
        realFirst.addAll(decoys);
        orders.add(realFirst);
        for (List<X509Certificate> order : orders)
        {
            Outcome o = build(f, JSL, f.rootA, order, f.leaf, Collections.<X509CRL>emptyList(), true, -1);
            Assertions.assertEquals(expected, o.path, what + ", seed " + seed + ": " + o);
        }
    }

    /**
     * Seventeen certificates naming CA X as subject and Root A as issuer, copying both key identifiers, forged:
     * the real certificate still builds in every ordering, because a certificate that cannot prove its issuer is
     * never reached and sorts after every one that can.
     */
    @Test
    public void forgedAnchorClaimsCannotExhaustTheBound() throws Exception
    {
        AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
        stuffedStillBuilds("forged anchor claims", f, f.forgedAnchorClaims(MANY),
                Collections.singletonList(f.xByA), Arrays.asList("leaf", "X_byA"));
    }

    /** Seventeen certificates with CA X's subject and key identifier but another key: the same. */
    @Test
    public void foreignKeyDecoysCannotExhaustTheBound() throws Exception
    {
        AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
        stuffedStillBuilds("foreign-key decoys", f, f.foreignKeyDecoys(MANY),
                Collections.singletonList(f.xByA), Arrays.asList("leaf", "X_byA"));
    }

    /**
     * Seventeen genuine certificates of CA X's own key from untrusted roots, which ARE reached, beside a route of
     * two through CA Y: they have no verified route to an anchor, so they sort after it, in every ordering.
     */
    @Test
    public void untrustedCrossCertificatesCannotExhaustTheBoundOnADeeperRoute() throws Exception
    {
        AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
        stuffedStillBuilds("untrusted cross-certificates", f,
                f.untrustedAlternatives(MANY),
                Arrays.asList(f.xByY, f.yByA), Arrays.asList("leaf", "X_byY", "Y_byA"));
    }

    /**
     * A failed Java check is a failed attempt. With maxPathLength 1, the route through CA Y (two non-self-issued
     * intermediates) is tried first and refused; the route through two self-issued certificates of CA X (one
     * non-self-issued intermediate) is found after it, in every ordering, as BouncyCastle finds it.
     */
    @Test
    public void aPathWithinMaxPathLengthIsFoundBehindOneBeyondIt() throws Exception
    {
        AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
        List<X509Certificate> pool = Arrays.asList(f.leaf, f.xByY, f.yByA, f.xSelfIssued1, f.xSelfIssued2, f.x2ByA);
        List<String> expected = Arrays.asList("leaf", "X_selfIssued1", "X_selfIssued2", "X2_byA");
        for (List<X509Certificate> order : OrderedCertStores.permutations(pool))
        {
            Outcome o = build(f, JSL, f.rootA, order, f.leaf, Collections.<X509CRL>emptyList(), true, 1);
            Assertions.assertEquals(expected, o.path, String.valueOf(o));
        }
        // Measured: BouncyCastle builds the self-issued route at 1 too; SUN finds no path at 1 and builds the
        // route through CA Y from 2. SUN's refusal is pinned as a divergence.
        Outcome bc = build(f, BC, f.rootA, pool, f.leaf, Collections.<X509CRL>emptyList(), true, 1);
        Assertions.assertEquals(expected, bc.path, String.valueOf(bc));
        Outcome sun = build(f, "SUN", f.rootA, pool, f.leaf, Collections.<X509CRL>emptyList(), true, 1);
        Assertions.assertFalse(sun.built(), String.valueOf(sun));
        Assertions.assertEquals(Arrays.asList("leaf", "X_byY", "Y_byA"),
                build(f, "SUN", f.rootA, pool, f.leaf, Collections.<X509CRL>emptyList(), true, 2).path);
        // Without the limit the shorter route through CA Y is the one returned.
        Assertions.assertEquals(Arrays.asList("leaf", "X_byY", "Y_byA"),
                build(f, JSL, f.rootA, pool, f.leaf, Collections.<X509CRL>emptyList(), true, -1).path);
        // At 0 neither route is admitted: the refusal is the cause, after both were tried.
        Outcome none = build(f, JSL, f.rootA, pool, f.leaf, Collections.<X509CRL>emptyList(), true, 0);
        Assertions.assertFalse(none.built());
        Assertions.assertEquals(NO_PATH, none.failure.getMessage());
        Assertions.assertTrue(none.failure.getCause() instanceof CertPathBuilderException,
                String.valueOf(none.failure.getCause()));
    }

    /** An X509CertSelector matching every end entity and no CA certificate. */
    private static X509CertSelector endEntities()
    {
        X509CertSelector sel = new X509CertSelector();
        sel.setBasicConstraints(-2);
        return sel;
    }

    private static CertPath buildJsl(AlternativeIssuerFixtures f, List<X509Certificate> pool,
            CertSelector sel) throws Exception
    {
        List<Object> objects = new ArrayList<Object>();
        for (X509Certificate c : pool)
        {
            objects.add(decode(JSL, c));
        }
        PKIXBuilderParameters p = new PKIXBuilderParameters(
                Collections.singleton(new TrustAnchor((X509Certificate) decode(JSL, f.rootA), null)), sel);
        p.setRevocationEnabled(false);
        p.addCertStore(OrderedCertStores.ordered(objects));
        return CertPathBuilder.getInstance("PKIX", JSL).build(p).getCertPath();
    }

    /**
     * Every matched target gets its first call, as before the search: one buildable end entity behind
     * ninety-nine that no path reaches, last in store order, is found by all three builders.
     */
    @Test
    public void aBuildableTargetBehindManyOthersIsFound() throws Exception
    {
        AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
        List<X509Certificate> pool = new ArrayList<X509Certificate>(f.forgedLeaves(99));
        pool.add(f.xByA);
        pool.add(f.leaf);
        Assertions.assertEquals(Arrays.asList("leaf", "X_byA"), f.labels(buildJsl(f, pool, endEntities())));
        for (String p : new String[]{"SUN", BC})
        {
            List<Object> objects = new ArrayList<Object>();
            for (X509Certificate c : pool)
            {
                objects.add(decode(p, c));
            }
            PKIXBuilderParameters params = new PKIXBuilderParameters(
                    Collections.singleton(new TrustAnchor((X509Certificate) decode(p, f.rootA), null)), endEntities());
            params.setRevocationEnabled(false);
            params.addCertStore(OrderedCertStores.ordered(objects));
            Assertions.assertEquals(Arrays.asList("leaf", "X_byA"),
                    f.labels(CertPathBuilder.getInstance("PKIX", p).build(params).getCertPath()), p);
        }
    }

    /**
     * Forged targets cannot spend the real target's attempts or ordering: four end entities no path reaches,
     * ahead of the real one in store order, and 245 forged certificates claiming Root A as CA X's issuer with a
     * later notAfter than the real one. The real path builds in every ordering tried.
     */
    @Test
    public void forgedTargetsAndForgedIssuersCannotStarveTheRealTarget() throws Exception
    {
        AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
        List<X509Certificate> pool = new ArrayList<X509Certificate>(f.forgedLeaves(4));
        pool.addAll(f.forgedAnchorClaims(245, 3650));
        pool.add(f.xByA);
        pool.add(f.leaf);
        long seed = new SecureRandom().nextLong();
        for (List<X509Certificate> order : orderings(pool, seed))
        {
            Assertions.assertEquals(Arrays.asList("leaf", "X_byA"), f.labels(buildJsl(f, order, endEntities())),
                    "seed " + seed);
        }
    }

    /**
     * A candidate whose key this provider cannot build counts as unverified and the build goes on: an
     * unidentified key algorithm, a DSA key whose parameters are inherited, and an EC key that is not a point.
     * All three builders build the real path in every ordering.
     */
    @Test
    public void aCandidateWhoseKeyCannotBeBuiltLeavesTheBuildGoing() throws Exception
    {
        AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
        byte[] junk = new byte[65];
        new SecureRandom().nextBytes(junk);
        SubjectPublicKeyInfo[] keys = {
                new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4.5")), junk),
                new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa),
                        new ASN1Integer(new BigInteger(1, junk))),
                new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                        SECObjectIdentifiers.secp256r1), junk)};
        String[] labels = {"unidentified key", "inherited DSA parameters", "EC key not a point"};
        for (int k = 0; k < keys.length; k++)
        {
            X509Certificate bad = f.withSubjectPublicKeyInfo(labels[k], keys[k]);
            List<X509Certificate> pool = Arrays.asList(f.leaf, f.xByA, bad);
            for (List<X509Certificate> order : OrderedCertStores.permutations(pool))
            {
                for (String p : PROVIDERS)
                {
                    if (!parses(p, bad))
                    {
                        // Measured: SUN's factory refuses the certificate whose EC key is not a point; only
                        // JSL's must take it.
                        Assertions.assertNotEquals(JSL, p, labels[k]);
                        continue;
                    }
                    Outcome o = build(f, p, f.rootA, order, f.leaf, Collections.<X509CRL>emptyList(), true, -1);
                    Assertions.assertTrue(o.built(), p + ", " + labels[k] + ": " + o);
                    if (JSL.equals(p))
                    {
                        Assertions.assertEquals(Arrays.asList("leaf", "X_byA"), o.path, labels[k]);
                    }
                }
            }
        }
    }

    private static boolean parses(String provider, X509Certificate cert)
    {
        try
        {
            decode(provider, cert);
            return true;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    /**
     * A target that is itself a trust anchor is a failed attempt for that target only: tried first (its route is
     * one), it fails, and the end entity after it builds.
     */
    @Test
    public void aTargetThatIsATrustAnchorFailsForItselfOnly() throws Exception
    {
        AlternativeIssuerFixtures f = new AlternativeIssuerFixtures();
        final Set<String> subjects = new TreeSet<String>(Arrays.asList(
                f.rootA.getSubjectX500Principal().getName(), f.leaf.getSubjectX500Principal().getName()));
        CertSelector rootOrLeaf = new CertSelector()
        {
            public boolean match(Certificate c)
            {
                return subjects.contains(((X509Certificate) c).getSubjectX500Principal().getName());
            }

            public Object clone()
            {
                return this;
            }
        };
        List<X509Certificate> pool = Arrays.asList(f.rootA, f.xByA, f.leaf);
        for (List<X509Certificate> order : OrderedCertStores.permutations(pool))
        {
            Assertions.assertEquals(Arrays.asList("leaf", "X_byA"), f.labels(buildJsl(f, order, rootOrLeaf)));
        }
        CertPathBuilderException e = assertThrows(CertPathBuilderException.class,
                () -> buildJsl(f, Collections.singletonList(f.rootA), rootOrLeaf));
        Assertions.assertEquals(NO_PATH, e.getMessage());
        Assertions.assertEquals("the target is a trust anchor, so no path is built", e.getCause().getMessage());

        // Divergences, measured: with the anchor itself the target, SUN returns an empty path and BouncyCastle a
        // path holding the anchor.
        Outcome sun = build(f, "SUN", f.rootA, Collections.singletonList(f.rootA), f.rootA,
                Collections.<X509CRL>emptyList(), true, -1);
        Assertions.assertEquals(Collections.<String>emptyList(), sun.path, String.valueOf(sun));
        Outcome bc = build(f, BC, f.rootA, Collections.singletonList(f.rootA), f.rootA,
                Collections.<X509CRL>emptyList(), true, -1);
        Assertions.assertEquals(Collections.singletonList("RootA"), bc.path, String.valueOf(bc));
    }

    /** A certificate of a PKITS CA's key issued by a new, untrusted root: an alternative for the builder. */
    private static X509Certificate untrustedCopyOf(X509Certificate ca) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
        kpg.initialize(256);
        KeyPair root = kpg.generateKeyPair();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=Untrusted PKITS Root"),
                BigInteger.valueOf(7), new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 30 * 86400000L),
                X500Name.getInstance(ca.getSubjectX500Principal().getEncoded()), ca.getPublicKey());
        byte[] ski = ASN1OctetString.getInstance(ca.getExtensionValue(Extension.subjectKeyIdentifier.getId()))
                .getOctets();
        b.addExtension(Extension.subjectKeyIdentifier, false, SubjectKeyIdentifier.getInstance(ski));
        b.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(root.getPublic()).getKeyIdentifier()));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(root.getPrivate())));
    }

    /** The PKITS separate-keys case through JSL's validator: success, or the failure's reason. */
    private static String validated(String ee, String ca, String crlSigner, String[] crls) throws Exception
    {
        List<Certificate> certs = new ArrayList<Certificate>();
        certs.add(pkits(ee));
        certs.add(pkits(ca));
        CertPath path = CertificateFactory.getInstance("X.509", JSL).generateCertPath(certs);
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(pkits(PkitsCertificates.ANCHOR),
                null)));
        p.setRevocationEnabled(true);
        List<Object> objects = new ArrayList<Object>();
        objects.add(pkits(crlSigner));
        for (String c : crls)
        {
            objects.add(pkitsCrl(c));
        }
        p.addCertStore(OrderedCertStores.ordered(objects));
        try
        {
            CertPathValidator.getInstance("PKIX", JSL).validate(path, p);
            return "valid";
        }
        catch (CertPathValidatorException e)
        {
            return "fails " + e.getReason();
        }
    }

    private static X509Certificate pkits(String name) throws Exception
    {
        return (X509Certificate) CertificateFactory.getInstance("X.509", JSL)
                .generateCertificate(new ByteArrayInputStream(PkitsCertificates.der(name)));
    }

    private static CRL pkitsCrl(String name) throws Exception
    {
        return CertificateFactory.getInstance("X.509", JSL)
                .generateCRL(new ByteArrayInputStream(PkitsCertificates.crlDer(name)));
    }

    /**
     * PKITS 4.4.19 to 4.4.21 through the BUILDER, revocation on, with an alternative of the signing CA's key
     * beside the separate CRL-signing certificate (which shares the CA's subject, so it is an alternative too):
     * every ordering gives the validator's answer for the same path, and SUN and BouncyCastle agree on whether
     * it builds.
     */
    @Test
    public void pkitsSeparateKeysThroughTheBuilderWithAnAlternative() throws Exception
    {
        String ca1 = "SeparateCertificateandCRLKeysCertificateSigningCACert.crt";
        String crlSigner1 = "SeparateCertificateandCRLKeysCRLSigningCert.crt";
        String crl1 = "SeparateCertificateandCRLKeysCRL.crl";
        String[][] rows = {
                {"ValidSeparateCertificateandCRLKeysTest19EE.crt", ca1, crlSigner1, crl1},
                {"InvalidSeparateCertificateandCRLKeysTest20EE.crt", ca1, crlSigner1, crl1},
                {"InvalidSeparateCertificateandCRLKeysTest21EE.crt",
                        "SeparateCertificateandCRLKeysCA2CertificateSigningCACert.crt",
                        "SeparateCertificateandCRLKeysCA2CRLSigningCert.crt",
                        "SeparateCertificateandCRLKeysCA2CRL.crl"}};
        // 4.4.21's CRL-signing certificate is itself revoked: JSL's validator reports the revocation status of
        // the end entity as undetermined, and the builder must give the validator's answer.
        String[] expected = {"valid", "fails REVOKED", "fails UNDETERMINED_REVOCATION_STATUS"};
        for (int r = 0; r < rows.length; r++)
        {
            String[] row = rows[r];
            String[] crls = {"TrustAnchorRootCRL.crl", row[3]};
            Assertions.assertEquals(expected[r], validated(row[0], row[1], row[2], crls), "validator, " + row[0]);
            X509Certificate alternative = untrustedCopyOf(pkits(row[1]));
            List<X509Certificate> pool = Arrays.asList(pkits(row[0]), pkits(row[1]), pkits(row[2]), alternative);
            for (List<X509Certificate> order : OrderedCertStores.permutations(pool))
            {
                for (String p : PROVIDERS)
                {
                    String got = pkitsBuild(p, order, row[0], crls);
                    if (JSL.equals(p))
                    {
                        Assertions.assertEquals(expected[r], got, "JSL builder, " + row[0] + " " + order);
                    }
                    else
                    {
                        Assertions.assertEquals("valid".equals(expected[r]), "valid".equals(got),
                                p + " builder, " + row[0] + ": " + got);
                    }
                }
            }
        }
    }

    /**
     * PKITS 4.4.20, the end entity revoked on a CRL signed by a separate key, through the builder with an
     * alternative present: REVOKED on every ordering. The search's first version reported
     * UNDETERMINED_REVOCATION_STATUS on some orderings.
     */
    @Test
    public void pkits4420IsRevokedOnEveryOrdering() throws Exception
    {
        String ee = "InvalidSeparateCertificateandCRLKeysTest20EE.crt";
        String ca = "SeparateCertificateandCRLKeysCertificateSigningCACert.crt";
        String[] crls = {"TrustAnchorRootCRL.crl", "SeparateCertificateandCRLKeysCRL.crl"};
        List<X509Certificate> pool = Arrays.asList(pkits(ee), pkits(ca),
                pkits("SeparateCertificateandCRLKeysCRLSigningCert.crt"), untrustedCopyOf(pkits(ca)));
        Set<String> outcomes = new TreeSet<String>();
        for (List<X509Certificate> order : OrderedCertStores.permutations(pool))
        {
            outcomes.add(pkitsBuild(JSL, order, ee, crls));
        }
        Assertions.assertEquals(Collections.singleton("fails REVOKED"), outcomes);
    }

    private static String pkitsBuild(String provider, List<X509Certificate> order, String ee, String[] crls)
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        List<Object> objects = new ArrayList<Object>();
        for (X509Certificate c : order)
        {
            objects.add(cf.generateCertificate(new ByteArrayInputStream(c.getEncoded())));
        }
        for (String c : crls)
        {
            objects.add(cf.generateCRL(new ByteArrayInputStream(PkitsCertificates.crlDer(c))));
        }
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate((X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(PkitsCertificates.der(ee))));
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(
                (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(
                        PkitsCertificates.der(PkitsCertificates.ANCHOR))), null)), sel);
        p.setRevocationEnabled(true);
        p.addCertStore(OrderedCertStores.ordered(objects));
        try
        {
            CertPathBuilder.getInstance("PKIX", provider).build(p);
            return "valid";
        }
        catch (CertPathBuilderException e)
        {
            Throwable c = e.getCause();
            return c instanceof CertPathValidatorException ? "fails " + ((CertPathValidatorException) c).getReason()
                    : "fails";
        }
    }
}
