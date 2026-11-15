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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.certpath.JostleCertPathBuilderSpi;
import org.openssl.jostle.jcajce.provider.certpath.JostleCertPathValidatorSpi;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * OpenSSL's CRL-issuer walk takes the first certificate in its untrusted stack with the CRL issuer's name that
 * passes the key-identifier check, so a certificate of the CA's own key (renewed, or the other half of a
 * cross-certification) ahead of a separate CRL-signing certificate makes the CRL fail its signature. The verified
 * order puts, among routed certificates of one name, one whose key verifies a supplied CRL of that name first. A
 * separate-key CA is rebuilt here with test keys: a root, a CA certifying with one key, a CRL-signing certificate of
 * that CA's name with another key, a leaf, and the CA's CRL signed by the CRL key, revoking the leaf or not.
 */
public class CrlSignerOrderAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final long DAY = 86400000L;
    /**
     * One base time for every certificate and CRL of the class, whole seconds: two CRLs meant to share an issue
     * time must not land either side of a second boundary.
     */
    private static final long NOW = System.currentTimeMillis() / 1000L * 1000L;

    private static KeyPairGenerator kpg;
    private static JcaX509ExtensionUtils ids;
    private static long serial = 1;

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
        kpg = KeyPairGenerator.getInstance("EC", BC);
        kpg.initialize(256);
        ids = new JcaX509ExtensionUtils();
    }

    private static X509Certificate cert(String issuer, KeyPair signer, String subject, PublicKey key, boolean ca,
            int usage) throws Exception
    {
        return cert(issuer, signer, subject, key, ca, usage, true);
    }

    private static X509Certificate cert(String issuer, KeyPair signer, String subject, PublicKey key, boolean ca,
            int usage, boolean withSki) throws Exception
    {
        long now = NOW;
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(serial++), new Date(now - DAY), new Date(now + 365 * DAY), new X500Name(subject),
                key);
        if (withSki)
        {
            b.addExtension(Extension.subjectKeyIdentifier, false, ids.createSubjectKeyIdentifier(key));
        }
        b.addExtension(Extension.authorityKeyIdentifier, false, ids.createAuthorityKeyIdentifier(signer.getPublic()));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        byte[] der = b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())).getEncoded();
        return (X509Certificate) CertificateFactory.getInstance("X.509", JSL)
                .generateCertificate(new ByteArrayInputStream(der));
    }

    private static X509CRL crl(String issuer, KeyPair signer, long thisDays, int number, BigInteger... revoked)
            throws Exception
    {
        return crl("SHA256withECDSA", issuer, signer, thisDays, number, revoked);
    }

    private static X509CRL crl(String algorithm, String issuer, KeyPair signer, long thisDays, int number,
            BigInteger... revoked) throws Exception
    {
        long now = NOW;
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(issuer), new Date(now + thisDays * DAY));
        b.setNextUpdate(new Date(now + 7 * DAY));
        for (BigInteger r : revoked)
        {
            b.addCRLEntry(r, new Date(now + thisDays * DAY), CRLReason.keyCompromise);
        }
        b.addExtension(Extension.authorityKeyIdentifier, false, ids.createAuthorityKeyIdentifier(signer.getPublic()));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        return new JcaX509CRLConverter().setProvider(BC).getCRL(b.build(new JcaContentSignerBuilder(algorithm)
                .build(signer.getPrivate())));
    }

    /** The separate-key world: root, CA (certifying key), CRL signer (CRL key), leaf, and the two keys' owners. */
    private static final class World
    {
        final KeyPair root = kpg.generateKeyPair();
        final KeyPair caKey = kpg.generateKeyPair();
        final KeyPair crlKey = kpg.generateKeyPair();
        final X509Certificate anchor;
        final X509Certificate ca;
        final X509Certificate signer;
        final X509Certificate leaf;
        final X509CRL rootCrl;

        World() throws Exception
        {
            anchor = cert("CN=Root", root, "CN=Root", root.getPublic(), true, KeyUsage.keyCertSign | KeyUsage.cRLSign);
            ca = cert("CN=Root", root, "CN=Sep CA", caKey.getPublic(), true, KeyUsage.keyCertSign);
            signer = cert("CN=Root", root, "CN=Sep CA", crlKey.getPublic(), false, KeyUsage.cRLSign);
            leaf = cert("CN=Sep CA", caKey, "CN=leaf", kpg.generateKeyPair().getPublic(), false,
                    KeyUsage.digitalSignature);
            rootCrl = crl("CN=Root", root, -1, 1);
        }

        X509CRL caCrl(boolean revoked) throws Exception
        {
            return revoked ? crl("CN=Sep CA", crlKey, -1, 1, leaf.getSerialNumber()) : crl("CN=Sep CA", crlKey, -1, 1);
        }
    }

    private static String validate(World w, List<Object> store) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JSL);
        CertPath path = cf.generateCertPath(Arrays.<Certificate>asList(w.leaf, w.ca));
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(w.anchor, null)));
        p.setRevocationEnabled(true);
        p.addCertStore(OrderedCertStores.ordered(store));
        try
        {
            CertPathValidator.getInstance("PKIX", JSL).validate(path, p);
            return "valid";
        }
        catch (CertPathValidatorException e)
        {
            return "refused " + e.getReason();
        }
    }

    private static String build(World w, List<Object> store) throws Exception
    {
        return build(w, store, new CountingCertPathNI());
    }

    private static String build(World w, List<Object> store, CountingCertPathNI counter) throws Exception
    {
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(w.leaf);
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(w.anchor, null)),
                sel);
        p.setRevocationEnabled(true);
        List<Object> pool = new ArrayList<Object>(Arrays.<Object>asList(w.leaf, w.ca));
        pool.addAll(store);
        p.addCertStore(OrderedCertStores.ordered(pool));
        try
        {
            new JostleCertPathBuilderSpi(counter.ni, Security.getProvider(JSL)).engineBuild(p);
            return "valid";
        }
        catch (CertPathBuilderException e)
        {
            Throwable c = e.getCause();
            return "refused" + (c instanceof CertPathValidatorException ? " " + ((CertPathValidatorException) c)
                    .getReason() : "");
        }
    }

    /** Every ordering of the store's certificates, the CRLs after them, through the validator and the builder. */
    private static void oneAnswer(String what, World w, List<Object> certs, List<Object> crls, String expected)
            throws Exception
    {
        Set<String> validator = new TreeSet<String>();
        Set<String> builder = new TreeSet<String>();
        for (List<Object> order : OrderedCertStores.permutations(certs))
        {
            List<Object> store = new ArrayList<Object>(order);
            store.addAll(crls);
            validator.add(validate(w, store));
            builder.add(build(w, store));
        }
        Assertions.assertEquals(Collections.singleton(expected), validator, "validator, " + what);
        Assertions.assertEquals(Collections.singleton(expected), builder, "builder, " + what);
    }

    /**
     * A renewed certificate of the CA's own key (same name, key and issuer, another serial) beside the separate CRL
     * signer: the clean leaf is valid and the revoked one REVOKED, on both orders, through both services. The
     * validator answered by store order before this order existed, and the builder reported the revoked leaf
     * UNDETERMINED.
     */
    @Test
    public void aRenewedCaCertificateDoesNotHideTheCrlSigner() throws Exception
    {
        World w = new World();
        X509Certificate renewed = cert("CN=Root", w.root, "CN=Sep CA", w.caKey.getPublic(), true, KeyUsage.keyCertSign);
        for (boolean revoked : new boolean[]{false, true})
        {
            oneAnswer("renewed CA, leaf " + (revoked ? "revoked" : "clean"), w,
                    Arrays.<Object>asList(w.signer, renewed), Arrays.<Object>asList(w.rootCrl, w.caCrl(revoked)),
                    revoked ? "refused REVOKED" : "valid");
        }
    }

    /**
     * The other half of a cross-certification: the CA's own key certified by a bridge CA under the root (routed,
     * able to issue). It does not hide the separate CRL signer either.
     */
    @Test
    public void aCrossCertificateOfTheCaKeyDoesNotHideTheCrlSigner() throws Exception
    {
        World w = new World();
        KeyPair bridge = kpg.generateKeyPair();
        X509Certificate bridgeCert = cert("CN=Root", w.root, "CN=Bridge", bridge.getPublic(), true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign);
        X509Certificate cross = cert("CN=Bridge", bridge, "CN=Sep CA", w.caKey.getPublic(), true,
                KeyUsage.keyCertSign);
        for (boolean revoked : new boolean[]{false, true})
        {
            oneAnswer("cross-certificate, leaf " + (revoked ? "revoked" : "clean"), w,
                    Arrays.<Object>asList(w.signer, cross, bridgeCert),
                    Arrays.<Object>asList(w.rootCrl, w.caCrl(revoked), crl("CN=Bridge", bridge, -1, 1)),
                    revoked ? "refused REVOKED" : "valid");
        }
    }

    /**
     * An unrouted certificate with the CA's name (issued by an untrusted root) whose own key signs a forged CRL of
     * that name, older than the genuine one so OpenSSL never prefers it: the rule applies only among routed
     * certificates, so the forgery's signer gains nothing and every order gives the genuine answer.
     */
    @Test
    public void anUnroutedSignerOfAForgedCrlGainsNothing() throws Exception
    {
        World w = new World();
        KeyPair outsider = kpg.generateKeyPair();
        KeyPair forgerRoot = kpg.generateKeyPair();
        X509Certificate forger = cert("CN=Untrusted", forgerRoot, "CN=Sep CA", outsider.getPublic(), true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign);
        X509Certificate renewed = cert("CN=Root", w.root, "CN=Sep CA", w.caKey.getPublic(), true, KeyUsage.keyCertSign);
        X509CRL forged = crl("CN=Sep CA", outsider, -3, 1);
        for (boolean revoked : new boolean[]{false, true})
        {
            oneAnswer("unrouted forger, leaf " + (revoked ? "revoked" : "clean"), w,
                    Arrays.<Object>asList(w.signer, renewed, forger),
                    Arrays.<Object>asList(w.rootCrl, w.caCrl(revoked), forged), revoked ? "refused REVOKED" : "valid");
        }
    }

    /**
     * The rule's checks: two routed certificates of the CA's name (the CRL signer and a renewed CA) and a hundred
     * CRLs naming the CA, ninety-nine of them signed by unrelated keys. Each routed candidate is checked against each
     * CRL of its name, once: at most 2 x 100 checks for the rule, drawn on the same budget; counted and printed.
     */
    @Test
    public void theCrlSignerChecksAreCountedWithinTheBudget() throws Exception
    {
        World w = new World();
        X509Certificate renewed = cert("CN=Root", w.root, "CN=Sep CA", w.caKey.getPublic(), true, KeyUsage.keyCertSign);
        List<Object> store = new ArrayList<Object>(Arrays.<Object>asList(w.signer, renewed, w.rootCrl, w.caCrl(true)));
        for (int i = 0; i < 99; i++)
        {
            store.add(crl("CN=Sep CA", kpg.generateKeyPair(), -2, 1));
        }
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(w.anchor, null)));
        p.setRevocationEnabled(true);
        p.addCertStore(OrderedCertStores.ordered(store));
        CertPath path = CertificateFactory.getInstance("X.509", JSL)
                .generateCertPath(Arrays.<Certificate>asList(w.leaf, w.ca));
        CountingJslProvider.VERIFICATIONS.set(0);
        long t0 = System.nanoTime();
        String got;
        try
        {
            new JostleCertPathValidatorSpi(NISelector.CertPathNI, new CountingJslProvider()).engineValidate(path, p);
            got = "valid";
        }
        catch (CertPathValidatorException e)
        {
            got = "refused " + e.getReason();
        }
        int checks = CountingJslProvider.VERIFICATIONS.get();
        System.out.printf("[crl-signer] 2 routed candidates, 100 CRLs of their name: %d checks, %d ms%n", checks,
                (System.nanoTime() - t0) / 1000000L);
        Assertions.assertEquals("refused REVOKED", got);
        Assertions.assertTrue(checks > 0, "no check was counted");
        // Routes: the root's two certificates of the CA's name and its route edges; the rule: at most 2 x 100.
        Assertions.assertTrue(checks <= 2 * 100 + 10, checks + " checks");
    }

    /**
     * The renewed-CA case through the builder, counted: the builder's up-front CRL-signer rule puts the signer ahead
     * of the CA's renewed certificate, so the first call gives the answer on every order. A clean leaf builds on the
     * first call and is confirmed by one more, since the root's and the CA's CRLs share a thisUpdate (a tie group);
     * a revoked one answers REVOKED first, and the search then demotes the CA's two certificates in turn, each
     * answering REVOKED (three calls).
     */
    @Test
    public void theBuilderAnswersTheRenewedCaCaseInOneCall() throws Exception
    {
        World w = new World();
        X509Certificate renewed = cert("CN=Root", w.root, "CN=Sep CA", w.caKey.getPublic(), true, KeyUsage.keyCertSign);
        for (boolean revoked : new boolean[]{false, true})
        {
            Set<String> answers = new TreeSet<String>();
            Set<Integer> calls = new TreeSet<Integer>();
            for (List<Object> order : OrderedCertStores.permutations(Arrays.<Object>asList(w.signer, renewed)))
            {
                List<Object> store = new ArrayList<Object>(order);
                store.add(w.rootCrl);
                store.add(w.caCrl(revoked));
                CountingCertPathNI counter = new CountingCertPathNI();
                answers.add(build(w, store, counter));
                System.out.println("[crl-signer] renewed CA through the builder, calls " + counter.errors);
                calls.add(counter.take());
            }
            Assertions.assertEquals(Collections.singleton(revoked ? "refused REVOKED" : "valid"), answers);
            Assertions.assertEquals(Collections.singleton(revoked ? 3 : 2), calls, "OpenSSL calls per build");
        }
    }

    /**
     * The CRL-signer flag has its own allowance: a store of forged CRLs under three names, each name with two
     * routed CRL-signing certificates, makes more candidate-by-CRL pairs than the allowance (256). The CRLs are
     * signed with SHA384withECDSA and the certificates with SHA256withECDSA, so the two kinds of check are counted
     * apart: the CRL checks stop at the allowance, the certificate checks equal those of the same store without
     * the forgeries, and the genuine answer comes out.
     */
    @Test
    public void forgedCrlsSpendOnlyTheCrlAllowance() throws Exception
    {
        World w = new World();
        KeyPair crlKey2 = kpg.generateKeyPair();
        X509Certificate signer2 = cert("CN=Root", w.root, "CN=Sep CA", crlKey2.getPublic(), false, KeyUsage.cRLSign);
        List<Object> base = new ArrayList<Object>(Arrays.<Object>asList(w.signer, signer2));
        List<Object> forgeries = new ArrayList<Object>();
        for (String name : new String[]{"CN=Other A", "CN=Other B"})
        {
            base.add(cert("CN=Root", w.root, name, kpg.generateKeyPair().getPublic(), false, KeyUsage.cRLSign));
            base.add(cert("CN=Root", w.root, name, kpg.generateKeyPair().getPublic(), false, KeyUsage.cRLSign));
        }
        for (String name : new String[]{"CN=Sep CA", "CN=Other A", "CN=Other B"})
        {
            for (int i = 0; i < 50; i++)
            {
                forgeries.add(crl("SHA384withECDSA", name, kpg.generateKeyPair(), -2, 1));
            }
        }
        List<Object> crls = Arrays.<Object>asList(crl("SHA384withECDSA", "CN=Root", w.root, -1, 1),
                crl("SHA384withECDSA", "CN=Sep CA", w.crlKey, -1, 1, w.leaf.getSerialNumber()));

        List<Object> plain = new ArrayList<Object>(base);
        plain.addAll(crls);
        int[] without = counted(w, plain);
        List<Object> hostile = new ArrayList<Object>(base);
        hostile.addAll(forgeries);
        hostile.addAll(crls);
        int[] with = counted(w, hostile);
        System.out.printf("[crl-signer] without forgeries: %d certificate checks, %d CRL checks; with 150: %d, %d%n",
                without[0], without[1], with[0], with[1]);
        Assertions.assertEquals(256, with[1], "the CRL allowance, spent");
        Assertions.assertEquals(without[0], with[0], "the certificate budget is untouched");
    }

    /** The validator's answer must be REVOKED; returns {certificate checks, CRL checks}. */
    private static int[] counted(World w, List<Object> store) throws Exception
    {
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(w.anchor, null)));
        p.setRevocationEnabled(true);
        p.addCertStore(OrderedCertStores.ordered(store));
        CertPath path = CertificateFactory.getInstance("X.509", JSL)
                .generateCertPath(Arrays.<Certificate>asList(w.leaf, w.ca));
        CountingJslProvider.VERIFICATIONS.set(0);
        CountingJslProvider.VERIFICATIONS_384.set(0);
        String got;
        try
        {
            new JostleCertPathValidatorSpi(NISelector.CertPathNI, new CountingJslProvider()).engineValidate(path, p);
            got = "valid";
        }
        catch (CertPathValidatorException e)
        {
            got = "refused " + e.getReason();
        }
        Assertions.assertEquals("refused REVOKED", got);
        return new int[]{CountingJslProvider.VERIFICATIONS.get(), CountingJslProvider.VERIFICATIONS_384.get()};
    }

    /**
     * A CRL signer without a subject key identifier, routed and flagged, so the builder puts it ahead of the CA:
     * OpenSSL skips a candidate issuer whose subject key identifier differs from the child's authority key
     * identifier, but takes one that has none, refuses it (NOT_CA_CERT at depth 1), and the builder demotes it: the
     * revoked leaf takes two calls; the clean leaf three, the build being confirmed since the two CRLs share a
     * thisUpdate. The revoked leaf's cause is REVOKED (calls [79@1, 23@0]), not the first failure
     * that reached the anchor.
     */
    @Test
    public void aSignerWithoutAKeyIdentifierCostsTheBuilderOneCall() throws Exception
    {
        World w = new World();
        X509Certificate bare = cert("CN=Root", w.root, "CN=Sep CA", w.crlKey.getPublic(), false, KeyUsage.cRLSign,
                false);
        for (boolean revoked : new boolean[]{false, true})
        {
            Set<String> answers = new TreeSet<String>();
            Set<Integer> calls = new TreeSet<Integer>();
            for (List<Object> order : OrderedCertStores.permutations(Arrays.<Object>asList(bare)))
            {
                List<Object> store = new ArrayList<Object>(order);
                store.add(w.rootCrl);
                store.add(w.caCrl(revoked));
                CountingCertPathNI counter = new CountingCertPathNI();
                answers.add(build(w, store, counter));
                System.out.println("[crl-signer] signer without SKI, calls " + counter.errors);
                calls.add(counter.take());
            }
            System.out.printf("[crl-signer] signer without SKI, leaf %s: builder %s, calls %s, validator %s%n",
                    revoked ? "revoked" : "clean", answers, calls,
                    validate(w, Arrays.<Object>asList(bare, w.rootCrl, w.caCrl(revoked))));
            Assertions.assertEquals(Collections.singleton(revoked ? "refused REVOKED" : "valid"), answers);
            Assertions.assertEquals(Collections.singleton(revoked ? 2 : 3), calls, "OpenSSL calls per build");
        }
    }


    /**
     * The builder when the CRL-signer flag cannot help: 130 forged CRLs of the CA's name come before the genuine one,
     * so the allowance is spent before the separate signer is checked and the flag is absent; the signer, which
     * cannot issue, then goes after the CA's two certificates. A revocation-class failure after reaching the anchor
     * re-verifies the chain as a path in the validator's order, which puts the CA's renewed certificate last as a
     * copy: REVOKED on every order, and the calls per order pinned.
     */
    @Test
    public void aSpentAllowanceIsRescuedByTheReverification() throws Exception
    {
        World w = new World();
        X509Certificate renewed = cert("CN=Root", w.root, "CN=Sep CA", w.caKey.getPublic(), true, KeyUsage.keyCertSign);
        List<Object> crls = new ArrayList<Object>();
        for (int i = 0; i < 130; i++)
        {
            crls.add(crl("SHA384withECDSA", "CN=Sep CA", kpg.generateKeyPair(), -2, 1));
        }
        crls.add(w.rootCrl);
        crls.add(w.caCrl(true));
        Set<String> answers = new TreeSet<String>();
        Set<String> calls = new TreeSet<String>();
        for (List<Object> order : OrderedCertStores.permutations(Arrays.<Object>asList(w.signer, renewed)))
        {
            List<Object> store = new ArrayList<Object>(order);
            store.addAll(crls);
            CountingCertPathNI counter = new CountingCertPathNI();
            answers.add(build(w, store, counter));
            calls.add(counter.errors.toString());
            counter.take();
        }
        System.out.println("[crl-signer] spent allowance through the builder: " + answers + " " + calls);
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), answers);
        Assertions.assertEquals(SPENT_ALLOWANCE_CALLS, calls.toString(), "OpenSSL calls (error@depth) per order");
    }

    /**
     * The first attempt fails CRL_PATH_VALIDATION_ERROR (54) at the leaf, the re-verification answers REVOKED, and
     * the search then demotes the CA's two certificates, each answering REVOKED.
     */
    private static final String SPENT_ALLOWANCE_CALLS = "[[54@0, 23@0, 23@0, 23@0]]";

    /**
     * The cause rule's second case. The intended path's CA is revoked by the root's CRL (REVOKED at depth 1). A
     * second certificate of the CA's name under the root, with another key and a copy of the CA's subject key
     * identifier, expires sooner, so it is ordered after the CA; once the CA is demoted, OpenSSL takes it as the
     * leaf's issuer and the leaf's CRL fails its signature under it (depth 0, a revocation-class code, so re-verified
     * once). By depth alone the builder would report UNDETERMINED_REVOCATION_STATUS; a CERT_REVOKED is preferred, so
     * it reports REVOKED, as the validator does for the intended path.
     */
    @Test
    public void theCauseRulePrefersARevocationOverAWrongCandidatesFailure() throws Exception
    {
        KeyPair root = kpg.generateKeyPair();
        KeyPair caKey = kpg.generateKeyPair();
        long now = NOW;
        X509Certificate anchor = cert("CN=Root", root, "CN=Root", root.getPublic(), true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign);
        X509Certificate ca = cert("CN=Root", root, "CN=Rev CA", caKey.getPublic(), true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign);
        JcaX509v3CertificateBuilder ob = new JcaX509v3CertificateBuilder(new X500Name("CN=Root"),
                BigInteger.valueOf(serial++), new Date(now - DAY), new Date(now + 200 * DAY), new X500Name("CN=Rev CA"),
                kpg.generateKeyPair().getPublic());
        ob.addExtension(Extension.subjectKeyIdentifier, false, ids.createSubjectKeyIdentifier(caKey.getPublic()));
        ob.addExtension(Extension.authorityKeyIdentifier, false, ids.createAuthorityKeyIdentifier(root.getPublic()));
        ob.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ob.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        X509Certificate other = (X509Certificate) CertificateFactory.getInstance("X.509", JSL).generateCertificate(
                new ByteArrayInputStream(ob.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .build(root.getPrivate())).getEncoded()));
        X509Certificate leaf = cert("CN=Rev CA", caKey, "CN=leaf", kpg.generateKeyPair().getPublic(), false,
                KeyUsage.digitalSignature);
        List<Object> crls = Arrays.<Object>asList(crl("CN=Root", root, -1, 1, ca.getSerialNumber()),
                crl("CN=Rev CA", caKey, -1, 1));

        PKIXParameters vp = new PKIXParameters(Collections.singleton(new TrustAnchor(anchor, null)));
        vp.setRevocationEnabled(true);
        vp.addCertStore(OrderedCertStores.ordered(crls));
        String validator;
        try
        {
            CertPathValidator.getInstance("PKIX", JSL).validate(CertificateFactory.getInstance("X.509", JSL)
                    .generateCertPath(Arrays.<Certificate>asList(leaf, ca)), vp);
            validator = "valid";
        }
        catch (CertPathValidatorException e)
        {
            validator = "refused " + e.getReason();
        }
        Set<String> builder = new TreeSet<String>();
        Set<String> calls = new TreeSet<String>();
        for (List<Object> order : OrderedCertStores.permutations(Arrays.<Object>asList(leaf, ca, other)))
        {
            X509CertSelector sel = new X509CertSelector();
            sel.setCertificate(leaf);
            PKIXBuilderParameters p = new PKIXBuilderParameters(
                    Collections.singleton(new TrustAnchor(anchor, null)), sel);
            p.setRevocationEnabled(true);
            List<Object> store = new ArrayList<Object>(order);
            store.addAll(crls);
            p.addCertStore(OrderedCertStores.ordered(store));
            CountingCertPathNI counter = new CountingCertPathNI();
            try
            {
                new JostleCertPathBuilderSpi(counter.ni, Security.getProvider(JSL)).engineBuild(p);
                builder.add("valid");
            }
            catch (CertPathBuilderException e)
            {
                Throwable c = e.getCause();
                builder.add("refused" + (c instanceof CertPathValidatorException
                        ? " " + ((CertPathValidatorException) c).getReason() : ""));
            }
            calls.add(counter.errors.toString());
            counter.take();
        }
        System.out.println("[cause] revoked intermediate, wrong candidate: validator " + validator + ", builder "
                + builder + " " + calls);
        Assertions.assertEquals("refused REVOKED", validator);
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), builder);
        Assertions.assertEquals(Collections.singleton("[23@1, 8@0, 8@0]"), calls,
                "the CA revoked; the wrong candidate's CRL signature failure; its re-verification");
    }

    /**
     * Ordinary CA key rollover: the path's CA on key 1, a rolled-over CA certificate of the same name on key 3 that
     * can issue, and a separate CRL signer of that name on key 2, the CA's CRL signed by key 2. A CRL without an
     * authority key identifier is never looked up in the store (OpenSSL takes the chain's own issuer), so the key
     * identifier is made not to discriminate the other way: the CRL names key 2, and neither the signer nor the
     * rolled-over certificate carries a subject key identifier, so OpenSSL takes whichever comes first. Both services,
     * every order, clean and revoked leaf.
     */
    @Test
    public void aRolledOverCaKeyDoesNotHideTheCrlSigner() throws Exception
    {
        World w = new World();
        X509Certificate rolledOver = cert("CN=Root", w.root, "CN=Sep CA", kpg.generateKeyPair().getPublic(), true,
                KeyUsage.keyCertSign, false);
        X509Certificate bareSigner = cert("CN=Root", w.root, "CN=Sep CA", w.crlKey.getPublic(), false,
                KeyUsage.cRLSign, false);
        for (boolean revoked : new boolean[]{false, true})
        {
            Set<String> validator = new TreeSet<String>();
            Set<String> builder = new TreeSet<String>();
            for (List<Object> order : OrderedCertStores.permutations(Arrays.<Object>asList(bareSigner, rolledOver)))
            {
                List<Object> store = new ArrayList<Object>(order);
                store.add(w.rootCrl);
                store.add(w.caCrl(revoked));
                validator.add(validate(w, store));
                builder.add(build(w, store));
            }
            System.out.printf("[crl-signer] key rollover, leaf %s: validator %s, builder %s%n",
                    revoked ? "revoked" : "clean", validator, builder);
            String expected = revoked ? "refused REVOKED" : "valid";
            Assertions.assertEquals(Collections.singleton(expected), validator, "validator");
            Assertions.assertEquals(Collections.singleton(expected), builder, "builder");
        }
    }
}
