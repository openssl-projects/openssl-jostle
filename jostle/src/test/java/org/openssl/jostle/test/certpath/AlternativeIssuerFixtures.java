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
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Certificates for the alternative-issuer cases: a trusted Root A, untrusted Roots B and C, a CA X holding one key
 * certified several ways, and a leaf issued by X. Every certificate carries key identifiers and a label, so a
 * built path reads as labels. Fresh keys per instance; validity relative to the time of creation.
 */
final class AlternativeIssuerFixtures
{
    private static final long DAY = 86400000L;

    /** One case: the pool a builder searches, the CRLs (empty when revocation is off), the target. */
    static final class Case
    {
        final String name;
        final List<X509Certificate> pool;
        final List<X509CRL> crls;

        Case(String name, List<X509Certificate> pool, List<X509CRL> crls)
        {
            this.name = name;
            this.pool = Collections.unmodifiableList(new ArrayList<X509Certificate>(pool));
            this.crls = Collections.unmodifiableList(new ArrayList<X509CRL>(crls));
        }

        boolean revocation()
        {
            return !crls.isEmpty();
        }
    }

    private final KeyPairGenerator kpg;
    private final long now = System.currentTimeMillis();
    private final Map<BigInteger, String> labels = new HashMap<BigInteger, String>();
    private long serial = 100;

    final KeyPair a;
    final KeyPair b;
    final KeyPair c;
    final KeyPair x;
    final KeyPair y;
    final X509Certificate rootA;
    final X509Certificate leaf;
    final X509Certificate xByA;
    final X509Certificate xByA2;
    final X509Certificate xByB;
    final X509Certificate xByC;
    final X509Certificate bByX;
    final X509Certificate xByAExpired;
    final X509Certificate xByBExpired;
    final X509CRL crlOfARevokingXByA;
    final X509CRL crlOfX;
    /** CA Y, issued by Root A, and a certificate of CA X's key issued by CA Y: a route of two. */
    final X509Certificate yByA;
    final X509Certificate xByY;
    /**
     * A route of three that counts ONE non-self-issued intermediate: two self-issued certificates of CA X (a key
     * rollover, x signed by x1, then x1 signed by x2) under a certificate of x2 issued by Root A.
     */
    final X509Certificate xSelfIssued1;
    final X509Certificate xSelfIssued2;
    final X509Certificate x2ByA;

    AlternativeIssuerFixtures() throws Exception
    {
        kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(256);
        a = kpg.generateKeyPair();
        b = kpg.generateKeyPair();
        c = kpg.generateKeyPair();
        x = kpg.generateKeyPair();
        y = kpg.generateKeyPair();
        rootA = cert("RootA", "CN=Root A", a, "CN=Root A", a, true, -1, 3650);
        leaf = cert("leaf", "CN=CA X", x, "CN=leaf", kpg.generateKeyPair(), false, -1, 30);
        xByA = cert("X_byA", "CN=Root A", a, "CN=CA X", x, true, -1, 365);
        xByA2 = cert("X_byA#2", "CN=Root A", a, "CN=CA X", x, true, -1, 365);
        xByB = cert("X_byB", "CN=Root B", b, "CN=CA X", x, true, -1, 365);
        xByC = cert("X_byC", "CN=Root C", c, "CN=CA X", x, true, -1, 365);
        bByX = cert("B_byX", "CN=CA X", x, "CN=Root B", b, true, -1, 365);
        xByAExpired = cert("X_byA_expired", "CN=Root A", a, "CN=CA X", x, true, -30, -1);
        xByBExpired = cert("X_byB_expired", "CN=Root B", b, "CN=CA X", x, true, -30, -1);
        crlOfARevokingXByA = crl("CN=Root A", a, xByA.getSerialNumber());
        crlOfX = crl("CN=CA X", x);
        yByA = cert("Y_byA", "CN=Root A", a, "CN=CA Y", y, true, -1, 365);
        xByY = cert("X_byY", "CN=CA Y", y, "CN=CA X", x, true, -1, 365);
        KeyPair x1 = kpg.generateKeyPair();
        KeyPair x2 = kpg.generateKeyPair();
        xSelfIssued1 = cert("X_selfIssued1", "CN=CA X", x1, "CN=CA X", x, true, -1, 365);
        xSelfIssued2 = cert("X_selfIssued2", "CN=CA X", x2, "CN=CA X", x1, true, -1, 365);
        x2ByA = cert("X2_byA", "CN=Root A", a, "CN=CA X", x2, true, -1, 365);
    }

    /** n further leaves issued by CA X, named leaf0 to leaf(n-1). */
    List<X509Certificate> leaves(int n) throws Exception
    {
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        for (int i = 0; i < n; i++)
        {
            out.add(cert("leaf" + i, "CN=CA X", x, "CN=leaf " + i, kpg.generateKeyPair(), false, -1, 30));
        }
        return out;
    }

    /** The cases measured for the builder, in a fixed order. */
    Map<String, Case> cases()
    {
        List<X509CRL> none = Collections.emptyList();
        List<X509CRL> revoking = Arrays.asList(crlOfARevokingXByA, crlOfX);
        Map<String, Case> out = new LinkedHashMap<String, Case>();
        put(out, new Case("two alternatives, one valid", Arrays.asList(leaf, xByA, xByB), none));
        put(out, new Case("three alternatives, one valid", Arrays.asList(leaf, xByA, xByB, xByC), none));
        put(out, new Case("a cross-certificate loop beside the trusted route",
                Arrays.asList(leaf, xByA, xByB, bByX), none));
        put(out, new Case("a cross-certificate loop with no trusted route", Arrays.asList(leaf, xByB, bByX), none));
        put(out, new Case("the trusted-route copy expired", Arrays.asList(leaf, xByAExpired, xByB), none));
        put(out, new Case("the untrusted copy expired", Arrays.asList(leaf, xByA, xByBExpired), none));
        put(out, new Case("two trusted-route copies, both valid", Arrays.asList(leaf, xByA, xByA2), none));
        put(out, new Case("one trusted-route copy revoked", Arrays.asList(leaf, xByA, xByA2), revoking));
        put(out, new Case("the trusted-route copy revoked, an untrusted alternative",
                Arrays.asList(leaf, xByA, xByB), revoking));
        put(out, new Case("no valid alternative", Arrays.asList(leaf, xByB, xByC), none));
        return out;
    }

    private static void put(Map<String, Case> out, Case c)
    {
        out.put(c.name, c);
    }

    /**
     * n further certificates of CA X's key, each issued by its own untrusted root: genuine alternatives that can
     * never reach Root A.
     */
    List<X509Certificate> untrustedAlternatives(int n) throws Exception
    {
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        for (int i = 0; i < n; i++)
        {
            KeyPair root = kpg.generateKeyPair();
            out.add(cert("X_byUntrusted" + i, "CN=Untrusted " + i, root, "CN=CA X", x, true, -1, 365));
        }
        return out;
    }

    /**
     * n certificates naming CA X as subject and Root A as issuer, with Root A's key identifier as their
     * authority key identifier and CA X's as their subject key identifier, but signed by another key: they
     * claim the trusted route and cannot validate.
     */
    List<X509Certificate> forgedAnchorClaims(int n) throws Exception
    {
        return forgedAnchorClaims(n, 365);
    }

    /** As {@link #forgedAnchorClaims(int)}, valid until the given number of days from now. */
    List<X509Certificate> forgedAnchorClaims(int n, long toDays) throws Exception
    {
        byte[] aSki = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(a.getPublic()).getKeyIdentifier();
        byte[] xSki = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(x.getPublic()).getKeyIdentifier();
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        for (int i = 0; i < n; i++)
        {
            out.add(cert("forgedByA" + i, "CN=Root A", kpg.generateKeyPair(), "CN=CA X", x, true, -1, toDays,
                    xSki, aSki));
        }
        return out;
    }

    /**
     * n certificates naming CA X as subject with CA X's subject key identifier but another key, each issued
     * by its own untrusted root: they match the leaf's authority key identifier and cannot verify its signature.
     */
    List<X509Certificate> foreignKeyDecoys(int n) throws Exception
    {
        byte[] xSki = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(x.getPublic()).getKeyIdentifier();
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        for (int i = 0; i < n; i++)
        {
            KeyPair root = kpg.generateKeyPair();
            byte[] rootSki = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(root.getPublic())
                    .getKeyIdentifier();
            out.add(cert("decoy" + i, "CN=Decoy Root " + i, root, "CN=CA X", kpg.generateKeyPair(), true, -1, 365,
                    xSki, rootSki));
        }
        return out;
    }

    /**
     * n leaves naming CA X as issuer, with CA X's key identifier as their authority key identifier, but signed
     * by other keys: targets no path can reach.
     */
    List<X509Certificate> forgedLeaves(int n) throws Exception
    {
        byte[] xSki = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(x.getPublic()).getKeyIdentifier();
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        for (int i = 0; i < n; i++)
        {
            KeyPair keys = kpg.generateKeyPair();
            byte[] ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keys.getPublic()).getKeyIdentifier();
            out.add(cert("forgedLeaf" + i, "CN=CA X", kpg.generateKeyPair(), "CN=forged leaf " + i, keys, false, -1,
                    30, ski, xSki));
        }
        return out;
    }

    /**
     * A certificate with CA X's subject, issued and signed by Root A, carrying the given SubjectPublicKeyInfo
     * as it stands: for a key this provider cannot build.
     */
    X509Certificate withSubjectPublicKeyInfo(String label, SubjectPublicKeyInfo spki) throws Exception
    {
        BigInteger sn = BigInteger.valueOf(serial++);
        labels.put(sn, label);
        X509v3CertificateBuilder bld = new X509v3CertificateBuilder(new X500Name("CN=Root A"), sn,
                new Date(now - DAY), new Date(now + 365 * DAY), new X500Name("CN=CA X"), spki);
        bld.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(a.getPublic()).getKeyIdentifier()));
        bld.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        bld.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        // Decoded by JSL's factory: the JDK's refuses some of these keys at parse time.
        return (X509Certificate) CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME)
                .generateCertificate(new ByteArrayInputStream(
                        bld.build(new JcaContentSignerBuilder("SHA256withECDSA").build(a.getPrivate())).getEncoded()));
    }

    /** The label of a certificate made here, or its serial when it was not. */
    String label(Certificate cert)
    {
        BigInteger sn = ((X509Certificate) cert).getSerialNumber();
        String l = labels.get(sn);
        return l == null ? "serial " + sn : l;
    }

    /** A path as its labels, target first. */
    List<String> labels(CertPath path)
    {
        List<String> out = new ArrayList<String>();
        for (Certificate cert : path.getCertificates())
        {
            out.add(label(cert));
        }
        return out;
    }

    private X509Certificate cert(String label, String issuer, KeyPair signer, String subject, KeyPair keys,
            boolean ca, long fromDays, long toDays) throws Exception
    {
        JcaX509ExtensionUtils u = new JcaX509ExtensionUtils();
        return cert(label, issuer, signer, subject, keys, ca, fromDays, toDays,
                u.createSubjectKeyIdentifier(keys.getPublic()).getKeyIdentifier(),
                u.createSubjectKeyIdentifier(signer.getPublic()).getKeyIdentifier());
    }

    private X509Certificate cert(String label, String issuer, KeyPair signer, String subject, KeyPair keys,
            boolean ca, long fromDays, long toDays, byte[] ski, byte[] aki) throws Exception
    {
        BigInteger sn = BigInteger.valueOf(serial++);
        labels.put(sn, label);
        JcaX509v3CertificateBuilder bld = new JcaX509v3CertificateBuilder(new X500Name(issuer), sn,
                new Date(now + fromDays * DAY), new Date(now + toDays * DAY), new X500Name(subject),
                keys.getPublic());
        bld.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(ski));
        bld.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(aki));
        if (ca)
        {
            bld.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            bld.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        else
        {
            bld.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        }
        return new JcaX509CertificateConverter().getCertificate(
                bld.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())));
    }

    private X509CRL crl(String issuer, KeyPair signer, BigInteger... revoked) throws Exception
    {
        X509v2CRLBuilder bld = new X509v2CRLBuilder(new X500Name(issuer), new Date(now - DAY));
        bld.setNextUpdate(new Date(now + 7 * DAY));
        for (BigInteger r : revoked)
        {
            bld.addCRLEntry(r, new Date(now - DAY), CRLReason.keyCompromise);
        }
        bld.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signer.getPublic()));
        bld.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        return new JcaX509CRLConverter().getCRL(
                bld.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())));
    }
}
