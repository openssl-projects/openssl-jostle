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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.certpath.CertPathNI;
import org.openssl.jostle.jcajce.provider.certpath.JostleCertPathBuilderSpi;
import org.openssl.jostle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * The PKIX builder over pools built to defeat it: decoys from a subordinate CA a trusted anchor really issued,
 * decoys signed by a subscriber's end-entity key, decoys beyond a path-length constraint, combinations that
 * spend the whole bound, and mutually signed end entities that would make the ordering quadratic. Each pool
 * reaches the builders through an order-keeping store, in several orders. Also the boundary seams: the OpenSSL
 * calls of one build, recorded, must carry the same certificates every time.
 */
public class HostilePoolAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String[] PROVIDERS = {JSL, "SUN", BC};
    private static final String NO_PATH = "no path could be built to any matching target";
    /** The builder's retry bound for one build, pinned: the pool limit. */
    private static final int RETRIES = 256;
    private static final long DAY = 86400000L;

    private static KeyPairGenerator kpg;
    private static JcaX509ExtensionUtils ids;
    private static long serial = 1000;

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

    private static byte[] ski(PublicKey key)
    {
        return ids.createSubjectKeyIdentifier(key).getKeyIdentifier();
    }

    /** What a certificate made here carries beyond its names, key and signer. */
    private static final class Shape
    {
        boolean ca;
        int pathLen = -1;
        boolean poisoned;
        long toDays = 365;
        byte[] subjectKeyId;
    }

    private static Shape ca()
    {
        Shape s = new Shape();
        s.ca = true;
        return s;
    }

    private static Shape endEntity()
    {
        return new Shape();
    }

    /**
     * A certificate decoded by JSL's factory. A poisoned certificate carries an extension no validator knows,
     * marked critical, so every validator must refuse it.
     */
    private static X509Certificate cert(String issuer, KeyPair signer, String subject, PublicKey key, Shape shape)
            throws Exception
    {
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(serial++), new Date(now - DAY), new Date(now + shape.toDays * DAY),
                new X500Name(subject), key);
        b.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(shape.subjectKeyId != null ? shape.subjectKeyId : ski(key)));
        b.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(ski(signer.getPublic())));
        if (shape.ca)
        {
            b.addExtension(Extension.basicConstraints, true,
                    shape.pathLen >= 0 ? new BasicConstraints(shape.pathLen) : new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        else
        {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        }
        if (shape.poisoned)
        {
            b.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"), true, new DEROctetString(new byte[]{1}));
        }
        byte[] der = b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())).getEncoded();
        return (X509Certificate) CertificateFactory.getInstance("X.509", JSL)
                .generateCertificate(new ByteArrayInputStream(der));
    }

    /** Root A (trusted), CA Y under it, CA X under CA Y, and a leaf of CA X: the real route of two. */
    private static final class World
    {
        final KeyPair a = kpg.generateKeyPair();
        final KeyPair y = kpg.generateKeyPair();
        final KeyPair x = kpg.generateKeyPair();
        final X509Certificate rootA;
        final X509Certificate yByA;
        final X509Certificate xByY;
        final X509Certificate leaf;

        World() throws Exception
        {
            rootA = cert("CN=Root A", a, "CN=Root A", a.getPublic(), ca());
            yByA = cert("CN=Root A", a, "CN=CA Y", y.getPublic(), ca());
            xByY = cert("CN=CA Y", y, "CN=CA X", x.getPublic(), ca());
            leaf = cert("CN=CA X", x, "CN=leaf", kpg.generateKeyPair().getPublic(), endEntity());
        }

        List<X509Certificate> realRoute()
        {
            return Arrays.asList(leaf, xByY, yByA);
        }
    }

    /** A build's outcome: the issuers' names of the path, target first, or the failure's message. */
    private static String build(String provider, X509Certificate anchor, List<X509Certificate> pool,
            X509Certificate target) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        List<Object> objects = new ArrayList<Object>();
        for (X509Certificate c : pool)
        {
            objects.add(cf.generateCertificate(new ByteArrayInputStream(c.getEncoded())));
        }
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(target.getEncoded())));
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(
                (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(anchor.getEncoded())), null)), sel);
        p.setRevocationEnabled(false);
        p.addCertStore(OrderedCertStores.ordered(objects));
        try
        {
            CertPath path = CertPathBuilder.getInstance("PKIX", provider).build(p).getCertPath();
            List<String> issuers = new ArrayList<String>();
            for (Certificate c : path.getCertificates())
            {
                issuers.add(((X509Certificate) c).getIssuerX500Principal().getName());
            }
            return issuers.toString();
        }
        catch (CertPathBuilderException e)
        {
            return "fails: " + e.getMessage();
        }
    }

    private static final String REAL = "[CN=CA X, CN=CA Y, CN=Root A]";

    /** The pool in store order, reversed, and seeded shuffles; the seed is in every failure message. */
    private static List<List<X509Certificate>> orderings(List<X509Certificate> pool, long seed)
    {
        List<List<X509Certificate>> out = new ArrayList<List<X509Certificate>>();
        out.add(new ArrayList<X509Certificate>(pool));
        List<X509Certificate> reversed = new ArrayList<X509Certificate>(pool);
        Collections.reverse(reversed);
        out.add(reversed);
        Random r = new Random(seed);
        for (int i = 0; i < 6; i++)
        {
            List<X509Certificate> s = new ArrayList<X509Certificate>(pool);
            Collections.shuffle(s, r);
            out.add(s);
        }
        return out;
    }

    /** Every provider builds the real route on every ordering tried; JSL's time is printed for the record. */
    private static void realRouteBuildsEverywhere(String what, World w, List<X509Certificate> pool) throws Exception
    {
        long seed = new SecureRandom().nextLong();
        for (List<X509Certificate> order : orderings(pool, seed))
        {
            for (String p : PROVIDERS)
            {
                long t0 = System.nanoTime();
                String got = build(p, w.rootA, order, w.leaf);
                if (JSL.equals(p))
                {
                    System.out.printf("[hostile] %s, %d certificates: JSL %.0f ms%n", what, pool.size(),
                            (System.nanoTime() - t0) / 1e6);
                }
                Assertions.assertEquals(REAL, got, p + ", " + what + ", seed " + seed);
            }
        }
    }

    /**
     * A subordinate CA genuinely issued by Root A mints n certificates of CA X's own key with a later notAfter,
     * unusable as issuers (cA false). They cannot issue, so they are tried after every certificate that can:
     * every provider builds the real route of two.
     */
    @Test
    public void decoysThatCannotIssueFromARealSubordinate() throws Exception
    {
        for (int n : new int[]{17, 120})
        {
            World w = new World();
            KeyPair evil = kpg.generateKeyPair();
            List<X509Certificate> pool = new ArrayList<X509Certificate>(w.realRoute());
            pool.add(cert("CN=Root A", w.a, "CN=Evil Sub", evil.getPublic(), ca()));
            Shape decoy = endEntity();
            decoy.toDays = 3000;
            for (int i = 0; i < n; i++)
            {
                pool.add(cert("CN=Evil Sub", evil, "CN=CA X", w.x.getPublic(), decoy));
            }
            realRouteBuildsEverywhere(n + " non-issuer decoys from a real subordinate", w, pool);
        }
    }

    /**
     * The same subordinate with pathLenConstraint 0 mints n CA certificates of CA X's key (cA true): a CA below it
     * is beyond its path length, so they cannot issue on that route and are tried after the real one.
     */
    @Test
    public void decoysBeyondAPathLengthConstraint() throws Exception
    {
        for (int n : new int[]{17, 120})
        {
            World w = new World();
            KeyPair evil = kpg.generateKeyPair();
            Shape sub = ca();
            sub.pathLen = 0;
            List<X509Certificate> pool = new ArrayList<X509Certificate>(w.realRoute());
            pool.add(cert("CN=Root A", w.a, "CN=Evil Sub", evil.getPublic(), sub));
            Shape decoy = ca();
            decoy.toDays = 3000;
            for (int i = 0; i < n; i++)
            {
                pool.add(cert("CN=Evil Sub", evil, "CN=CA X", w.x.getPublic(), decoy));
            }
            realRouteBuildsEverywhere(n + " CA decoys beyond a path length of 0", w, pool);
        }
    }

    /**
     * A subscriber holds an ordinary end-entity certificate from Root A and signs certificates naming CA X as
     * subject, copying CA X's key identifier, with a later notAfter. An end-entity key extends no route, so the
     * decoys have none, and every provider builds the real route.
     */
    @Test
    public void decoysSignedByASubscriber() throws Exception
    {
        World w = new World();
        KeyPair subscriber = kpg.generateKeyPair();
        List<X509Certificate> pool = new ArrayList<X509Certificate>(w.realRoute());
        pool.add(cert("CN=Root A", w.a, "CN=Subscriber", subscriber.getPublic(), endEntity()));
        Shape decoy = ca();
        decoy.toDays = 3000;
        decoy.subjectKeyId = ski(w.x.getPublic());
        for (int i = 0; i < 40; i++)
        {
            pool.add(cert("CN=Subscriber", subscriber, "CN=CA X", kpg.generateKeyPair().getPublic(), decoy));
        }
        realRouteBuildsEverywhere("40 decoys signed by a subscriber", w, pool);
    }

    /**
     * The residual a party made a CA by a trusted anchor holds, measured: CA-usable decoys that every validator
     * must refuse (an unknown critical extension), at the real route's length, from the subordinate itself (route
     * two) and from one new subordinate each (route three). JSL walks past them within its bound; SUN and
     * BouncyCastle build too.
     */
    @Test
    public void caUsableDecoysFromARealSubordinateAtTheRealRoutesLength() throws Exception
    {
        for (int n : new int[]{17, 120})
        {
            World w = new World();
            KeyPair evil = kpg.generateKeyPair();
            List<X509Certificate> pool = new ArrayList<X509Certificate>(w.realRoute());
            pool.add(cert("CN=Root A", w.a, "CN=Evil Sub", evil.getPublic(), ca()));
            Shape poisoned = ca();
            poisoned.poisoned = true;
            poisoned.toDays = 3000;
            for (int i = 0; i < n; i++)
            {
                pool.add(cert("CN=Evil Sub", evil, "CN=CA X", w.x.getPublic(), poisoned));
            }
            realRouteBuildsEverywhere(n + " poisoned CA decoys at route two", w, pool);
        }
        World w = new World();
        KeyPair z = kpg.generateKeyPair();
        KeyPair evil = kpg.generateKeyPair();
        X509Certificate zByY = cert("CN=CA Y", w.y, "CN=CA Z", z.getPublic(), ca());
        X509Certificate xByZ = cert("CN=CA Z", z, "CN=CA X", w.x.getPublic(), ca());
        List<X509Certificate> pool = new ArrayList<X509Certificate>(Arrays.asList(w.leaf, xByZ, zByY, w.yByA));
        pool.add(cert("CN=Root A", w.a, "CN=Evil Sub", evil.getPublic(), ca()));
        Shape poisoned = ca();
        poisoned.poisoned = true;
        poisoned.toDays = 3000;
        for (int i = 0; i < 60; i++)
        {
            KeyPair s = kpg.generateKeyPair();
            pool.add(cert("CN=Evil Sub", evil, "CN=Evil Sub " + i, s.getPublic(), ca()));
            pool.add(cert("CN=Evil Sub " + i, s, "CN=CA X", w.x.getPublic(), poisoned));
        }
        for (String p : PROVIDERS)
        {
            Assertions.assertEquals("[CN=CA X, CN=CA Z, CN=CA Y, CN=Root A]", build(p, w.rootA, pool, w.leaf),
                    p + ", route three");
        }
    }

    /**
     * The path length a certificate may use is the largest any verified route allows. CA Y is certified twice:
     * by Root A with pathLenConstraint 0 (route one) and by Root B, itself under Root A, with none (route two).
     * CA C, issued by CA Y's key, is reached first through the constrained certificate, where it could not issue;
     * through Root B it can, so CA X under CA C has a route. Forty forged certificates of CA X with a later notAfter
     * and no route are tried after it: every provider builds leaf, X, C, Y by B, B by A.
     */
    @Test
    public void aLargerPathLengthFromALongerRouteStillCounts() throws Exception
    {
        KeyPair a = kpg.generateKeyPair();
        KeyPair b = kpg.generateKeyPair();
        KeyPair y = kpg.generateKeyPair();
        KeyPair c = kpg.generateKeyPair();
        KeyPair x = kpg.generateKeyPair();
        X509Certificate rootA = cert("CN=Root A", a, "CN=Root A", a.getPublic(), ca());
        Shape zero = ca();
        zero.pathLen = 0;
        List<X509Certificate> pool = new ArrayList<X509Certificate>();
        X509Certificate leaf = cert("CN=CA X", x, "CN=leaf", kpg.generateKeyPair().getPublic(), endEntity());
        pool.add(leaf);
        pool.add(cert("CN=CA C", c, "CN=CA X", x.getPublic(), ca()));
        pool.add(cert("CN=CA Y", y, "CN=CA C", c.getPublic(), ca()));
        pool.add(cert("CN=Root A", a, "CN=CA Y", y.getPublic(), zero));
        pool.add(cert("CN=Root B", b, "CN=CA Y", y.getPublic(), ca()));
        pool.add(cert("CN=Root A", a, "CN=Root B", b.getPublic(), ca()));
        Shape forged = ca();
        forged.toDays = 3000;
        forged.subjectKeyId = ski(x.getPublic());
        for (int i = 0; i < 40; i++)
        {
            pool.add(cert("CN=Root A", kpg.generateKeyPair(), "CN=CA X", kpg.generateKeyPair().getPublic(),
                    forged));
        }
        long seed = new SecureRandom().nextLong();
        for (List<X509Certificate> order : orderings(pool, seed))
        {
            for (String p : PROVIDERS)
            {
                Assertions.assertEquals("[CN=CA X, CN=CA C, CN=CA Y, CN=Root B, CN=Root A]",
                        build(p, rootA, order, leaf), p + ", seed " + seed);
            }
            // CA X has a route, so none of the forged certificates is tried: the constrained CA Y is tried once,
            // fails, is demoted, and the path through Root B builds on its retry.
            Recording rec = new Recording();
            Assertions.assertEquals("built", rec.build(rootA, order, leaf));
            Assertions.assertEquals(2, rec.untrusted.size(), "seed " + seed);
        }
    }

    /**
     * Certificates that cannot issue, at a route STRICTLY SHORTER than the real issuer's: a real subordinate of
     * Root A (route one) mints n certificates of CA X's key that cannot issue (route two), while the real CA X is
     * at route three. The issue test comes before the route's length, so they are ordered after the real CA X and
     * the real path builds on the first OpenSSL call.
     */
    @Test
    public void nonIssuersAtAShorterRouteAreOrderedAfterTheRealIssuer() throws Exception
    {
        World w = new World();
        KeyPair z = kpg.generateKeyPair();
        KeyPair evil = kpg.generateKeyPair();
        X509Certificate zByY = cert("CN=CA Y", w.y, "CN=CA Z", z.getPublic(), ca());
        X509Certificate xByZ = cert("CN=CA Z", z, "CN=CA X", w.x.getPublic(), ca());
        int n = 30;
        List<X509Certificate> pool = new ArrayList<X509Certificate>(Arrays.asList(w.leaf, xByZ, zByY, w.yByA));
        pool.add(cert("CN=Root A", w.a, "CN=Evil Sub", evil.getPublic(), ca()));
        Shape decoy = endEntity();
        decoy.toDays = 3000;
        for (int i = 0; i < n; i++)
        {
            pool.add(cert("CN=Evil Sub", evil, "CN=CA X", w.x.getPublic(), decoy));
        }
        Recording rec = new Recording();
        Assertions.assertEquals("built", rec.build(w.rootA, pool, w.leaf));
        Assertions.assertEquals(1, rec.untrusted.size());
        for (String p : PROVIDERS)
        {
            Assertions.assertEquals("[CN=CA X, CN=CA Z, CN=CA Y, CN=Root A]", build(p, w.rootA, pool, w.leaf), p);
        }
    }

    /**
     * A forged target: a certificate with the real target's subject, issued and signed by a subscriber's
     * end-entity key, matched by the same selector. A subscriber's key gives it no route, so the real target is
     * tried first and its path is returned on the first OpenSSL call.
     */
    @Test
    public void aForgedTargetSignedByASubscriberIsTriedAfterTheRealOne() throws Exception
    {
        World w = new World();
        KeyPair subscriber = kpg.generateKeyPair();
        List<X509Certificate> pool = new ArrayList<X509Certificate>();
        pool.add(cert("CN=Root A", w.a, "CN=Subscriber", subscriber.getPublic(), endEntity()));
        Shape forged = endEntity();
        forged.toDays = 3000;
        pool.add(cert("CN=Subscriber", subscriber, "CN=leaf", kpg.generateKeyPair().getPublic(), forged));
        pool.addAll(w.realRoute());
        X509CertSelector bySubject = new X509CertSelector();
        bySubject.setSubject("CN=leaf");
        Recording rec = new Recording();
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(w.rootA, null)),
                bySubject);
        p.setRevocationEnabled(false);
        p.addCertStore(OrderedCertStores.ordered(new ArrayList<Object>(pool)));
        CertPath path = new JostleCertPathBuilderSpi(rec.ni, Security.getProvider(JSL)).engineBuild(p).getCertPath();
        Assertions.assertArrayEquals(w.leaf.getEncoded(), path.getCertificates().get(0).getEncoded());
        Assertions.assertEquals(1, rec.untrusted.size(), "the real target first, built on the first call");
    }

    /** A CertPathNI that forwards to the real one and records the untrusted certificates of every call. */
    private static final class Recording
    {
        final List<List<String>> untrusted = new ArrayList<List<String>>();
        final CertPathNI ni;

        Recording()
        {
            final CertPathNI real = NISelector.CertPathNI;
            ni = (CertPathNI) Proxy.newProxyInstance(HostilePoolAgreementTest.class.getClassLoader(),
                    new Class<?>[]{CertPathNI.class}, (proxy, m, args) -> {
                        if ("ni_verify".equals(m.getName()))
                        {
                            byte[] der = (byte[]) args[0];
                            int[] sizes = (int[]) args[1];
                            int count = (Integer) args[2];
                            int anchors = (Integer) args[4];
                            int off = 0;
                            List<String> call = new ArrayList<String>();
                            for (int i = 0; i < count; i++)
                            {
                                if (i >= anchors && i < count - 1)
                                {
                                    call.add(Hex.toHexString(Arrays.copyOfRange(der, off, off + sizes[i])));
                                }
                                off += sizes[i];
                            }
                            untrusted.add(call);
                        }
                        try
                        {
                            return m.invoke(real, args);
                        }
                        catch (InvocationTargetException e)
                        {
                            throw e.getCause();
                        }
                    });
        }

        String build(X509Certificate anchor, List<X509Certificate> pool, X509Certificate target) throws Exception
        {
            X509CertSelector sel = new X509CertSelector();
            sel.setCertificate(target);
            PKIXBuilderParameters p = new PKIXBuilderParameters(
                    Collections.singleton(new TrustAnchor(anchor, null)), sel);
            p.setRevocationEnabled(false);
            p.addCertStore(OrderedCertStores.ordered(new ArrayList<Object>(pool)));
            try
            {
                new JostleCertPathBuilderSpi(ni, Security.getProvider(JSL)).engineBuild(p);
                return "built";
            }
            catch (CertPathBuilderException e)
            {
                return e.getMessage();
            }
        }
    }

    /**
     * fan certificates of CA X's key under CA Y, and fan of CA Y's key under untrusted roots: fan x fan chains,
     * none reaching Root A.
     */
    private static List<X509Certificate> fan(World w, int fan) throws Exception
    {
        List<X509Certificate> pool = new ArrayList<X509Certificate>();
        pool.add(w.leaf);
        for (int i = 0; i < fan; i++)
        {
            Shape s = ca();
            s.toDays = 365 + i;
            pool.add(cert("CN=CA Y", w.y, "CN=CA X", w.x.getPublic(), s));
            KeyPair r = kpg.generateKeyPair();
            pool.add(cert("CN=Untrusted " + i, r, "CN=CA Y", w.y.getPublic(), s));
        }
        return pool;
    }

    /**
     * Demotion keeps the revocation evidence the same on every attempt: across all the OpenSSL calls of one build,
     * the untrusted certificates handed over are the same multiset, and only their order differs.
     */
    @Test
    public void everyAttemptHandsOpenSslTheSameCertificates() throws Exception
    {
        World w = new World();
        Recording rec = new Recording();
        Assertions.assertEquals(NO_PATH, rec.build(w.rootA, fan(w, 4), w.leaf));
        Assertions.assertEquals(16, rec.untrusted.size(), "four by four chains, one call each");
        List<String> first = new ArrayList<String>(rec.untrusted.get(0));
        Collections.sort(first);
        boolean reordered = false;
        for (List<String> call : rec.untrusted)
        {
            List<String> sorted = new ArrayList<String>(call);
            Collections.sort(sorted);
            Assertions.assertEquals(first, sorted, "the same certificates on every attempt");
            reordered |= !call.equals(rec.untrusted.get(0));
        }
        Assertions.assertTrue(reordered, "the attempts differ in order");
    }

    /**
     * The bound is the pool limit in retries for one build. Sixteen by sixteen chains exhaust in exactly 256 calls,
     * one first attempt and 255 retries, and fail plainly; seventeen by seventeen need more, so the search stops
     * at 257 calls and the failure names the bound.
     */
    @Test
    public void theRetryBoundIsThePoolLimit() throws Exception
    {
        World w = new World();
        Recording sixteen = new Recording();
        Assertions.assertEquals(NO_PATH, sixteen.build(w.rootA, fan(w, 16), w.leaf));
        Assertions.assertEquals(256, sixteen.untrusted.size());
        Recording seventeen = new Recording();
        Assertions.assertEquals(NO_PATH + "; the search stopped at its bound of " + RETRIES + " retries for one build",
                seventeen.build(w.rootA, fan(w, 17), w.leaf));
        Assertions.assertEquals(RETRIES + 1, seventeen.untrusted.size());

        // Every matched target keeps its first call: two end entities of CA X over the same fan, one of them
        // spends the retries, and the other is still tried once.
        List<X509Certificate> pool = fan(w, 17);
        pool.add(cert("CN=CA X", w.x, "CN=second leaf", kpg.generateKeyPair().getPublic(), endEntity()));
        X509CertSelector endEntities = new X509CertSelector();
        endEntities.setBasicConstraints(-2);
        Recording two = new Recording();
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(w.rootA, null)),
                endEntities);
        p.setRevocationEnabled(false);
        p.addCertStore(OrderedCertStores.ordered(new ArrayList<Object>(pool)));
        try
        {
            new JostleCertPathBuilderSpi(two.ni, Security.getProvider(JSL)).engineBuild(p);
            Assertions.fail("no path exists");
        }
        catch (CertPathBuilderException e)
        {
            Assertions.assertEquals(NO_PATH + "; the search stopped at its bound of " + RETRIES
                    + " retries for one build", e.getMessage());
        }
        Assertions.assertEquals(RETRIES + 2, two.untrusted.size(), "the second target's first call is made");
    }

    /**
     * The ordering's verifications grow linearly with mutually signed end entities: n end-entity certificates
     * sharing one name, each signed by the previous one's key, the first by Root A. An end-entity key extends
     * no route, so only the anchor's candidates are tried: one verification per certificate naming it. The count
     * and the time are printed for the record.
     */
    @Test
    public void mutuallySignedEndEntitiesCostLinearly() throws Exception
    {
        int[] sizes = {50, 100, 200};
        int[] counts = new int[sizes.length];
        for (int k = 0; k < sizes.length; k++)
        {
            World w = new World();
            List<X509Certificate> pool = new ArrayList<X509Certificate>(w.realRoute());
            KeyPair previous = w.a;
            String previousName = "CN=Root A";
            for (int i = 0; i < sizes[k]; i++)
            {
                KeyPair next = kpg.generateKeyPair();
                pool.add(cert(previousName, previous, "CN=Shared", next.getPublic(), endEntity()));
                previous = next;
                previousName = "CN=Shared";
            }
            X509CertSelector sel = new X509CertSelector();
            sel.setCertificate(w.leaf);
            PKIXBuilderParameters p = new PKIXBuilderParameters(
                    Collections.singleton(new TrustAnchor(w.rootA, null)), sel);
            p.setRevocationEnabled(false);
            p.addCertStore(OrderedCertStores.ordered(new ArrayList<Object>(pool)));
            CountingJslProvider.VERIFICATIONS.set(0);
            long t0 = System.nanoTime();
            new JostleCertPathBuilderSpi(NISelector.CertPathNI, new CountingJslProvider()).engineBuild(p);
            counts[k] = CountingJslProvider.VERIFICATIONS.get();
            System.out.printf("[hostile] %d mutually signed end entities: %d verifications, %.0f ms%n", sizes[k],
                    counts[k], (System.nanoTime() - t0) / 1e6);
            // The counter moved, so the builder's verifications did go through it.
            Assertions.assertTrue(counts[k] > 0, "no verification was counted");
            Assertions.assertTrue(counts[k] <= 2 * (pool.size() + 2),
                    sizes[k] + " end entities cost " + counts[k] + " verifications");
        }
        Assertions.assertTrue(counts[2] < 3 * counts[1], "doubling the pool did not double the work: "
                + Arrays.toString(counts));
    }

    /**
     * A ladder: a real subordinate of Root A issues k certificates of one key and one name with pathLenConstraint
     * 1 to k, in increasing order in the store, and beneath that key a chain of m CA certificates sharing one name,
     * each signed by the previous one's key. Each certificate's path length is settled once, largest first, so
     * nothing is expanded twice: the verifications stay within the pool size squared, the time is printed for the
     * record, and the real route still builds.
     */
    @Test
    public void aPathLengthLadderIsSettledOnce() throws Exception
    {
        int k = 120;
        int m = 120;
        World w = new World();
        KeyPair evil = kpg.generateKeyPair();
        KeyPair ladder = kpg.generateKeyPair();
        List<X509Certificate> pool = new ArrayList<X509Certificate>(w.realRoute());
        pool.add(cert("CN=Root A", w.a, "CN=Evil Sub", evil.getPublic(), ca()));
        for (int i = 1; i <= k; i++)
        {
            Shape step = ca();
            step.pathLen = i;
            pool.add(cert("CN=Evil Sub", evil, "CN=Ladder", ladder.getPublic(), step));
        }
        KeyPair previous = ladder;
        String previousName = "CN=Ladder";
        for (int i = 0; i < m; i++)
        {
            KeyPair next = kpg.generateKeyPair();
            pool.add(cert(previousName, previous, "CN=Chain", next.getPublic(), ca()));
            previous = next;
            previousName = "CN=Chain";
        }
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(w.leaf);
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(w.rootA, null)),
                sel);
        p.setRevocationEnabled(false);
        p.addCertStore(OrderedCertStores.ordered(new ArrayList<Object>(pool)));
        CountingJslProvider.VERIFICATIONS.set(0);
        long t0 = System.nanoTime();
        CertPath path = new JostleCertPathBuilderSpi(NISelector.CertPathNI, new CountingJslProvider()).engineBuild(p)
                .getCertPath();
        long ms = (System.nanoTime() - t0) / 1000000L;
        int count = CountingJslProvider.VERIFICATIONS.get();
        System.out.printf("[hostile] ladder k=%d chain m=%d, %d certificates: %d verifications, %d ms%n", k, m,
                pool.size(), count, ms);
        Assertions.assertEquals(3, path.getCertificates().size());
        Assertions.assertTrue(count > 0, "no verification was counted");
        Assertions.assertTrue(count <= pool.size() * pool.size(), count + " verifications for " + pool.size());
    }

    /** The builder's verification budget for one build, pinned: eight times the pool limit. */
    private static final int VERIFICATION_BUDGET = 8 * 256;

    /** Counts the builder's signature checks for one build through the counting provider; the path is returned. */
    private static CertPath countedBuild(X509Certificate anchor, List<X509Certificate> pool, X509Certificate target)
            throws Exception
    {
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(target);
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(anchor, null)),
                sel);
        p.setRevocationEnabled(false);
        p.addCertStore(OrderedCertStores.ordered(new ArrayList<Object>(pool)));
        CountingJslProvider.VERIFICATIONS.set(0);
        return new JostleCertPathBuilderSpi(NISelector.CertPathNI, new CountingJslProvider()).engineBuild(p)
                .getCertPath();
    }

    /**
     * A real subordinate of Root A issues 128 CA certificates with DISTINCT keys and one name, each able to issue,
     * and 120 certificates name that name as their issuer: about 15,000 checks without a budget. The ordering
     * stops at the budget exactly, and the real path, whose own edges are checked first, still builds.
     */
    @Test
    public void manyRoutedIssuingKeysStopAtTheVerificationBudget() throws Exception
    {
        World w = new World();
        KeyPair evil = kpg.generateKeyPair();
        List<X509Certificate> pool = new ArrayList<X509Certificate>(w.realRoute());
        pool.add(cert("CN=Root A", w.a, "CN=Evil Sub", evil.getPublic(), ca()));
        KeyPair first = null;
        for (int i = 0; i < 128; i++)
        {
            KeyPair k = kpg.generateKeyPair();
            first = first == null ? k : first;
            pool.add(cert("CN=Evil Sub", evil, "CN=Many", k.getPublic(), ca()));
        }
        for (int i = 0; i < 120; i++)
        {
            pool.add(cert("CN=Many", first, "CN=claimant " + i, kpg.generateKeyPair().getPublic(), endEntity()));
        }
        long t0 = System.nanoTime();
        CertPath path = countedBuild(w.rootA, pool, w.leaf);
        System.out.printf("[hostile] 128 routed issuing keys, 120 claimants, %d certificates: %d checks, %d ms%n",
                pool.size(), CountingJslProvider.VERIFICATIONS.get(), (System.nanoTime() - t0) / 1000000L);
        Assertions.assertEquals(VERIFICATION_BUDGET, CountingJslProvider.VERIFICATIONS.get());
        Assertions.assertArrayEquals(w.xByY.getEncoded(), path.getCertificates().get(1).getEncoded());
    }

    /**
     * An outsider stuffs the pool to its limit with forged certificates, each naming a genuine issuer (half CA X,
     * half Root A) and signed by another key. Each costs one check against the one genuine key of the name it
     * claims: the forged certificates plus the real route's three edges, far under the budget.
     */
    @Test
    public void anOutsidersStuffedPoolSpendsOneCheckPerForgery() throws Exception
    {
        World w = new World();
        List<X509Certificate> pool = new ArrayList<X509Certificate>(w.realRoute());
        int forged = 256 - 1 - pool.size();
        for (int i = 0; i < forged; i++)
        {
            String issuer = i % 2 == 0 ? "CN=CA X" : "CN=Root A";
            pool.add(cert(issuer, kpg.generateKeyPair(), "CN=forged " + i, kpg.generateKeyPair().getPublic(),
                    endEntity()));
        }
        CertPath path = countedBuild(w.rootA, pool, w.leaf);
        System.out.printf("[hostile] outsider's stuffed pool, %d certificates: %d checks%n", pool.size(),
                CountingJslProvider.VERIFICATIONS.get());
        Assertions.assertEquals(forged + 3, CountingJslProvider.VERIFICATIONS.get());
        Assertions.assertTrue(forged + 3 < VERIFICATION_BUDGET / 4);
        Assertions.assertArrayEquals(w.xByY.getEncoded(), path.getCertificates().get(1).getEncoded());
    }

    /** With no path anywhere, every provider fails, and JSL's failure is the plain one. */
    @Test
    public void aRealSubordinatesDecoysAloneBuildNothing() throws Exception
    {
        World w = new World();
        KeyPair evil = kpg.generateKeyPair();
        List<X509Certificate> pool = new ArrayList<X509Certificate>();
        pool.add(w.leaf);
        pool.add(cert("CN=Root A", w.a, "CN=Evil Sub", evil.getPublic(), ca()));
        Shape poisoned = ca();
        poisoned.poisoned = true;
        for (int i = 0; i < 20; i++)
        {
            pool.add(cert("CN=Evil Sub", evil, "CN=CA X", w.x.getPublic(), poisoned));
        }
        for (String p : PROVIDERS)
        {
            Assertions.assertTrue(build(p, w.rootA, pool, w.leaf).startsWith("fails"), p);
        }
        Assertions.assertEquals("fails: " + NO_PATH, build(JSL, w.rootA, pool, w.leaf));
    }
}
