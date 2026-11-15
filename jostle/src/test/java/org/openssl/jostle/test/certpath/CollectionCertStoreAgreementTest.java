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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.certpath.JostleCollectionCertStoreSpi;
import org.openssl.jostle.test.cert.ProviderRegistrySnapshot;
import org.openssl.jostle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
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
import java.security.cert.LDAPCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.AbstractCollection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.ConcurrentModificationException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * JSL's Collection CertStore against the JDK's (SUN) and BouncyCastle 1.87's: the same objects for the same
 * selectors, the collection seen live, foreign objects ignored, the retry under concurrent modification, a
 * selector's exception passed through, and the parameter refusals.
 */
public class CollectionCertStoreAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static X509Certificate one;
    private static X509Certificate two;
    private static X509Certificate three;
    private static X509CRL crlA;
    private static X509CRL crlB;
    private static Date middle;

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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
        kpg.initialize(256);
        KeyPair caA = kpg.generateKeyPair();
        KeyPair caB = kpg.generateKeyPair();
        long now = System.currentTimeMillis();
        long day = 86400000L;
        middle = new Date(now + 15 * day);
        one = cert("CN=Issuer A", caA, "CN=one", 11, new Date(now - day), new Date(now + 10 * day),
                kpg.generateKeyPair());
        two = cert("CN=Issuer A", caA, "CN=two", 22, new Date(now - day), new Date(now + 30 * day),
                kpg.generateKeyPair());
        three = cert("CN=Issuer B", caB, "CN=three", 33, new Date(now + 20 * day), new Date(now + 40 * day),
                kpg.generateKeyPair());
        crlA = crl("CN=Issuer A", caA, new Date(now));
        crlB = crl("CN=Issuer B", caB, new Date(now + 5 * day));
    }

    private static X509Certificate cert(String issuer, KeyPair ca, String subject, long serial, Date from, Date to,
            KeyPair subjectKeys) throws Exception
    {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(serial), from, to, new X500Name(subject), subjectKeys.getPublic());
        b.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(subjectKeys.getPublic()));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(ca.getPrivate())));
    }

    private static X509CRL crl(String issuer, KeyPair ca, Date thisUpdate) throws Exception
    {
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(issuer), thisUpdate);
        b.setNextUpdate(new Date(thisUpdate.getTime() + 86400000L));
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(ca.getPrivate())));
    }

    private static List<Object> everything()
    {
        List<Object> coll = new ArrayList<Object>();
        coll.add(one);
        coll.add(two);
        coll.add(three);
        coll.add(crlA);
        coll.add(crlB);
        return coll;
    }

    private static CertStore store(String provider, Collection<?> coll) throws Exception
    {
        return CertStore.getInstance("Collection", new CollectionCertStoreParameters(coll),
                Security.getProvider(provider));
    }

    private static Set<String> certs(CertStore s, CertSelector sel) throws Exception
    {
        Set<String> out = new TreeSet<String>();
        for (Certificate c : s.getCertificates(sel))
        {
            out.add(Hex.toHexString(c.getEncoded()));
        }
        return out;
    }

    private static Set<String> crls(CertStore s, CRLSelector sel) throws Exception
    {
        Set<String> out = new TreeSet<String>();
        for (CRL c : s.getCRLs(sel))
        {
            out.add(Hex.toHexString(((X509CRL) c).getEncoded()));
        }
        return out;
    }

    @Test
    public void jslServesTheCollectionStoreItself() throws Exception
    {
        CertStore s = store(JSL, everything());
        Assertions.assertEquals(JSL, s.getProvider().getName());
        Assertions.assertEquals("Collection", s.getType());
    }

    /** Every selector selects the same objects from JSL's store as from SUN's and BouncyCastle's. */
    @Test
    public void selectorsAgreeWithSunAndBouncyCastle() throws Exception
    {
        selectorsAgree(everything(), everything(), everything());
    }

    /**
     * The same matrix with each store holding its own provider's objects for the same encodings, so the selectors
     * call back into JSL's certificates and CRLs in JSL's store; then once with JSL's and the JDK's objects side by
     * side in one collection.
     */
    @Test
    public void selectorsAgreeOverEachProvidersOwnObjects() throws Exception
    {
        List<Object> ours = decoded(JSL);
        for (Object o : ours)
        {
            Assertions.assertTrue(o.getClass().getName().startsWith("org.openssl.jostle."), o.getClass().getName());
        }
        selectorsAgree(ours, decoded("SUN"), decoded(BC));

        List<Object> sun = decoded("SUN");
        List<Object> mixed = new ArrayList<Object>();
        mixed.add(ours.get(0));
        mixed.add(sun.get(1));
        mixed.add(ours.get(2));
        mixed.add(sun.get(3));
        mixed.add(ours.get(4));
        selectorsAgree(mixed, mixed, mixed);
    }

    /** one, two, three, crlA and crlB re-decoded through the named provider's CertificateFactory, in that order. */
    private static List<Object> decoded(String provider) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        List<Object> out = new ArrayList<Object>();
        for (X509Certificate c : new X509Certificate[]{one, two, three})
        {
            out.add(cf.generateCertificate(new ByteArrayInputStream(c.getEncoded())));
        }
        for (X509CRL c : new X509CRL[]{crlA, crlB})
        {
            out.add(cf.generateCRL(new ByteArrayInputStream(c.getEncoded())));
        }
        return out;
    }

    private static void selectorsAgree(List<Object> jslColl, List<Object> sunColl, List<Object> bcColl)
            throws Exception
    {
        X509CertSelector bySubject = new X509CertSelector();
        bySubject.setSubject("CN=two");
        X509CertSelector byIssuer = new X509CertSelector();
        byIssuer.setIssuer("CN=Issuer A");
        X509CertSelector bySerial = new X509CertSelector();
        bySerial.setSerialNumber(BigInteger.valueOf(33));
        X509CertSelector bySki = new X509CertSelector();
        // The selector takes the extension's DER value, the OCTET STRING inside the one getExtensionValue returns.
        bySki.setSubjectKeyIdentifier(ASN1OctetString.getInstance(
                one.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets());
        X509CertSelector byDate = new X509CertSelector();
        byDate.setCertificateValid(middle);
        X509CertSelector none = new X509CertSelector();
        none.setSubject("CN=nobody");
        CertSelector[] certSelectors = {null, bySubject, byIssuer, bySerial, bySki, byDate, none};
        int[] expected = {3, 1, 2, 1, 1, 1, 0};

        X509CRLSelector byCrlIssuer = new X509CRLSelector();
        byCrlIssuer.addIssuerName("CN=Issuer B");
        X509CRLSelector byCrlDate = new X509CRLSelector();
        byCrlDate.setDateAndTime(new Date(crlA.getThisUpdate().getTime() + 1000L));
        CRLSelector[] crlSelectors = {null, byCrlIssuer, byCrlDate};
        int[] expectedCrls = {2, 1, 1};

        CertStore jsl = store(JSL, jslColl);
        CertStore sun = store("SUN", sunColl);
        CertStore bc = store(BC, bcColl);
        for (int i = 0; i < certSelectors.length; i++)
        {
            Set<String> ours = certs(jsl, certSelectors[i]);
            Assertions.assertEquals(expected[i], ours.size(), "certificate selector " + i);
            Assertions.assertEquals(certs(sun, certSelectors[i]), ours, "SUN, certificate selector " + i);
            Assertions.assertEquals(certs(bc, certSelectors[i]), ours, "BC, certificate selector " + i);
        }
        for (int i = 0; i < crlSelectors.length; i++)
        {
            Set<String> ours = crls(jsl, crlSelectors[i]);
            Assertions.assertEquals(expectedCrls[i], ours.size(), "CRL selector " + i);
            Assertions.assertEquals(crls(sun, crlSelectors[i]), ours, "SUN, CRL selector " + i);
            Assertions.assertEquals(crls(bc, crlSelectors[i]), ours, "BC, CRL selector " + i);
        }
    }

    /** Objects that are neither a certificate nor a CRL, and null elements, are ignored, as by SUN and BC. */
    @Test
    public void foreignObjectsAndNullElementsAreIgnored() throws Exception
    {
        List<Object> coll = everything();
        coll.add("not a certificate");
        coll.add(null);
        coll.add(new byte[]{1, 2, 3});
        for (String p : new String[]{JSL, "SUN", BC})
        {
            CertStore s = store(p, coll);
            Assertions.assertEquals(3, s.getCertificates(null).size(), p);
            Assertions.assertEquals(2, s.getCRLs(null).size(), p);
        }
    }

    /**
     * The collection is not copied: a later change to it is seen by the next query, as by SUN and BC, and the
     * parameters the store hands back are a copy holding the caller's collection.
     */
    @Test
    public void theStoreIsALiveViewOfTheCollection() throws Exception
    {
        for (String p : new String[]{JSL, "SUN", BC})
        {
            List<Object> coll = new ArrayList<Object>();
            coll.add(one);
            CollectionCertStoreParameters params = new CollectionCertStoreParameters(coll);
            CertStore s = CertStore.getInstance("Collection", params, Security.getProvider(p));
            Assertions.assertEquals(1, s.getCertificates(null).size(), p);
            coll.add(two);
            coll.add(crlA);
            Assertions.assertEquals(2, s.getCertificates(null).size(), p + ": an added certificate is seen");
            Assertions.assertEquals(1, s.getCRLs(null).size(), p + ": an added CRL is seen");
            coll.remove(one);
            Assertions.assertEquals(1, s.getCertificates(null).size(), p + ": a removed certificate is gone");
            CollectionCertStoreParameters back = (CollectionCertStoreParameters) s.getCertStoreParameters();
            Assertions.assertNotSame(params, back, p);
            Assertions.assertSame(coll, back.getCollection(), p);
        }
    }

    /** Each query returns a new, mutable collection; clearing it leaves the store and the caller's collection. */
    @Test
    public void queriesReturnFreshMutableCollections() throws Exception
    {
        List<Object> coll = everything();
        CertStore s = store(JSL, coll);
        Collection<? extends Certificate> first = s.getCertificates(null);
        Assertions.assertNotSame(first, s.getCertificates(null));
        first.clear();
        Collection<? extends CRL> crls = s.getCRLs(null);
        crls.clear();
        Assertions.assertEquals(3, s.getCertificates(null).size());
        Assertions.assertEquals(2, s.getCRLs(null).size());
        Assertions.assertEquals(5, coll.size());
    }

    /** A collection whose iterator throws ConcurrentModificationException on its first failFirst scans. */
    static final class Flaky extends AbstractCollection<Object>
    {
        private final int failFirst;
        int scans;

        Flaky(int failFirst)
        {
            this.failFirst = failFirst;
        }

        @Override
        public Iterator<Object> iterator()
        {
            final boolean fail = scans++ < failFirst;
            return new Iterator<Object>()
            {
                private boolean served;

                public boolean hasNext()
                {
                    return fail || !served;
                }

                public Object next()
                {
                    if (fail)
                    {
                        throw new ConcurrentModificationException("modified during the scan");
                    }
                    if (served)
                    {
                        throw new NoSuchElementException();
                    }
                    served = true;
                    return one;
                }
            };
        }

        @Override
        public int size()
        {
            return 1;
        }
    }

    /**
     * A scan that meets a concurrent modification is retried: nine failures then a clean scan succeed on the tenth;
     * ten failures exhaust it with ConcurrentModificationException, as SUN does. BouncyCastle does not retry.
     */
    @Test
    public void aConcurrentModificationIsRetriedForTenScans() throws Exception
    {
        for (String p : new String[]{JSL, "SUN"})
        {
            Flaky nine = new Flaky(9);
            CertStore s = store(p, nine);
            nine.scans = 0;
            Assertions.assertEquals(1, s.getCertificates(null).size(), p);
            Assertions.assertEquals(10, nine.scans, p);

            for (boolean crl : new boolean[]{false, true})
            {
                Flaky ten = new Flaky(10);
                CertStore t = store(p, ten);
                ten.scans = 0;
                ConcurrentModificationException e = assertThrows(ConcurrentModificationException.class,
                        () -> {
                            if (crl)
                            {
                                t.getCRLs(null);
                            }
                            else
                            {
                                t.getCertificates(null);
                            }
                        }, p);
                Assertions.assertEquals("Too many ConcurrentModificationExceptions", e.getMessage(), p);
                Assertions.assertEquals(10, ten.scans, p);
            }
        }
        Flaky once = new Flaky(1);
        CertStore bc = store(BC, once);
        once.scans = 0;
        assertThrows(ConcurrentModificationException.class, () -> bc.getCertificates(null));
        Assertions.assertEquals(1, once.scans, "BouncyCastle does not retry");
    }

    /**
     * The caller's selector is the caller's code: its exception passes through, as from SUN and BC. A selector
     * throwing ConcurrentModificationException is the one exception, pinned in its own cell.
     */
    @Test
    public void aSelectorsExceptionPassesThrough() throws Exception
    {
        CertSelector cs = new CertSelector()
        {
            public boolean match(Certificate c)
            {
                throw new IllegalStateException("cert selector says no");
            }

            public Object clone()
            {
                return this;
            }
        };
        CRLSelector rs = new CRLSelector()
        {
            public boolean match(CRL c)
            {
                throw new IllegalStateException("crl selector says no");
            }

            public Object clone()
            {
                return this;
            }
        };
        for (String p : new String[]{JSL, "SUN", BC})
        {
            CertStore s = store(p, everything());
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> s.getCertificates(cs), p);
            Assertions.assertEquals("cert selector says no", e.getMessage(), p);
            e = assertThrows(IllegalStateException.class, () -> s.getCRLs(rs), p);
            Assertions.assertEquals("crl selector says no", e.getMessage(), p);
        }
    }

    /**
     * A selector throwing ConcurrentModificationException is taken for a modification of the collection: JSL and
     * SUN retry it for ten scans and then throw their own message. BouncyCastle passes it through on the first.
     */
    @Test
    public void aSelectorsConcurrentModificationIsRetriedAsAModification() throws Exception
    {
        for (String p : new String[]{JSL, "SUN", BC})
        {
            final int[] calls = new int[1];
            CertSelector cs = new CertSelector()
            {
                public boolean match(Certificate c)
                {
                    calls[0]++;
                    throw new ConcurrentModificationException("selector's own");
                }

                public Object clone()
                {
                    return this;
                }
            };
            List<Object> single = new ArrayList<Object>();
            single.add(one);
            CertStore s = store(p, single);
            ConcurrentModificationException e = assertThrows(ConcurrentModificationException.class,
                    () -> s.getCertificates(cs), p);
            if (BC.equals(p))
            {
                Assertions.assertEquals("selector's own", e.getMessage(), p);
                Assertions.assertEquals(1, calls[0], p);
            }
            else
            {
                Assertions.assertEquals("Too many ConcurrentModificationExceptions", e.getMessage(), p);
                Assertions.assertEquals(10, calls[0], p);
            }
        }
    }

    /**
     * Over a CopyOnWriteArrayList changed by another thread during the queries, every query returns without an
     * exception and selects a subset of the objects the collection ever held. A smoke cell, not a proof: a
     * copy-on-write iterator never throws, so this catches a store that indexes the live collection only when the
     * race lands.
     */
    @Test
    public void aCopyOnWriteCollectionChangedDuringQueriesIsSafe() throws Exception
    {
        Set<String> union = new TreeSet<String>();
        for (X509Certificate c : new X509Certificate[]{one, two, three})
        {
            union.add(Hex.toHexString(c.getEncoded()));
        }
        for (String p : new String[]{JSL, "SUN"})
        {
            final CopyOnWriteArrayList<Object> coll = new CopyOnWriteArrayList<Object>();
            coll.add(one);
            CertStore s = store(p, coll);
            final AtomicBoolean stop = new AtomicBoolean();
            Thread writer = new Thread(() -> {
                while (!stop.get())
                {
                    coll.add(two);
                    coll.add(three);
                    coll.remove(two);
                    coll.remove(three);
                }
            });
            writer.start();
            try
            {
                for (int i = 0; i < 500; i++)
                {
                    Set<String> got = certs(s, null);
                    Assertions.assertTrue(got.contains(Hex.toHexString(one.getEncoded())), p);
                    Assertions.assertTrue(union.containsAll(got), p);
                }
            }
            finally
            {
                stop.set(true);
                writer.join();
            }
        }
    }

    /**
     * The result is a set, so the same encoding held twice, once as JSL's object and once as the JDK's, is one
     * result: the two implementations' equals and hashCode agree. SUN's store gives the same answer, and both keep
     * the object the collection holds first.
     */
    @Test
    public void ourObjectAndTheJdksForOneEncodingCollapse() throws Exception
    {
        List<Object> ours = decoded(JSL);
        List<Object> sun = decoded("SUN");
        Assertions.assertEquals(ours.get(0), sun.get(0));
        Assertions.assertEquals(sun.get(0), ours.get(0));
        Assertions.assertEquals(ours.get(0).hashCode(), sun.get(0).hashCode());
        Assertions.assertEquals(ours.get(3), sun.get(3));
        Assertions.assertEquals(sun.get(3), ours.get(3));
        Assertions.assertEquals(ours.get(3).hashCode(), sun.get(3).hashCode());
        List<Object> coll = new ArrayList<Object>();
        coll.add(ours.get(0));
        coll.add(sun.get(0));
        coll.add(ours.get(3));
        coll.add(sun.get(3));
        for (String p : new String[]{JSL, "SUN"})
        {
            CertStore s = store(p, coll);
            Collection<? extends Certificate> c = s.getCertificates(null);
            Assertions.assertEquals(1, c.size(), p);
            Assertions.assertSame(ours.get(0), c.iterator().next(), p);
            Collection<? extends CRL> r = s.getCRLs(null);
            Assertions.assertEquals(1, r.size(), p);
            Assertions.assertSame(ours.get(3), r.iterator().next(), p);
        }
    }

    /**
     * With JSL first in the search order and no provider named, the JCA reaches JSL's store. Parameters of another
     * kind are refused with InvalidAlgorithmParameterException; the JCA tries every provider serving the type and
     * reports the last refusal, so with JSL the only provider that refusal is JSL's SPI's own.
     */
    @Test
    public void withNoProviderNamedJslFirstServesAndRefuses() throws Exception
    {
        try (ProviderRegistrySnapshot ignored = new ProviderRegistrySnapshot())
        {
            ProviderRegistrySnapshot.insertFirst(Security.getProvider(JSL));
            CertStore s = CertStore.getInstance("Collection", new CollectionCertStoreParameters(everything()));
            Assertions.assertEquals(JSL, s.getProvider().getName());
            Assertions.assertEquals(3, s.getCertificates(null).size());
            assertThrows(InvalidAlgorithmParameterException.class,
                    () -> CertStore.getInstance("Collection", new LDAPCertStoreParameters()));

            Provider jsl = Security.getProvider(JSL);
            ProviderRegistrySnapshot.empty();
            ProviderRegistrySnapshot.insertFirst(jsl);
            InvalidAlgorithmParameterException e = assertThrows(InvalidAlgorithmParameterException.class,
                    () -> CertStore.getInstance("Collection", new LDAPCertStoreParameters()));
            Assertions.assertEquals("parameters must be CollectionCertStoreParameters", e.getMessage());
            Assertions.assertEquals(JostleCollectionCertStoreSpi.class.getName(), e.getStackTrace()[0].getClassName());
        }
    }

    /** A PKITS certificate or CRL decoded through the named provider's CertificateFactory. */
    private static Object pkits(String provider, String name, boolean crl) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        if (crl)
        {
            return cf.generateCRL(new ByteArrayInputStream(PkitsCertificates.crlDer(name)));
        }
        return cf.generateCertificate(new ByteArrayInputStream(PkitsCertificates.der(name)));
    }

    /**
     * PKITS 4.1.1 built with revocation checked from the named provider's Collection store over its own objects:
     * the end entity, GoodCACert unless withoutCa, and both CRLs unless withoutCrls.
     */
    private static CertPath build(String provider, boolean withoutCa, boolean withoutCrls) throws Exception
    {
        X509Certificate ee = (X509Certificate) pkits(provider, "ValidCertificatePathTest1EE.crt", false);
        List<Object> pool = new ArrayList<Object>();
        pool.add(ee);
        if (!withoutCa)
        {
            pool.add(pkits(provider, "GoodCACert.crt", false));
        }
        if (!withoutCrls)
        {
            pool.add(pkits(provider, "GoodCACRL.crl", true));
            pool.add(pkits(provider, "TrustAnchorRootCRL.crl", true));
        }
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(ee);
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(
                (X509Certificate) pkits(provider, PkitsCertificates.ANCHOR, false), null)), target);
        p.setRevocationEnabled(true);
        p.addCertStore(store(provider, pool));
        return CertPathBuilder.getInstance("PKIX", provider).build(p).getCertPath();
    }

    /**
     * JSL's PKIX builder takes the intermediate certificate and both CRLs from a JSL Collection store holding JSL's
     * objects, with revocation checked. Without GoodCACert the build fails for want of an issuer; without the two
     * CRLs it fails for want of revocation status. SUN and BouncyCastle fail both with CertPathBuilderException:
     * SUN with no cause, BouncyCastle with no issuer for the first and an UNSPECIFIED reason for the second.
     */
    @Test
    public void jslsBuilderDrawsTheIntermediateAndTheCrlsFromTheStore() throws Exception
    {
        CertPath path = build(JSL, false, false);
        Assertions.assertEquals(2, path.getCertificates().size());
        Assertions.assertArrayEquals(PkitsCertificates.der("ValidCertificatePathTest1EE.crt"),
                path.getCertificates().get(0).getEncoded());
        Assertions.assertArrayEquals(PkitsCertificates.der("GoodCACert.crt"),
                path.getCertificates().get(1).getEncoded());

        CertPathBuilderException noCa = assertThrows(CertPathBuilderException.class, () -> build(JSL, true, false));
        Assertions.assertEquals(PKIXReason.NO_TRUST_ANCHOR,
                ((CertPathValidatorException) noCa.getCause()).getReason());
        CertPathBuilderException noCrls = assertThrows(CertPathBuilderException.class,
                () -> build(JSL, false, true));
        Assertions.assertEquals(CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS,
                ((CertPathValidatorException) noCrls.getCause()).getReason());

        for (String p : new String[]{"SUN", BC})
        {
            Assertions.assertEquals(2, build(p, false, false).getCertificates().size(), p);
            assertThrows(CertPathBuilderException.class, () -> build(p, true, false), p);
            assertThrows(CertPathBuilderException.class, () -> build(p, false, true), p);
        }
        Assertions.assertNull(assertThrows(CertPathBuilderException.class, () -> build("SUN", false, true))
                .getCause(), "SUN gives no cause");
        CertPathBuilderException bcNoCrls = assertThrows(CertPathBuilderException.class,
                () -> build(BC, false, true));
        Assertions.assertEquals(CertPathValidatorException.BasicReason.UNSPECIFIED,
                ((CertPathValidatorException) bcNoCrls.getCause()).getReason());
    }

    /** PKITS 4.1.1 validated with revocation checked, the CRLs drawn from the named provider's store, or none. */
    private static void validate(String provider, boolean withoutCrls) throws Exception
    {
        List<Certificate> certs = new ArrayList<Certificate>();
        certs.add((Certificate) pkits(provider, "ValidCertificatePathTest1EE.crt", false));
        certs.add((Certificate) pkits(provider, "GoodCACert.crt", false));
        CertPath path = CertificateFactory.getInstance("X.509", provider).generateCertPath(certs);
        List<Object> crls = new ArrayList<Object>();
        if (!withoutCrls)
        {
            crls.add(pkits(provider, "GoodCACRL.crl", true));
            crls.add(pkits(provider, "TrustAnchorRootCRL.crl", true));
        }
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(
                (X509Certificate) pkits(provider, PkitsCertificates.ANCHOR, false), null)));
        p.setRevocationEnabled(true);
        p.addCertStore(store(provider, crls));
        CertPathValidator.getInstance("PKIX", provider).validate(path, p);
    }

    /**
     * JSL's PKIX validator, with revocation checked, takes both CRLs from a JSL Collection store holding JSL's
     * objects; without them it fails for want of revocation status, as SUN's does. BouncyCastle's reason is
     * UNSPECIFIED.
     */
    @Test
    public void jslsValidatorDrawsTheCrlsFromTheStore() throws Exception
    {
        String[] providers = {JSL, "SUN", BC};
        CertPathValidatorException.Reason[] reasons = {
                CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS,
                CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS,
                CertPathValidatorException.BasicReason.UNSPECIFIED};
        for (int i = 0; i < providers.length; i++)
        {
            String p = providers[i];
            validate(p, false);
            CertPathValidatorException e = assertThrows(CertPathValidatorException.class, () -> validate(p, true), p);
            Assertions.assertEquals(reasons[i], e.getReason(), p);
        }
    }

    /**
     * Parameters of another kind, or none, are refused with InvalidAlgorithmParameterException and SUN's message;
     * BouncyCastle refuses null parameters with NoSuchAlgorithmException instead.
     */
    @Test
    public void otherParametersAreRefused() throws Exception
    {
        for (String p : new String[]{JSL, "SUN"})
        {
            Provider provider = Security.getProvider(p);
            InvalidAlgorithmParameterException e = assertThrows(InvalidAlgorithmParameterException.class,
                    () -> CertStore.getInstance("Collection", new LDAPCertStoreParameters(), provider), p);
            Assertions.assertEquals("parameters must be CollectionCertStoreParameters", e.getMessage(), p);
            e = assertThrows(InvalidAlgorithmParameterException.class,
                    () -> CertStore.getInstance("Collection", null, provider), p);
            Assertions.assertEquals("parameters must be CollectionCertStoreParameters", e.getMessage(), p);
        }
        Provider bc = Security.getProvider(BC);
        assertThrows(InvalidAlgorithmParameterException.class,
                () -> CertStore.getInstance("Collection", new LDAPCertStoreParameters(), bc));
        assertThrows(NoSuchAlgorithmException.class, () -> CertStore.getInstance("Collection", null, bc));
    }
}
