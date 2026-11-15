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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
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
import java.security.SecureRandom;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The PKIX validator gives one answer whatever order the caller's stores return their certificates in. The store's
 * certificates reach OpenSSL in a verified order (routes from the trust anchors by verified signatures), and a store
 * copy of a path certificate or an anchor goes last; before this, a store copy of a path CA ahead of a separate
 * CRL-signing certificate, or an unrouted copy of a store certificate, changed OpenSSL's revocation answer by order.
 * PKITS revocation rows are driven over every ordering of hostile stores: the row's own store plus unrouted copies
 * of every certificate (V1), plus decoy CRL signers with each CRL's issuer name and key identifier (V2), and with the
 * path itself in the store, as the PKITS harness and BouncyCastle hold it. JSL's answer is pinned; SUN's and
 * BouncyCastle 1.87's are pinned where they are stable, which on these rows they are.
 */
public class ValidatorStoreOrderAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    /**
     * One base time for every certificate and CRL of the class, whole seconds: two CRLs meant to share an issue
     * time must not land either side of a second boundary.
     */
    private static final long NOW = System.currentTimeMillis() / 1000L * 1000L;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static KeyPairGenerator ec;
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
        ec = KeyPairGenerator.getInstance("EC", BC);
        ec.initialize(256);
    }

    /**
     * The rows store order used to decide, each with JSL's answer, SUN's and BouncyCastle's, as measured. BC
     * refuses 4.14.28 and 4.14.29 and gives no reason on four revoked rows; SUN agrees with JSL on all eleven.
     */
    private static final String[][] ROWS = {
            {"4.4.19", "valid", "valid", "valid"},
            {"4.14.24", "valid", "valid", "valid"},
            {"4.14.25", "valid", "valid", "valid"},
            {"4.14.28", "valid", "valid", "refused UNSPECIFIED"},
            {"4.14.29", "valid", "valid", "refused UNSPECIFIED"},
            {"4.14.33", "valid", "valid", "valid"},
            {"4.4.20", "refused REVOKED", "refused REVOKED", "refused REVOKED"},
            {"4.5.5", "refused REVOKED", "refused REVOKED", "refused UNSPECIFIED"},
            {"4.5.7", "refused REVOKED", "refused REVOKED", "refused UNSPECIFIED"},
            {"4.14.31", "refused REVOKED", "refused REVOKED", "refused UNSPECIFIED"},
            {"4.14.32", "refused REVOKED", "refused REVOKED", "refused REVOKED"}};

    private static PkitsCertificates.Case find(String number) throws Exception
    {
        for (PkitsCertificates.Case c : PkitsCertificates.cases())
        {
            if (c.number.equals(number))
            {
                return c;
            }
        }
        throw new IllegalStateException(number + " is not in the PKITS table");
    }

    /** A certificate with the given subject and key, issued by a fresh untrusted root. */
    private static X509Certificate untrusted(X500Name subject, PublicKey key, byte[] ski, int usage) throws Exception
    {
        KeyPair root = ec.generateKeyPair();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=Untrusted Root"),
                BigInteger.valueOf(serial++), new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 3650L * 86400000L), subject, key);
        if (ski != null)
        {
            b.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(ski));
        }
        b.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(root.getPublic()).getKeyIdentifier()));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        byte[] der = b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(root.getPrivate())).getEncoded();
        return (X509Certificate) CertificateFactory.getInstance("X.509", BC)
                .generateCertificate(new ByteArrayInputStream(der));
    }

    private static byte[] ski(X509Certificate c)
    {
        byte[] v = c.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        return v == null ? null : ASN1OctetString.getInstance(ASN1OctetString.getInstance(v).getOctets()).getOctets();
    }

    /** The certificate's subject, key and key identifier, issued by an untrusted root: never routed. */
    private static X509Certificate copyOf(X509Certificate c) throws Exception
    {
        return untrusted(X500Name.getInstance(c.getSubjectX500Principal().getEncoded()), c.getPublicKey(), ski(c),
                KeyUsage.keyCertSign | KeyUsage.cRLSign);
    }

    /** A decoy CRL signer: the CRL's issuer name and authority key identifier, a fresh key, an untrusted issuer. */
    private static X509Certificate decoySignerFor(X509CRL crl) throws Exception
    {
        byte[] akid = null;
        byte[] v = crl.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (v != null)
        {
            akid = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(v).getOctets()).getKeyIdentifier();
        }
        return untrusted(X500Name.getInstance(crl.getIssuerX500Principal().getEncoded()),
                ec.generateKeyPair().getPublic(), akid, KeyUsage.cRLSign | KeyUsage.keyCertSign);
    }

    /** The provider's validator over the path with the store in the given order, revocation on. */
    private static String validate(String provider, List<X509Certificate> path, List<Object> store) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        List<Certificate> pc = new ArrayList<Certificate>();
        for (X509Certificate c : path)
        {
            pc.add(cf.generateCertificate(new ByteArrayInputStream(c.getEncoded())));
        }
        List<Object> objs = new ArrayList<Object>();
        for (Object o : store)
        {
            objs.add(o instanceof X509CRL ? cf.generateCRL(new ByteArrayInputStream(((X509CRL) o).getEncoded()))
                    : cf.generateCertificate(new ByteArrayInputStream(((X509Certificate) o).getEncoded())));
        }
        X509Certificate anchor = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(PkitsCertificates.der(PkitsCertificates.ANCHOR)));
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(anchor, null)));
        p.setRevocationEnabled(true);
        p.addCertStore(OrderedCertStores.ordered(objs));
        try
        {
            CertPathValidator.getInstance("PKIX", provider).validate(cf.generateCertPath(pc), p);
            return "valid";
        }
        catch (CertPathValidatorException e)
        {
            return "refused " + e.getReason();
        }
    }

    /** Every ordering when there are at most five objects, else the order, its reverse and 40 seeded shuffles. */
    private static List<List<Object>> orderings(List<Object> store, long seed)
    {
        if (store.size() <= 5)
        {
            return OrderedCertStores.permutations(store);
        }
        List<List<Object>> out = new ArrayList<List<Object>>();
        out.add(new ArrayList<Object>(store));
        List<Object> rev = new ArrayList<Object>(store);
        Collections.reverse(rev);
        out.add(rev);
        Random r = new Random(seed);
        for (int i = 0; i < 40; i++)
        {
            List<Object> s = new ArrayList<Object>(store);
            Collections.shuffle(s, r);
            out.add(s);
        }
        return out;
    }

    /** The row's own store: its non-path certificates, then its CRLs. */
    private static List<Object> ownStore(PkitsCertificates.Case c, List<X509Certificate> chain) throws Exception
    {
        List<Object> store = new ArrayList<Object>();
        for (String n : c.intermediates)
        {
            X509Certificate x = PkitsCertificates.certificate(n);
            if (!chain.contains(x))
            {
                store.add(x);
            }
        }
        for (String n : c.crls)
        {
            store.add(PkitsCertificates.crl(n));
        }
        return store;
    }

    /** V1: the row's store plus an unrouted copy of every store certificate and path CA. */
    private static List<Object> withCopies(List<Object> own, List<X509Certificate> chain) throws Exception
    {
        List<Object> out = new ArrayList<Object>(own);
        for (Object o : own)
        {
            if (o instanceof X509Certificate)
            {
                out.add(copyOf((X509Certificate) o));
            }
        }
        for (int i = 1; i < chain.size(); i++)
        {
            out.add(copyOf(chain.get(i)));
        }
        return out;
    }

    /** V2: V1 plus a decoy CRL signer for every CRL in the store. */
    private static List<Object> withDecoys(List<Object> v1) throws Exception
    {
        List<Object> out = new ArrayList<Object>(v1);
        for (Object o : v1)
        {
            if (o instanceof X509CRL)
            {
                out.add(decoySignerFor((X509CRL) o));
            }
        }
        return out;
    }

    /** Every provider over every ordering of the store: one answer each, the pinned one. */
    private static void oneAnswerEach(String row, String what, List<X509Certificate> path, List<Object> store,
            String[] expected, long seed) throws Exception
    {
        String[] providers = {JSL, "SUN", BC};
        for (int i = 0; i < providers.length; i++)
        {
            Set<String> seen = new TreeSet<String>();
            for (List<Object> order : orderings(store, seed))
            {
                seen.add(validate(providers[i], path, order));
            }
            Assertions.assertEquals(Collections.singleton(expected[i]), seen,
                    providers[i] + " " + row + " " + what + ", seed " + seed);
        }
    }

    /**
     * The six valid rows store order refused, and the five whose refusal reason store order changed: one answer on
     * every ordering of the copies-and-decoys stores, JSL's the right one.
     */
    @Test
    public void hostileStoresGiveOneAnswerOnEveryOrdering() throws Exception
    {
        long seed = new SecureRandom().nextLong();
        for (String[] row : ROWS)
        {
            PkitsCertificates.Case c = find(row[0]);
            List<X509Certificate> chain = PkitsCertificates.chain(c);
            String[] expected = {row[1], row[2], row[3]};
            List<Object> own = ownStore(c, chain);
            List<Object> v1 = withCopies(own, chain);
            oneAnswerEach(row[0], "own store", chain, own, expected, seed);
            oneAnswerEach(row[0], "with copies", chain, v1, expected, seed);
            oneAnswerEach(row[0], "with copies and decoy CRL signers", chain, withDecoys(v1), expected, seed);
        }
    }

    /**
     * The path in the store too, as the PKITS harness and BouncyCastle hold it: the store's copy of the path CA ahead
     * of the separate CRL signer used to decide 4.4.19, 4.4.20, 4.5.5 and 4.5.7 (right only when the signer came
     * first). Every ordering now gives the right answer.
     */
    @Test
    public void thePathInTheStoreGivesOneAnswerOnEveryOrdering() throws Exception
    {
        Map<String, String[]> rows = new LinkedHashMap<String, String[]>();
        for (String[] row : ROWS)
        {
            rows.put(row[0], new String[]{row[1], row[2], row[3]});
        }
        for (String number : Arrays.asList("4.4.19", "4.4.20", "4.5.5", "4.5.7"))
        {
            PkitsCertificates.Case c = find(number);
            List<X509Certificate> chain = PkitsCertificates.chain(c);
            List<Object> certs = new ArrayList<Object>();
            List<Object> crls = new ArrayList<Object>();
            for (Object o : ownStore(c, chain))
            {
                (o instanceof X509CRL ? crls : certs).add(o);
            }
            certs.addAll(chain);
            Set<String> seen = new TreeSet<String>();
            for (List<Object> order : OrderedCertStores.permutations(certs))
            {
                List<Object> store = new ArrayList<Object>(order);
                store.addAll(crls);
                seen.add(validate(JSL, chain, store));
            }
            Assertions.assertEquals(Collections.singleton(rows.get(number)[0]), seen, number);
        }
    }

    /**
     * The same four rows through the builder, the path's certificates in the pool beside the store's: one answer on
     * every ordering, the validator's, and the OpenSSL calls per ordering pinned.
     */
    @Test
    public void thePathInThePoolBuildsOneAnswerOnEveryOrdering() throws Exception
    {
        Map<String, String[]> rows = new LinkedHashMap<String, String[]>();
        for (String[] row : ROWS)
        {
            rows.put(row[0], new String[]{row[1], row[2], row[3]});
        }
        Map<String, Map<String, Integer>> calls = new TreeMap<String, Map<String, Integer>>();
        for (String number : Arrays.asList("4.4.19", "4.4.20", "4.5.5", "4.5.7"))
        {
            PkitsCertificates.Case c = find(number);
            List<X509Certificate> chain = PkitsCertificates.chain(c);
            List<Object> certs = new ArrayList<Object>();
            List<Object> crls = new ArrayList<Object>();
            for (Object o : ownStore(c, chain))
            {
                (o instanceof X509CRL ? crls : certs).add(o);
            }
            certs.addAll(chain);
            Set<String> seen = new TreeSet<String>();
            Map<String, Integer> perOrder = new TreeMap<String, Integer>();
            for (List<Object> order : OrderedCertStores.permutations(certs))
            {
                List<Object> store = new ArrayList<Object>(order);
                store.addAll(crls);
                CountingCertPathNI counter = new CountingCertPathNI();
                seen.add(build(chain.get(0), store, counter));
                System.out.println("[builder] PKITS " + number + " calls " + counter.errors);
                String key = counter.take() + " calls";
                perOrder.put(key, perOrder.containsKey(key) ? perOrder.get(key) + 1 : 1);
            }
            System.out.printf("[builder] PKITS %s, path in the pool: %s %s%n", number, seen, perOrder);
            calls.put(number, perOrder);
            Assertions.assertEquals(Collections.singleton(rows.get(number)[0]), seen, number);
        }
        Assertions.assertEquals(BUILDER_CALLS, calls.toString());
    }

    /**
     * The builder's OpenSSL calls per ordering for the four rows, as measured: 4.4.19 builds on the first call and
     * is confirmed by a second (its CRLs share a thisUpdate, as almost all of PKITS's do);
     * the three REVOKED rows answer on the first and spend one more demoting the path CA's alternative in the pool
     * (REVOKED is not a revocation-class error, so no re-verification is made).
     */
    private static final String BUILDER_CALLS = "{4.4.19={2 calls=6}, 4.4.20={2 calls=6}, 4.5.5={2 calls=6}, "
            + "4.5.7={2 calls=6}}";

    private static String build(X509Certificate target, List<Object> store, CountingCertPathNI counter)
            throws Exception
    {
        X509Certificate anchor = (X509Certificate) CertificateFactory.getInstance("X.509", JSL).generateCertificate(
                new ByteArrayInputStream(PkitsCertificates.der(PkitsCertificates.ANCHOR)));
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(target);
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(anchor, null)),
                sel);
        p.setRevocationEnabled(true);
        p.addCertStore(OrderedCertStores.ordered(store));
        try
        {
            new JostleCertPathBuilderSpi(counter.ni, Security.getProvider(JSL)).engineBuild(p);
            return "valid";
        }
        catch (CertPathBuilderException e)
        {
            Throwable cause = e.getCause();
            return "refused" + (cause instanceof CertPathValidatorException
                    ? " " + ((CertPathValidatorException) cause).getReason() : "");
        }
    }

    /**
     * A store certificate with the path CA's subject whose public key the provider cannot rebuild (an algorithm it
     * does not know), issued by the root: it is never treated as a copy of the CA, so it keeps its routed place
     * ahead of an unrouted certificate rather than going last, on both store orders, and the answer is unchanged.
     */
    @Test
    public void aKeyTheProviderCannotRebuildIsNeverACopy() throws Exception
    {
        KeyPair root = ec.generateKeyPair();
        KeyPair ca = ec.generateKeyPair();
        X509Certificate anchor = issued("CN=Root", root, "CN=Root", root.getPublic(), true);
        X509Certificate caCert = issued("CN=Root", root, "CN=CA", ca.getPublic(), true);
        X509Certificate leaf = issued("CN=CA", ca, "CN=leaf", ec.generateKeyPair().getPublic(), false);
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(new X500Name("CN=Root"),
                BigInteger.valueOf(serial++), new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 365L * 86400000L), new X500Name("CN=CA"),
                new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1")),
                        new byte[32]));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        X509Certificate unknownKey = (X509Certificate) CertificateFactory.getInstance("X.509", JSL)
                .generateCertificate(new ByteArrayInputStream(b.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .build(root.getPrivate())).getEncoded()));
        try
        {
            unknownKey.getPublicKey();
            Assertions.fail("the provider rebuilt a key it should not know");
        }
        catch (RuntimeException expected)
        {
            // The precondition: this key cannot be rebuilt.
        }
        X509Certificate stranger = issued("CN=Stranger", ec.generateKeyPair(), "CN=Elsewhere",
                ec.generateKeyPair().getPublic(), false);
        CertPath cp = CertificateFactory.getInstance("X.509", JSL)
                .generateCertPath(Arrays.<Certificate>asList(leaf, caCert));
        for (List<Object> certs : OrderedCertStores.permutations(Arrays.<Object>asList(unknownKey, stranger)))
        {
            List<Object> store = new ArrayList<Object>(certs);
            store.add(crl("CN=Root", root));
            store.add(crl("CN=CA", ca));
            PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(anchor, null)));
            p.setRevocationEnabled(true);
            p.addCertStore(OrderedCertStores.ordered(store));
            CountingCertPathNI counter = new CountingCertPathNI();
            new JostleCertPathValidatorSpi(counter.ni, Security.getProvider(JSL)).engineValidate(cp, p);
            // Anchor, the CA, then the store in order, then the leaf.
            List<byte[]> marshalled = counter.lastCerts;
            Assertions.assertEquals(5, marshalled.size());
            Assertions.assertArrayEquals(unknownKey.getEncoded(), marshalled.get(2), "routed, not last as a copy");
            Assertions.assertArrayEquals(stranger.getEncoded(), marshalled.get(3));
        }
    }

    /**
     * A revocation-on validation with the store at the certificate limit: forged copies of the CA, forged CRL
     * signers with the CA's name and key identifier, and certificates signed by a subscriber's end-entity key. The
     * answer is the same on every ordering tried, and the ordering's signature checks are counted and timed.
     */
    @Test
    public void aStoreAtTheLimitIsOrderedWithinTheBudget() throws Exception
    {
        KeyPair root = ec.generateKeyPair();
        KeyPair ca = ec.generateKeyPair();
        KeyPair subscriber = ec.generateKeyPair();
        X509Certificate anchor = issued("CN=Root", root, "CN=Root", root.getPublic(), true);
        X509Certificate caCert = issued("CN=Root", root, "CN=CA", ca.getPublic(), true);
        X509Certificate leaf = issued("CN=CA", ca, "CN=leaf", ec.generateKeyPair().getPublic(), false);
        X509Certificate sub = issued("CN=Root", root, "CN=Subscriber", subscriber.getPublic(), false);
        List<Object> store = new ArrayList<Object>();
        store.add(sub);
        int forged = 256 - 1 - 2 - 1;
        for (int i = 0; i < forged; i++)
        {
            if (i % 3 == 0)
            {
                store.add(copyOf(caCert));
            }
            else if (i % 3 == 1)
            {
                store.add(untrusted(new X500Name("CN=CA"), ec.generateKeyPair().getPublic(), ski(caCert),
                        KeyUsage.cRLSign));
            }
            else
            {
                store.add(issued("CN=Subscriber", subscriber, "CN=CA", ec.generateKeyPair().getPublic(), true));
            }
        }
        store.add(crl("CN=Root", root));
        store.add(crl("CN=CA", ca));
        List<X509Certificate> path = Arrays.asList(leaf, caCert);
        Set<String> seen = new TreeSet<String>();
        long seed = new SecureRandom().nextLong();
        Random r = new Random(seed);
        for (int i = 0; i < 3; i++)
        {
            List<Object> order = new ArrayList<Object>(store);
            Collections.shuffle(order, r);
            CountingJslProvider.VERIFICATIONS.set(0);
            long t0 = System.nanoTime();
            seen.add(countedValidate(anchor, path, order));
            System.out.printf("[validator] store at the limit, %d certificates: %d checks, %d ms%n", store.size() - 2,
                    CountingJslProvider.VERIFICATIONS.get(), (System.nanoTime() - t0) / 1000000L);
            Assertions.assertTrue(CountingJslProvider.VERIFICATIONS.get() > 0, "no check was counted");
            Assertions.assertTrue(CountingJslProvider.VERIFICATIONS.get() <= 8 * 256);
        }
        Assertions.assertEquals(Collections.singleton("valid"), seen, "seed " + seed);
    }

    /**
     * An ordinary revocation-on validation: root, CA and leaf, the store holding the CA's certificate and the two
     * CRLs, as a caller typically holds them. The ordering's checks are counted and timed for the record.
     */
    @Test
    public void anOrdinaryValidationCostsAFewChecks() throws Exception
    {
        KeyPair root = ec.generateKeyPair();
        KeyPair ca = ec.generateKeyPair();
        X509Certificate anchor = issued("CN=Root", root, "CN=Root", root.getPublic(), true);
        X509Certificate caCert = issued("CN=Root", root, "CN=CA", ca.getPublic(), true);
        X509Certificate leaf = issued("CN=CA", ca, "CN=leaf", ec.generateKeyPair().getPublic(), false);
        List<Object> store = Arrays.<Object>asList(caCert, crl("CN=Root", root), crl("CN=CA", ca));
        CountingJslProvider.VERIFICATIONS.set(0);
        long t0 = System.nanoTime();
        String got = countedValidate(anchor, Arrays.asList(leaf, caCert), store);
        System.out.printf("[validator] ordinary validation, 1 store certificate: %d checks, %d ms%n",
                CountingJslProvider.VERIFICATIONS.get(), (System.nanoTime() - t0) / 1000000L);
        Assertions.assertEquals("valid", got);
        // One store certificate: nothing to order, so no check is made at all.
        Assertions.assertEquals(0, CountingJslProvider.VERIFICATIONS.get());
    }

    /**
     * An ordinary revocation-on validation and build where the order has work to do: a root, the CA and a sibling CA
     * under it, the leaf, both CA certificates in the store and the two CRLs. Signature checks made for the order,
     * OpenSSL calls and time are counted and printed for the record; the checks and calls are pinned.
     */
    @Test
    public void anOrdinaryStoreIsOrderedInAFewChecksAndOneCall() throws Exception
    {
        KeyPair root = ec.generateKeyPair();
        KeyPair ca = ec.generateKeyPair();
        X509Certificate anchor = issued("CN=Root", root, "CN=Root", root.getPublic(), true);
        X509Certificate caCert = issued("CN=Root", root, "CN=CA", ca.getPublic(), true);
        X509Certificate sibling = issued("CN=Root", root, "CN=Sibling CA", ec.generateKeyPair().getPublic(), true);
        X509Certificate leaf = issued("CN=CA", ca, "CN=leaf", ec.generateKeyPair().getPublic(), false);
        List<Object> store = Arrays.<Object>asList(caCert, sibling, crl("CN=Root", root), crl("CN=CA", ca));
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(anchor, null)));
        p.setRevocationEnabled(true);
        p.addCertStore(OrderedCertStores.ordered(store));
        CertPath cp = CertificateFactory.getInstance("X.509", JSL)
                .generateCertPath(Arrays.<Certificate>asList(leaf, caCert));
        CountingCertPathNI counter = new CountingCertPathNI();
        CountingJslProvider.VERIFICATIONS.set(0);
        long t0 = System.nanoTime();
        new JostleCertPathValidatorSpi(counter.ni, new CountingJslProvider()).engineValidate(cp, p);
        long validateMs = (System.nanoTime() - t0) / 1000000L;
        int validateChecks = CountingJslProvider.VERIFICATIONS.get();
        int validateCalls = counter.take();

        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(leaf);
        PKIXBuilderParameters bp = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(anchor, null)),
                sel);
        bp.setRevocationEnabled(true);
        List<Object> pool = new ArrayList<Object>(store);
        pool.add(leaf);
        bp.addCertStore(OrderedCertStores.ordered(pool));
        CountingJslProvider.VERIFICATIONS.set(0);
        t0 = System.nanoTime();
        new JostleCertPathBuilderSpi(counter.ni, new CountingJslProvider()).engineBuild(bp);
        long buildMs = (System.nanoTime() - t0) / 1000000L;
        int buildChecks = CountingJslProvider.VERIFICATIONS.get();
        int buildCalls = counter.take();
        System.out.printf("[validator] ordinary store of 2 CA certificates and 2 CRLs: validator %d checks, %d call, "
                + "%d ms; builder %d checks, %d call, %d ms%n", validateChecks, validateCalls, validateMs, buildChecks,
                buildCalls, buildMs);
        Assertions.assertEquals(ORDINARY, validateChecks + " " + validateCalls + " " + buildChecks + " " + buildCalls,
                "validator checks, calls; builder checks, calls");
    }

    /**
     * Three route checks for each service; one OpenSSL call for the validator, two for the builder, whose build is
     * confirmed because the two CRLs share a thisUpdate.
     */
    private static final String ORDINARY = "3 1 3 2";

    private static String countedValidate(X509Certificate anchor, List<X509Certificate> path, List<Object> store)
            throws Exception
    {
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(anchor, null)));
        p.setRevocationEnabled(true);
        p.addCertStore(OrderedCertStores.ordered(store));
        CertPath cp = CertificateFactory.getInstance("X.509", JSL).generateCertPath(new ArrayList<Certificate>(path));
        try
        {
            new JostleCertPathValidatorSpi(NISelector.CertPathNI, new CountingJslProvider()).engineValidate(cp, p);
            return "valid";
        }
        catch (CertPathValidatorException e)
        {
            return "refused " + e.getReason();
        }
    }

    private static X509Certificate issued(String issuer, KeyPair signer, String subject, PublicKey key, boolean ca)
            throws Exception
    {
        JcaX509ExtensionUtils u = new JcaX509ExtensionUtils();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(serial++), new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 365L * 86400000L), new X500Name(subject), key);
        b.addExtension(Extension.subjectKeyIdentifier, false, u.createSubjectKeyIdentifier(key));
        b.addExtension(Extension.authorityKeyIdentifier, false, u.createAuthorityKeyIdentifier(signer.getPublic()));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign
                : KeyUsage.digitalSignature));
        byte[] der = b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())).getEncoded();
        return (X509Certificate) CertificateFactory.getInstance("X.509", JSL)
                .generateCertificate(new ByteArrayInputStream(der));
    }

    private static X509CRL crl(String issuer, KeyPair signer) throws Exception
    {
        long now = NOW;
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(issuer), new Date(now - 86400000L));
        b.setNextUpdate(new Date(now + 7 * 86400000L));
        b.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signer.getPublic()));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        return new JcaX509CRLConverter().getCRL(b.build(new JcaContentSignerBuilder("SHA256withECDSA")
                .build(signer.getPrivate())));
    }
}
