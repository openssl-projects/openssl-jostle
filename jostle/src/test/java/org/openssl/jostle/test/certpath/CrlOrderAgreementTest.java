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

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ReasonFlags;
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
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The CRL order both services hand OpenSSL: current at the validation time first, newest thisUpdate, and, in the
 * validator, a CRL listing a path certificate first within one issuer and one thisUpdate; then the CRL number and
 * the encoding. OpenSSL keeps the first of CRLs it scores equal, so before this order the store's order decided
 * between them. Every case runs over every ordering of its CRLs through JSL's validator and builder; SUN's and
 * BC's answers are pinned where they are stable and printed where they vary between runs (ties, which they decide
 * by the CRLs' bytes).
 */
public class CrlOrderAgreementTest
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
        return cert(new X500Name(issuer), signer, new X500Name(subject), key, ca, usage);
    }

    private static X509Certificate cert(X500Name issuer, KeyPair signer, X500Name subject, PublicKey key, boolean ca,
            int usage) throws Exception
    {
        long now = NOW;
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer,
                BigInteger.valueOf(serial++), new Date(now - 30 * DAY), new Date(now + 365 * DAY),
                subject, key);
        b.addExtension(Extension.subjectKeyIdentifier, false, ids.createSubjectKeyIdentifier(key));
        b.addExtension(Extension.authorityKeyIdentifier, false, ids.createAuthorityKeyIdentifier(signer.getPublic()));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        byte[] der = b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())).getEncoded();
        return (X509Certificate) CertificateFactory.getInstance("X.509", JSL)
                .generateCertificate(new ByteArrayInputStream(der));
    }

    /** A CRL of that issuer, signed by that key, thisUpdate and nextUpdate in days from now. */
    private static X509CRL crl(String issuer, KeyPair signer, long thisDays, long nextDays, int number,
            Extension[] exts, BigInteger... revoked) throws Exception
    {
        return crl(new X500Name(issuer), signer, thisDays, nextDays, number, exts, revoked);
    }

    private static X509CRL crl(X500Name issuer, KeyPair signer, long thisDays, long nextDays, int number,
            Extension[] exts, BigInteger... revoked) throws Exception
    {
        long now = NOW;
        X509v2CRLBuilder b = new X509v2CRLBuilder(issuer, new Date(now + thisDays * DAY));
        b.setNextUpdate(new Date(now + nextDays * DAY));
        for (BigInteger r : revoked)
        {
            b.addCRLEntry(r, new Date(now + thisDays * DAY), CRLReason.keyCompromise);
        }
        b.addExtension(Extension.authorityKeyIdentifier, false, ids.createAuthorityKeyIdentifier(signer.getPublic()));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        for (Extension x : exts)
        {
            b.addExtension(x);
        }
        return new JcaX509CRLConverter().setProvider(BC).getCRL(b.build(new JcaContentSignerBuilder("SHA256withECDSA")
                .build(signer.getPrivate())));
    }

    /** A root, a CA under it, a target leaf T and another leaf Z of that CA. */
    private static final class World
    {
        final KeyPair root = kpg.generateKeyPair();
        final KeyPair ca = kpg.generateKeyPair();
        final X509Certificate anchor;
        final X509Certificate caCert;
        final X509Certificate t;
        final X509Certificate z;
        final X509CRL rootCrl;
        final BigInteger sn;

        final X500Name caName;

        World() throws Exception
        {
            this(new X500Name("CN=CA"));
        }

        /** The CA under the name as encoded here; its certificates and CRLs carry exactly this encoding. */
        World(X500Name caName) throws Exception
        {
            this.caName = caName;
            anchor = cert("CN=Root", root, "CN=Root", root.getPublic(), true, KeyUsage.keyCertSign | KeyUsage.cRLSign);
            caCert = cert(new X500Name("CN=Root"), root, caName, ca.getPublic(), true,
                    KeyUsage.keyCertSign | KeyUsage.cRLSign);
            t = cert(caName, ca, new X500Name("CN=target"), kpg.generateKeyPair().getPublic(), false,
                    KeyUsage.digitalSignature);
            z = cert(caName, ca, new X500Name("CN=other"), kpg.generateKeyPair().getPublic(), false,
                    KeyUsage.digitalSignature);
            rootCrl = crl("CN=Root", root, -20, 7, 1, new Extension[0]);
            sn = t.getSerialNumber();
        }

        X509CRL caCrl(long thisDays, long nextDays, int number, Extension[] exts, BigInteger... revoked)
                throws Exception
        {
            return crl(caName, ca, thisDays, nextDays, number, exts, revoked);
        }
    }

    private static PKIXParameters params(World w, List<Object> store, Date at) throws Exception
    {
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(w.anchor, null)));
        p.setRevocationEnabled(true);
        p.setDate(at);
        p.addCertStore(OrderedCertStores.ordered(store));
        return p;
    }

    private static String validate(World w, List<Object> crls, Date at) throws Exception
    {
        List<Object> store = new ArrayList<Object>(crls);
        store.add(w.rootCrl);
        CertPath path = CertificateFactory.getInstance("X.509", JSL)
                .generateCertPath(Arrays.<Certificate>asList(w.t, w.caCert));
        try
        {
            new JostleCertPathValidatorSpi(new CountingCertPathNI().ni, Security.getProvider(JSL))
                    .engineValidate(path, params(w, store, at));
            return "valid";
        }
        catch (CertPathValidatorException e)
        {
            return "refused " + e.getReason();
        }
    }

    /** The builder over the pool [T, Z, CA] and the CRLs; the answer and the number of OpenSSL calls. */
    private static String build(World w, List<Object> crls, Date at, CountingCertPathNI counter) throws Exception
    {
        List<Object> store = new ArrayList<Object>(Arrays.<Object>asList(w.t, w.z, w.caCert));
        store.addAll(crls);
        store.add(w.rootCrl);
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(w.t);
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(w.anchor, null)),
                sel);
        p.setRevocationEnabled(true);
        p.setDate(at);
        p.addCertStore(OrderedCertStores.ordered(store));
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

    /** The JDK's or BC's validator for the path [T, CA], each object decoded by that provider. */
    private static String other(String provider, World w, List<Object> crls, Date at) throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        List<Object> store = new ArrayList<Object>();
        for (Object o : crls)
        {
            store.add(cf.generateCRL(new ByteArrayInputStream(((X509CRL) o).getEncoded())));
        }
        store.add(cf.generateCRL(new ByteArrayInputStream(w.rootCrl.getEncoded())));
        CertPath path = cf.generateCertPath(Arrays.<Certificate>asList(
                cf.generateCertificate(new ByteArrayInputStream(w.t.getEncoded())),
                cf.generateCertificate(new ByteArrayInputStream(w.caCert.getEncoded()))));
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor((X509Certificate)
                cf.generateCertificate(new ByteArrayInputStream(w.anchor.getEncoded())), null)));
        p.setRevocationEnabled(true);
        p.setDate(at);
        p.addCertStore(OrderedCertStores.ordered(store));
        try
        {
            CertPathValidator.getInstance("PKIX", provider).validate(path, p);
            return "valid";
        }
        catch (CertPathValidatorException e)
        {
            return "refused " + e.getReason();
        }
    }

    /** JSL's answers over every ordering, with the builder's OpenSSL calls per ordering. */
    private static final class Answers
    {
        final Set<String> validator = new TreeSet<String>();
        final Set<String> builder = new TreeSet<String>();
        final Map<String, Integer> builderCalls = new TreeMap<String, Integer>();
    }

    private static Answers everyOrder(String what, World w, List<Object> crls, Date at) throws Exception
    {
        Answers a = new Answers();
        for (List<Object> order : OrderedCertStores.permutations(crls))
        {
            a.validator.add(validate(w, order, at));
            CountingCertPathNI counter = new CountingCertPathNI();
            a.builder.add(build(w, order, at, counter));
            int calls = counter.take();
            String key = calls + " calls";
            a.builderCalls.put(key, a.builderCalls.containsKey(key) ? a.builderCalls.get(key) + 1 : 1);
        }
        System.out.printf("[crl-order] %s: validator %s, builder %s %s%n", what, a.validator, a.builder,
                a.builderCalls);
        return a;
    }

    private static void observed(String what, World w, List<Object> crls, Date at) throws Exception
    {
        for (String provider : new String[]{"SUN", BC})
        {
            Set<String> seen = new TreeSet<String>();
            for (List<Object> order : OrderedCertStores.permutations(crls))
            {
                seen.add(other(provider, w, order, at));
            }
            System.out.printf("[crl-order] %s: %s observed %s%n", what, provider, seen);
        }
    }

    private static Date now()
    {
        return new Date();
    }

    /**
     * The four ways one issuer's CRLs tie in OpenSSL's scoring, each with one CRL revoking the target: same
     * thisUpdate and number; same thisUpdate with either number order; a full clean CRL beside a revoking reasons
     * partition. REVOKED on every order, through the validator and the builder. A tie the builder meets clean is
     * confirmed by one more call; SUN and BC decide ties by the CRLs' bytes, so theirs are printed, not pinned.
     */
    @Test
    public void everyTieIsRevokedOnEveryOrder() throws Exception
    {
        World w = new World();
        Extension[] none = new Extension[0];
        Extension someReasons = new Extension(Extension.issuingDistributionPoint, true,
                new IssuingDistributionPoint(null, false, false, new ReasonFlags(ReasonFlags.keyCompromise), false,
                        false).getEncoded());
        Map<String, List<Object>> cases = new TreeMap<String, List<Object>>();
        cases.put("same time and number", Arrays.<Object>asList(w.caCrl(-1, 7, 5, none),
                w.caCrl(-1, 7, 5, none, w.sn)));
        cases.put("same time, 5 clean and 6 revoking", Arrays.<Object>asList(w.caCrl(-1, 7, 5, none),
                w.caCrl(-1, 7, 6, none, w.sn)));
        cases.put("same time, 6 clean and 5 revoking", Arrays.<Object>asList(w.caCrl(-1, 7, 6, none),
                w.caCrl(-1, 7, 5, none, w.sn)));
        cases.put("full clean beside a revoking partition", Arrays.<Object>asList(w.caCrl(-1, 7, 5, none),
                w.caCrl(-1, 7, 6, new Extension[]{someReasons}, w.sn)));
        for (Map.Entry<String, List<Object>> e : cases.entrySet())
        {
            Answers a = everyOrder(e.getKey(), w, e.getValue(), now());
            Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.validator, e.getKey());
            Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.builder, e.getKey());
            observed(e.getKey(), w, e.getValue(), now());
        }
    }

    /**
     * The same-number tie with the issuer's name encoded two ways: the clean CRL's issuer as the CA certificate
     * spells it (UTF8String) and the revoking CRL's as a PrintableString. OpenSSL compares names in canonical form,
     * so the two tie for it; they must be one tie group here too. REVOKED on every order in both services.
     */
    @Test
    public void aTieAcrossTwoEncodingsOfTheIssuerIsRevokedOnEveryOrder() throws Exception
    {
        World w = new World();
        Extension[] none = new Extension[0];
        X500Name printable = new X500Name(new RDN[]{new RDN(BCStyle.CN, new DERPrintableString("CA"))});
        Assertions.assertFalse(Arrays.equals(printable.getEncoded(), new X500Name("CN=CA").getEncoded()),
                "two encodings");
        List<Object> crls = Arrays.<Object>asList(w.caCrl(-1, 7, 5, none),
                crl(printable, w.ca, -1, 7, 5, none, w.sn));
        Answers a = everyOrder("same-number tie, issuer in two encodings", w, crls, now());
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.validator);
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.builder);
    }

    /**
     * The same-number tie with the issuer's CN as a BMPString on one CRL, against the UTF8String the CA's
     * certificate and the other CRL carry, the clean CRL in the BMPString and then the revoking one. OpenSSL
     * converts every directory string to UTF8 before it compares names, so the two tie for it; Java's canonical
     * form does not fold BMPString. REVOKED on every order in both services.
     */
    @Test
    public void aTieAcrossABmpStringIssuerIsRevokedOnEveryOrder() throws Exception
    {
        World w = new World();
        X500Name bmp = new X500Name(new RDN[]{new RDN(BCStyle.CN, new DERBMPString("CA"))});
        List<Object> crls = Arrays.<Object>asList(crl(bmp, w.ca, -1, 7, 5, new Extension[0]),
                w.caCrl(-1, 7, 5, new Extension[0], w.sn));
        Answers a = everyOrder("same-number tie, clean CRL's CN as BMPString", w, crls, now());
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.validator);
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.builder);
        // The other way round: the revoking CRL carries the BMPString, so a listing test by issuer name would miss it.
        List<Object> reversed = Arrays.<Object>asList(w.caCrl(-1, 7, 5, new Extension[0]),
                crl(bmp, w.ca, -1, 7, 5, new Extension[0], w.sn));
        Answers b = everyOrder("same-number tie, revoking CRL's CN as BMPString", w, reversed, now());
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), b.validator);
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), b.builder);
    }

    /**
     * The same tie under a CA named with a serialNumber attribute (2.5.4.5) as a PrintableString, the clean CRL's
     * issuer carrying it as a UTF8String. OpenSSL folds the string type for every attribute; Java's canonical form
     * writes an attribute it has no keyword for as the hex of its encoding. REVOKED on every order in both services.
     */
    @Test
    public void aTieAcrossASerialNumberEncodingIsRevokedOnEveryOrder() throws Exception
    {
        X500Name printable = new X500Name(new RDN[]{new RDN(BCStyle.CN, new DERUTF8String("CA")),
                new RDN(BCStyle.SERIALNUMBER, new DERPrintableString("A1"))});
        X500Name utf8 = new X500Name(new RDN[]{new RDN(BCStyle.CN, new DERUTF8String("CA")),
                new RDN(BCStyle.SERIALNUMBER, new DERUTF8String("A1"))});
        World w = new World(printable);
        List<Object> crls = Arrays.<Object>asList(crl(utf8, w.ca, -1, 7, 5, new Extension[0]),
                w.caCrl(-1, 7, 5, new Extension[0], w.sn));
        Answers a = everyOrder("same-number tie, clean CRL's serialNumber as UTF8String", w, crls, now());
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.validator);
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.builder);
    }

    /**
     * Two genuine deltas for one base carrying freshestCRL: the newest current delta is met first and governs.
     * An older clean and a newer revoking delta: REVOKED on every order; an older revoking and a newer clean
     * (a hold released): valid on every order. SUN and BC ignore deltas: valid in both.
     */
    @Test
    public void theNewestDeltaGovernsOnEveryOrder() throws Exception
    {
        World w = new World();
        Extension freshest = freshest();
        Extension delta5 = new Extension(Extension.deltaCRLIndicator, true,
                new CRLNumber(BigInteger.valueOf(5)).getEncoded());
        X509CRL base = w.caCrl(-10, 7, 5, new Extension[]{freshest});
        Extension[] d = new Extension[]{delta5};
        List<Object> newerRevokes = Arrays.<Object>asList(base, w.caCrl(-5, 7, 6, d), w.caCrl(-1, 7, 7, d, w.sn));
        Answers a = everyOrder("older clean delta, newer revoking delta", w, newerRevokes, now());
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.validator);
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.builder);
        List<Object> released = Arrays.<Object>asList(base, w.caCrl(-5, 7, 6, d, w.sn), w.caCrl(-1, 7, 7, d));
        Answers b = everyOrder("older revoking delta, newer clean delta", w, released, now());
        Assertions.assertEquals(Collections.singleton("valid"), b.validator);
        Assertions.assertEquals(Collections.singleton("valid"), b.builder);
        Assertions.assertEquals("valid", other("SUN", w, newerRevokes, now()));
        Assertions.assertEquals("valid", other(BC, w, newerRevokes, now()));
    }

    /**
     * Validation at a date three days ago: the base current then, an older clean delta current then, a newer
     * revoking delta not yet valid then. OpenSSL takes the first delta that fits the base before it checks the
     * delta's times, so the current-at-the-time key comes first: valid on every order, as SUN and BC answer.
     */
    @Test
    public void aDeltaNotYetValidAtAPastDateIsNotMetFirst() throws Exception
    {
        World w = new World();
        Extension[] d = new Extension[]{new Extension(Extension.deltaCRLIndicator, true,
                new CRLNumber(BigInteger.valueOf(5)).getEncoded())};
        List<Object> crls = Arrays.<Object>asList(w.caCrl(-10, 7, 5, new Extension[]{freshest()}),
                w.caCrl(-5, -2, 6, d), w.caCrl(-1, 7, 7, d, w.sn));
        Date at = new Date(System.currentTimeMillis() - 3 * DAY);
        Answers a = everyOrder("historical date, newer delta not yet valid", w, crls, at);
        Assertions.assertEquals(Collections.singleton("valid"), a.validator);
        Assertions.assertEquals(Collections.singleton("valid"), a.builder);
        Assertions.assertEquals("valid", other("SUN", w, crls, at));
        Assertions.assertEquals("valid", other(BC, w, crls, at));
    }

    /**
     * The builder's tie: CRL A clean for T but listing Z (number 6), CRL B revoking T (number 5), one thisUpdate.
     * The builder has no path before its call, so it meets A first and builds; the tie group makes it re-verify
     * that path with the validator's order, which lists T's revocation first: REVOKED on every order, exactly one
     * extra call. Without a tie group no extra call is made.
     */
    @Test
    public void theBuildersTieIsConfirmedByOneCall() throws Exception
    {
        World w = new World();
        Extension[] none = new Extension[0];
        List<Object> tie = Arrays.<Object>asList(w.caCrl(-1, 7, 6, none, w.z.getSerialNumber()),
                w.caCrl(-1, 7, 5, none, w.sn));
        Answers a = everyOrder("Z-and-T tie", w, tie, now());
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.validator);
        Assertions.assertEquals(Collections.singleton("refused REVOKED"), a.builder);
        Assertions.assertEquals(Collections.singletonMap("2 calls", 2), a.builderCalls,
                "the attempt and one confirming call");

        List<Object> noTie = Arrays.<Object>asList(w.caCrl(-2, 7, 6, none, w.z.getSerialNumber()),
                w.caCrl(-1, 7, 7, none));
        Answers b = everyOrder("no tie", w, noTie, now());
        Assertions.assertEquals(Collections.singleton("valid"), b.builder);
        Assertions.assertEquals(Collections.singletonMap("1 calls", 2), b.builderCalls, "no extra call");
    }

    /**
     * A forged CRL with the CA's name and key identifier, a newer thisUpdate and another key's signature, beside
     * the genuine one, clean beside revoking and revoking beside clean: OpenSSL chooses the forgery on
     * unauthenticated fields and it fails its signature. A refusal on every order, never an acceptance; nothing is
     * dropped. SUN and BC skip it and answer from the genuine CRL.
     */
    @Test
    public void aForgedNewerCrlIsARefusal() throws Exception
    {
        World w = new World();
        Extension[] none = new Extension[0];
        for (boolean genuineRevokes : new boolean[]{false, true})
        {
            long now = NOW;
            X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name("CN=CA"), new Date(now - 60000L));
            b.setNextUpdate(new Date(now + 7 * DAY));
            if (!genuineRevokes)
            {
                b.addCRLEntry(w.sn, new Date(now - 60000L), CRLReason.keyCompromise);
            }
            b.addExtension(Extension.authorityKeyIdentifier, false,
                    ids.createAuthorityKeyIdentifier(w.ca.getPublic()));
            b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(9)));
            X509CRL forged = new JcaX509CRLConverter().setProvider(BC).getCRL(b.build(
                    new JcaContentSignerBuilder("SHA256withECDSA").build(kpg.generateKeyPair().getPrivate())));
            X509CRL genuine = genuineRevokes ? w.caCrl(-2, 7, 5, none, w.sn) : w.caCrl(-2, 7, 5, none);
            List<Object> crls = Arrays.<Object>asList(genuine, forged);
            String what = "forged newer " + (genuineRevokes ? "clean CRL beside the genuine revoking one"
                    : "revoking CRL beside the genuine clean one");
            Answers a = everyOrder(what, w, crls, now());
            Assertions.assertEquals(Collections.singleton("refused UNDETERMINED_REVOCATION_STATUS"), a.validator,
                    what);
            Assertions.assertEquals(Collections.singleton("refused UNDETERMINED_REVOCATION_STATUS"), a.builder,
                    what);
            String genuineAnswer = genuineRevokes ? "refused REVOKED" : "valid";
            for (List<Object> order : OrderedCertStores.permutations(crls))
            {
                Assertions.assertEquals(genuineAnswer, other("SUN", w, order, now()), what);
                Assertions.assertEquals(genuineAnswer, other(BC, w, order, now()), what);
            }
        }
    }

    private static Extension freshest() throws Exception
    {
        return new Extension(Extension.freshestCRL, false, new CRLDistPoint(new DistributionPoint[]{
                new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(
                        GeneralName.uniformResourceIdentifier, "http://example.invalid/delta.crl"))), null,
                        null)}).getEncoded());
    }
}
