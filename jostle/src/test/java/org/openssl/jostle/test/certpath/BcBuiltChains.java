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
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * A certification-path corpus MINTED BY BOUNCYCASTLE, covering the key
 * families and the certificate shapes PKITS does not reach.
 *
 * <p><b>BouncyCastle is both producer and reference here, and that is stated
 * once so no reader has to infer it.</b> PKITS remains the fixed-expectation
 * corpus: its rows carry an outcome the specification states, so a provider
 * can be measured against something that is not another implementation. This
 * corpus cannot do that — a row minted by BouncyCastle and compared against
 * BouncyCastle measures agreement only, and a defect the two share is
 * invisible to it. It is here for the reach PKITS lacks: PKITS is entirely
 * RSA, so every post-quantum, Edwards and elliptic-curve path in the provider
 * is untested by it, and PKITS carries no policy mapping, no name-constraint
 * pair, no path-length boundary and no synthetic critical extension of our
 * choosing.
 *
 * <p><b>Fresh keys every run, from a logged seed.</b> A pinned fixture key
 * hides alignment- and value-specific faults, so every key here is drawn from
 * a {@code SHA1PRNG} seeded from one logged value; a failing run is replayed
 * by setting {@code org.openssl.jostle.test.bcchains.seed} to the number the
 * run printed. The corpus is built once per JVM because SLH-DSA costs roughly
 * half a second a signature and a chain needs five.
 *
 * <p><b>Every certificate carries a subject and authority key identifier and
 * a critical basicConstraints</b>, because this provider validates under
 * {@code X509_V_FLAG_X509_STRICT}: without them the verdict is code 85 or 89
 * and the fixture would measure the fixture rather than the path.
 *
 * <p>Nothing here asserts an outcome. The families and shapes are material;
 * which provider must say what about them belongs in the test that reads it.
 */
public final class BcBuiltChains
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final long DAY = 86400000L;
    private static final String ORG = ", O=Jostle BC Corpus";

    /** Replay a failing run by setting this to the seed the run printed. */
    private static final String SEED_PROPERTY = "org.openssl.jostle.test.bcchains.seed";

    /** The policy the root and intermediate assert. */
    public static final String POLICY_ASSERTED = "1.3.6.1.4.1.99999.1.1";
    /** The policy the intermediate maps {@link #POLICY_ASSERTED} to. */
    public static final String POLICY_MAPPED = "1.3.6.1.4.1.99999.2.1";
    /** A critical extension under a private arc that nobody can understand. */
    public static final String UNKNOWN_EXTENSION = "1.3.6.1.4.1.99999.7.1";
    /**
     * privateKeyUsagePeriod. RFC 5280 dropped it, SUN still parses it into a
     * known extension type and we do not list it as supported, so it is the
     * one OID on which the three disagree about
     * {@code hasUnsupportedCriticalExtension}.
     */
    public static final String PRIVATE_KEY_USAGE_PERIOD = "2.5.29.16";

    private static List<Family> families;
    private static List<Shape> shapes;
    private static SecureRandom random;

    private BcBuiltChains()
    {
    }

    // -----------------------------------------------------------------
    // What a caller gets
    // -----------------------------------------------------------------

    /** A root, an intermediate and two end entities in one key family. */
    public static final class Family
    {
        /** The family as this corpus names it, for failure messages. */
        public final String label;
        /** The name to ask the FIPS module about with {@code canFetch} keymgmt. */
        public final String keyManagementName;
        /** The JCA signature algorithm every certificate in the family is signed with. */
        public final String signatureAlgorithm;
        /**
         * The SubjectPublicKeyInfo algorithm OID of this family's keys, read
         * off the encoding rather than tabulated — a refusal message naming
         * the algorithm can then be checked against the certificate itself.
         */
        public final String publicKeyAlgorithmOid;
        public final X509Certificate root;
        public final X509Certificate ca;
        /** Time-valid, not revoked. */
        public final X509Certificate ee;
        /** Revoked by {@link #caCrl}, so a path to it must be refused. */
        public final X509Certificate revokedEe;
        /** {@link #ee} with one byte of its subject altered, signature untouched. */
        public final X509Certificate tamperedEe;
        public final X509CRL rootCrl;
        /** Lists {@link #revokedEe} and nothing else. */
        public final X509CRL caCrl;

        Family(String label, String keyManagementName, String signatureAlgorithm,
               String publicKeyAlgorithmOid,
               X509Certificate root, X509Certificate ca, X509Certificate ee,
               X509Certificate revokedEe, X509Certificate tamperedEe,
               X509CRL rootCrl, X509CRL caCrl)
        {
            this.label = label;
            this.keyManagementName = keyManagementName;
            this.signatureAlgorithm = signatureAlgorithm;
            this.publicKeyAlgorithmOid = publicKeyAlgorithmOid;
            this.root = root;
            this.ca = ca;
            this.ee = ee;
            this.revokedEe = revokedEe;
            this.tamperedEe = tamperedEe;
            this.rootCrl = rootCrl;
            this.caCrl = caCrl;
        }

        /** End entity first, as a {@code CertPath} is ordered. */
        public List<X509Certificate> chain()
        {
            return Collections.unmodifiableList(Arrays.asList(ee, ca));
        }

        public List<X509Certificate> chainTo(X509Certificate endEntity)
        {
            return Collections.unmodifiableList(Arrays.asList(endEntity, ca));
        }

        public List<X509CRL> crls()
        {
            return Collections.unmodifiableList(Arrays.asList(rootCrl, caCrl));
        }

        /** Every certificate in the family, for an accessor sweep. */
        public List<X509Certificate> allCertificates()
        {
            return Collections.unmodifiableList(
                    Arrays.asList(root, ca, ee, revokedEe, tamperedEe));
        }

        public String toString()
        {
            return label;
        }
    }

    /** One certificate shape PKITS does not carry. */
    public static final class Shape
    {
        public final String label;
        public final X509Certificate root;
        /** End entity first. */
        public final List<X509Certificate> chain;
        public final List<X509CRL> crls;
        /**
         * When the path must be validated, or null for "now". A shape probing
         * the validity boundary needs a date the caller cannot compute.
         */
        public final Date validAt;

        Shape(String label, X509Certificate root, List<X509Certificate> chain,
              List<X509CRL> crls, Date validAt)
        {
            this.label = label;
            this.root = root;
            this.chain = Collections.unmodifiableList(new ArrayList<X509Certificate>(chain));
            this.crls = Collections.unmodifiableList(new ArrayList<X509CRL>(crls));
            this.validAt = validAt;
        }

        /** The end entity, which is what every shape is actually about. */
        public X509Certificate endEntity()
        {
            return chain.get(0);
        }

        public String toString()
        {
            return label;
        }
    }

    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    public static synchronized List<Family> families() throws Exception
    {
        if (families == null)
        {
            build();
        }
        return families;
    }

    public static synchronized List<Shape> shapes() throws Exception
    {
        if (shapes == null)
        {
            build();
        }
        return shapes;
    }

    /** The one shape whose end entity carries a critical extension we reject. */
    public static Shape shape(String label) throws Exception
    {
        for (Shape s : shapes())
        {
            if (s.label.equals(label))
            {
                return s;
            }
        }
        throw new IllegalArgumentException("no such shape: " + label);
    }

    private static void build() throws Exception
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        String configured = System.getProperty(SEED_PROPERTY);
        long seed = configured == null
                ? new SecureRandom().nextLong()
                : Long.parseLong(configured);
        System.out.println("BcBuiltChains " + SEED_PROPERTY + "=" + seed);
        random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(seed);

        long started = System.currentTimeMillis();
        List<Family> f = new ArrayList<Family>();
        f.add(family("RSA-PKCS1", "RSA", "SHA256withRSA", "RSA", null, 2048));
        f.add(family("RSA-PSS", "RSA", "SHA256withRSAandMGF1", "RSA", null, 2048));
        f.add(family("DSA", "DSA", "SHA256withDSA", "DSA", null, 2048));
        f.add(family("EC-P256", "EC", "SHA256withECDSA", "EC", new ECGenParameterSpec("P-256"), 0));
        f.add(family("EC-P384", "EC", "SHA384withECDSA", "EC", new ECGenParameterSpec("P-384"), 0));
        f.add(family("EC-P521", "EC", "SHA512withECDSA", "EC", new ECGenParameterSpec("P-521"), 0));
        f.add(family("Ed25519", "ED25519", "Ed25519", "Ed25519",
                new EdDSAParameterSpec("Ed25519"), 0));
        f.add(family("Ed448", "ED448", "Ed448", "Ed448",
                new EdDSAParameterSpec("Ed448"), 0));
        f.add(family("ML-DSA-44", "ML-DSA-44", "ML-DSA-44", "ML-DSA",
                MLDSAParameterSpec.ml_dsa_44, 0));
        f.add(family("ML-DSA-65", "ML-DSA-65", "ML-DSA-65", "ML-DSA",
                MLDSAParameterSpec.ml_dsa_65, 0));
        f.add(family("ML-DSA-87", "ML-DSA-87", "ML-DSA-87", "ML-DSA",
                MLDSAParameterSpec.ml_dsa_87, 0));
        f.add(family("SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S", "SLH-DSA",
                SLHDSAParameterSpec.slh_dsa_sha2_128s, 0));
        f.add(family("SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128S", "SLH-DSA",
                SLHDSAParameterSpec.slh_dsa_shake_128s, 0));
        families = Collections.unmodifiableList(f);

        List<Shape> s = new ArrayList<Shape>();
        s.add(dsaInheritedParameters());
        s.add(policyMapping());
        addNameConstraints(s);
        addPathLength(s);
        s.add(validityBoundary());
        addCriticalExtensions(s);
        shapes = Collections.unmodifiableList(s);

        System.out.println("BcBuiltChains built " + families.size() + " families and "
                + shapes.size() + " shapes in " + (System.currentTimeMillis() - started) + "ms");
    }

    // -----------------------------------------------------------------
    // Families
    // -----------------------------------------------------------------

    private static Family family(String label, String keyManagementName, String sigAlg,
                                 String kpgAlgorithm, AlgorithmParameterSpec spec, int keySize)
            throws Exception
    {
        KeyPair rootKp = keyPair(kpgAlgorithm, spec, keySize);
        KeyPair caKp = keyPair(kpgAlgorithm, spec, keySize);
        KeyPair eeKp = keyPair(kpgAlgorithm, spec, keySize);

        X500Name rootName = name(label + " Root");
        X500Name caName = name(label + " CA");
        X500Name eeName = name(label + " EE");
        X500Name revokedName = name(label + " Revoked EE");

        X509Certificate root = authority(rootName, rootKp.getPublic(), rootName, rootKp,
                sigAlg, 1, null, null, null);
        X509Certificate ca = authority(caName, caKp.getPublic(), rootName, rootKp,
                sigAlg, 2, null, null, null);
        X509Certificate ee = endEntity(eeName, eeKp.getPublic(), caName, caKp, sigAlg, 3);
        X509Certificate revoked = endEntity(revokedName, eeKp.getPublic(), caName, caKp, sigAlg, 4);

        return new Family(label, keyManagementName, sigAlg,
                SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded())
                        .getAlgorithm().getAlgorithm().getId(),
                root, ca, ee, revoked,
                tamper(ee, label + " EE"),
                crl(rootName, rootKp, sigAlg, null),
                crl(caName, caKp, sigAlg, BigInteger.valueOf(4)));
    }

    /**
     * {@code ee} with one byte of its subject common name altered and the
     * signature left alone. The DER length is unchanged, so the result still
     * parses and only the signature check can reject it — which is the point:
     * a certificate refused because it will not decode would measure the
     * decoder rather than the verifier.
     */
    private static X509Certificate tamper(X509Certificate ee, String marker) throws Exception
    {
        byte[] der = ee.getEncoded();
        byte[] find = marker.getBytes("US-ASCII");
        int at = indexOf(der, find);
        Assertions.assertTrue(at >= 0,
                "the subject marker " + marker + " is not in the encoding, so nothing was tampered");
        byte[] copy = der.clone();
        // One printable letter for another keeps the DER length and the
        // string's character class, so only the signature can notice.
        copy[at] = (byte) (copy[at] == (byte) 'X' ? 'Y' : 'X');
        Assertions.assertFalse(java.util.Arrays.equals(der, copy), "the tamper changed nothing");
        X509Certificate tampered = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(copy));
        Assertions.assertNotEquals(ee.getSubjectX500Principal(), tampered.getSubjectX500Principal(),
                "the tampered certificate has the same subject, so the tamper missed the name");
        return tampered;
    }

    private static int indexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.length <= haystack.length; i++)
        {
            boolean hit = true;
            for (int j = 0; j < needle.length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    hit = false;
                    break;
                }
            }
            if (hit)
            {
                return i;
            }
        }
        return -1;
    }

    // -----------------------------------------------------------------
    // Shapes
    // -----------------------------------------------------------------

    /**
     * RFC 3279 §2.3.2: an end entity whose DSA SubjectPublicKeyInfo omits the
     * parameters and inherits them from the issuer. PKITS carries two such
     * certificates; this mints a third independently, so the divergence is
     * measured rather than inherited from one corpus.
     */
    private static Shape dsaInheritedParameters() throws Exception
    {
        KeyPair rootKp = keyPair("DSA", null, 2048);
        KeyPair caKp = sameDsaParameters(rootKp);
        KeyPair eeKp = sameDsaParameters(rootKp);
        X500Name rootName = name("DSA-Inherited Root");
        X500Name caName = name("DSA-Inherited CA");
        X500Name eeName = name("DSA-Inherited EE");

        X509Certificate root = authority(rootName, rootKp.getPublic(), rootName, rootKp,
                "SHA256withDSA", 1, null, null, null);
        X509Certificate ca = authority(caName, caKp.getPublic(), rootName, rootKp,
                "SHA256withDSA", 2, null, null, null);

        SubjectPublicKeyInfo full = SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded());
        SubjectPublicKeyInfo stripped = new SubjectPublicKeyInfo(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(full.getAlgorithm().getAlgorithm()),
                full.getPublicKeyData().getBytes());
        Assertions.assertNull(stripped.getAlgorithm().getParameters(),
                "the end entity still carries DSA parameters, so it inherits nothing");

        X509v3CertificateBuilder b = new X509v3CertificateBuilder(caName, BigInteger.valueOf(3),
                new Date(System.currentTimeMillis() - DAY),
                new Date(System.currentTimeMillis() + 365 * DAY), eeName, stripped);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caKp.getPublic()));
        b.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(
                MessageDigest.getInstance("SHA-1").digest(stripped.getPublicKeyData().getBytes())));
        X509Certificate ee = convert(b.build(signer(caKp, "SHA256withDSA")));

        return new Shape("dsa-inherited-parameters", root, Arrays.asList(ee, ca),
                Arrays.asList(crl(rootName, rootKp, "SHA256withDSA", null),
                        crl(caName, caKp, "SHA256withDSA", null)), null);
    }

    /**
     * A root and an intermediate asserting {@link #POLICY_ASSERTED}, the
     * intermediate mapping it to {@link #POLICY_MAPPED}, and an end entity
     * asserting the mapped policy. PKITS has policy rows, but none this
     * provider can be driven through: it refuses an initial policy set
     * outright, so the shape exists to measure that refusal and the empty
     * policy tree beside a reference that builds one.
     */
    private static Shape policyMapping() throws Exception
    {
        KeyPair rootKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair caKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair eeKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        X500Name rootName = name("Policy Root");
        X500Name caName = name("Policy CA");
        X500Name eeName = name("Policy EE");
        String sigAlg = "SHA256withECDSA";

        CertificatePolicies asserted = new CertificatePolicies(
                new PolicyInformation(new ASN1ObjectIdentifier(POLICY_ASSERTED)));
        CertificatePolicies mapped = new CertificatePolicies(
                new PolicyInformation(new ASN1ObjectIdentifier(POLICY_MAPPED)));
        PolicyMappings mappings = new PolicyMappings(
                new CertPolicyId[]{CertPolicyId.getInstance(new ASN1ObjectIdentifier(POLICY_ASSERTED))},
                new CertPolicyId[]{CertPolicyId.getInstance(new ASN1ObjectIdentifier(POLICY_MAPPED))});

        X509Certificate root = authority(rootName, rootKp.getPublic(), rootName, rootKp,
                sigAlg, 1, asserted, null, null);
        X509Certificate ca = authority(caName, caKp.getPublic(), rootName, rootKp,
                sigAlg, 2, asserted, mappings, null);
        X509Certificate ee = endEntity(eeName, eeKp.getPublic(), caName, caKp, sigAlg, 3,
                mapped, null, null, false);

        return new Shape("policy-mapping", root, Arrays.asList(ee, ca),
                Arrays.asList(crl(rootName, rootKp, sigAlg, null),
                        crl(caName, caKp, sigAlg, null)), null);
    }

    /**
     * One intermediate carrying permitted and excluded subtrees over both
     * dNSName and rfc822Name, and two end entities beneath it — one inside
     * the permitted subtree, one inside the excluded one.
     */
    private static void addNameConstraints(List<Shape> out) throws Exception
    {
        KeyPair rootKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair caKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair eeKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        X500Name rootName = name("NameConstraints Root");
        X500Name caName = name("NameConstraints CA");
        X500Name eeName = new X500Name("CN=nc-ee" + ORG);
        String sigAlg = "SHA256withECDSA";

        NameConstraints nc = new NameConstraints(
                new GeneralSubtree[]{
                        new GeneralSubtree(new GeneralName(GeneralName.dNSName, "permitted.example")),
                        new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "permitted.example"))},
                new GeneralSubtree[]{
                        new GeneralSubtree(new GeneralName(GeneralName.dNSName,
                                "blocked.permitted.example")),
                        new GeneralSubtree(new GeneralName(GeneralName.rfc822Name,
                                "blocked.permitted.example"))});

        X509Certificate root = authority(rootName, rootKp.getPublic(), rootName, rootKp,
                sigAlg, 1, null, null, null);
        X509Certificate ca = authority(caName, caKp.getPublic(), rootName, rootKp,
                sigAlg, 2, null, null, nc);

        GeneralNames inside = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "host.permitted.example"),
                new GeneralName(GeneralName.rfc822Name, "user@permitted.example")});
        GeneralNames outside = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "host.blocked.permitted.example"),
                new GeneralName(GeneralName.rfc822Name, "user@blocked.permitted.example")});

        List<X509CRL> crls = Arrays.asList(crl(rootName, rootKp, sigAlg, null),
                crl(caName, caKp, sigAlg, null));

        out.add(new Shape("name-constraints-permitted", root,
                Arrays.asList(endEntity(eeName, eeKp.getPublic(), caName, caKp, sigAlg, 3,
                        null, inside, null, false), ca), crls, null));
        out.add(new Shape("name-constraints-excluded", root,
                Arrays.asList(endEntity(eeName, eeKp.getPublic(), caName, caKp, sigAlg, 4,
                        null, outside, null, false), ca), crls, null));
    }

    /**
     * An intermediate with {@code pathLenConstraint} 0: it may issue end
     * entities and no further authority. One path stops at an end entity
     * directly beneath it; the other inserts a subordinate authority, which
     * is one level too deep.
     */
    private static void addPathLength(List<Shape> out) throws Exception
    {
        KeyPair rootKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair caKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair subKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair eeKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        X500Name rootName = name("PathLen Root");
        X500Name caName = name("PathLen CA");
        X500Name subName = name("PathLen Sub CA");
        X500Name eeName = name("PathLen EE");
        String sigAlg = "SHA256withECDSA";

        X509Certificate root = authority(rootName, rootKp.getPublic(), rootName, rootKp,
                sigAlg, 1, null, null, null);
        X509Certificate ca = pathLimited(caName, caKp.getPublic(), rootName, rootKp, sigAlg, 2, 0);
        X509Certificate sub = pathLimited(subName, subKp.getPublic(), caName, caKp, sigAlg, 3, 0);
        X509Certificate under = endEntity(eeName, eeKp.getPublic(), caName, caKp, sigAlg, 4);
        X509Certificate tooDeep = endEntity(eeName, eeKp.getPublic(), subName, subKp, sigAlg, 5);

        List<X509CRL> crls = Arrays.asList(crl(rootName, rootKp, sigAlg, null),
                crl(caName, caKp, sigAlg, null), crl(subName, subKp, sigAlg, null));

        out.add(new Shape("pathlen-at-boundary", root, Arrays.asList(under, ca), crls, null));
        out.add(new Shape("pathlen-over-boundary", root,
                Arrays.asList(tooDeep, sub, ca), crls, null));
    }

    /**
     * An end entity whose validity window lies entirely in the PAST, so the
     * boundary can be probed on both ends.
     * <p>
     * The window has to be past because BouncyCastle refuses any validation
     * date later than now ("Validation time is in future"), which would
     * decide a future-window probe before the certificate's own dates were
     * consulted. Everything above the end entity, and both CRLs, are valid
     * across a 400-day window, so only the end entity's own notBefore and
     * notAfter can decide the verdict.
     */
    private static Shape validityBoundary() throws Exception
    {
        KeyPair rootKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair caKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair eeKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        X500Name rootName = name("Validity Root");
        X500Name caName = name("Validity CA");
        X500Name eeName = name("Validity EE");
        String sigAlg = "SHA256withECDSA";

        long now = System.currentTimeMillis();
        Date wideFrom = new Date(now - 400 * DAY);
        Date wideTo = new Date(now + 400 * DAY);

        X509Certificate root = dated(rootName, rootKp.getPublic(), rootName, rootKp,
                sigAlg, 1, true, wideFrom, wideTo);
        X509Certificate ca = dated(caName, caKp.getPublic(), rootName, rootKp,
                sigAlg, 2, true, wideFrom, wideTo);
        X509Certificate ee = dated(eeName, eeKp.getPublic(), caName, caKp,
                sigAlg, 3, false, new Date(now - 20 * DAY), new Date(now - 10 * DAY));

        return new Shape("validity-boundary", root, Arrays.asList(ee, ca),
                Arrays.asList(datedCrl(rootName, rootKp, sigAlg, wideFrom, wideTo),
                        datedCrl(caName, caKp, sigAlg, wideFrom, wideTo)), null);
    }

    /**
     * Three end entities differing only in one extension: a critical OID
     * nobody understands, the same OID non-critical, and a critical
     * privateKeyUsagePeriod.
     * <p>
     * The corpus cannot reach this. Across 578 PKITS files exactly one
     * certificate and one CRL carry a critical extension outside the
     * supported set, and the two references agree on every file — so the
     * supported-extension list is indistinguishable from a different one
     * without a certificate minted to separate them.
     */
    private static void addCriticalExtensions(List<Shape> out) throws Exception
    {
        KeyPair rootKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair caKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        KeyPair eeKp = keyPair("EC", new ECGenParameterSpec("P-256"), 0);
        X500Name rootName = name("CriticalExt Root");
        X500Name caName = name("CriticalExt CA");
        X500Name eeName = name("CriticalExt EE");
        String sigAlg = "SHA256withECDSA";

        X509Certificate root = authority(rootName, rootKp.getPublic(), rootName, rootKp,
                sigAlg, 1, null, null, null);
        X509Certificate ca = authority(caName, caKp.getPublic(), rootName, rootKp,
                sigAlg, 2, null, null, null);
        List<X509CRL> crls = Arrays.asList(crl(rootName, rootKp, sigAlg, null),
                crl(caName, caKp, sigAlg, null));

        byte[] opaque = new DEROctetString(new byte[]{1, 2, 3}).getEncoded();
        byte[] emptyPeriod = new DERSequence().getEncoded();

        out.add(new Shape("unknown-critical-extension", root,
                Arrays.asList(endEntity(eeName, eeKp.getPublic(), caName, caKp, sigAlg, 3,
                        null, null, extension(UNKNOWN_EXTENSION, opaque), true), ca), crls, null));
        out.add(new Shape("unknown-noncritical-extension", root,
                Arrays.asList(endEntity(eeName, eeKp.getPublic(), caName, caKp, sigAlg, 4,
                        null, null, extension(UNKNOWN_EXTENSION, opaque), false), ca), crls, null));
        out.add(new Shape("private-key-usage-period-critical", root,
                Arrays.asList(endEntity(eeName, eeKp.getPublic(), caName, caKp, sigAlg, 5,
                        null, null, extension(PRIVATE_KEY_USAGE_PERIOD, emptyPeriod), true), ca),
                crls, null));
    }

    private static Object[] extension(String oid, byte[] value)
    {
        return new Object[]{oid, value};
    }

    // -----------------------------------------------------------------
    // Builders
    // -----------------------------------------------------------------

    private static X500Name name(String cn)
    {
        return new X500Name("CN=" + cn + ORG);
    }

    private static KeyPair keyPair(String algorithm, AlgorithmParameterSpec spec, int keySize)
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, BC);
        if (spec != null)
        {
            kpg.initialize(spec, random);
        }
        else
        {
            kpg.initialize(keySize, random);
        }
        return kpg.generateKeyPair();
    }

    /** A second DSA key over the issuer's own p, q and g, so parameters can be inherited. */
    private static KeyPair sameDsaParameters(KeyPair like) throws Exception
    {
        DSAPublicKey pub = (DSAPublicKey) like.getPublic();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", BC);
        kpg.initialize(new DSAParameterSpec(pub.getParams().getP(), pub.getParams().getQ(),
                pub.getParams().getG()), random);
        return kpg.generateKeyPair();
    }

    private static X509Certificate authority(X500Name subject, PublicKey subjectKey,
                                             X500Name issuer, KeyPair issuerKp, String sigAlg,
                                             int serial, CertificatePolicies policies,
                                             PolicyMappings mappings, NameConstraints constraints)
            throws Exception
    {
        JcaX509v3CertificateBuilder b = base(subject, subjectKey, issuer, issuerKp, serial,
                new Date(System.currentTimeMillis() - DAY),
                new Date(System.currentTimeMillis() + 365 * DAY));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        if (policies != null)
        {
            b.addExtension(Extension.certificatePolicies, false, policies);
        }
        if (mappings != null)
        {
            b.addExtension(Extension.policyMappings, true, mappings);
        }
        if (constraints != null)
        {
            b.addExtension(Extension.nameConstraints, true, constraints);
        }
        return convert(b.build(signer(issuerKp, sigAlg)));
    }

    private static X509Certificate pathLimited(X500Name subject, PublicKey subjectKey,
                                               X500Name issuer, KeyPair issuerKp, String sigAlg,
                                               int serial, int pathLen) throws Exception
    {
        JcaX509v3CertificateBuilder b = base(subject, subjectKey, issuer, issuerKp, serial,
                new Date(System.currentTimeMillis() - DAY),
                new Date(System.currentTimeMillis() + 365 * DAY));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return convert(b.build(signer(issuerKp, sigAlg)));
    }

    private static X509Certificate endEntity(X500Name subject, PublicKey subjectKey,
                                             X500Name issuer, KeyPair issuerKp, String sigAlg,
                                             int serial) throws Exception
    {
        return endEntity(subject, subjectKey, issuer, issuerKp, sigAlg, serial,
                null, null, null, false);
    }

    private static X509Certificate endEntity(X500Name subject, PublicKey subjectKey,
                                             X500Name issuer, KeyPair issuerKp, String sigAlg,
                                             int serial, CertificatePolicies policies,
                                             GeneralNames subjectAltName, Object[] extra,
                                             boolean extraCritical) throws Exception
    {
        JcaX509v3CertificateBuilder b = base(subject, subjectKey, issuer, issuerKp, serial,
                new Date(System.currentTimeMillis() - DAY),
                new Date(System.currentTimeMillis() + 365 * DAY));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        if (policies != null)
        {
            b.addExtension(Extension.certificatePolicies, false, policies);
        }
        if (subjectAltName != null)
        {
            b.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
        }
        if (extra != null)
        {
            b.addExtension(new ASN1ObjectIdentifier((String) extra[0]), extraCritical,
                    (byte[]) extra[1]);
        }
        return convert(b.build(signer(issuerKp, sigAlg)));
    }

    private static X509Certificate dated(X500Name subject, PublicKey subjectKey, X500Name issuer,
                                         KeyPair issuerKp, String sigAlg, int serial,
                                         boolean isAuthority, Date from, Date to) throws Exception
    {
        JcaX509v3CertificateBuilder b = base(subject, subjectKey, issuer, issuerKp, serial, from, to);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isAuthority));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(isAuthority
                ? KeyUsage.keyCertSign | KeyUsage.cRLSign
                : KeyUsage.digitalSignature));
        return convert(b.build(signer(issuerKp, sigAlg)));
    }

    private static JcaX509v3CertificateBuilder base(X500Name subject, PublicKey subjectKey,
                                                    X500Name issuer, KeyPair issuerKp,
                                                    int serial, Date from, Date to) throws Exception
    {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(serial), from, to, subject, subjectKey);
        JcaX509ExtensionUtils u = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, u.createSubjectKeyIdentifier(subjectKey));
        b.addExtension(Extension.authorityKeyIdentifier, false,
                u.createAuthorityKeyIdentifier(issuerKp.getPublic()));
        return b;
    }

    private static X509CRL crl(X500Name issuer, KeyPair issuerKp, String sigAlg, BigInteger revoked)
            throws Exception
    {
        long now = System.currentTimeMillis();
        return buildCrl(issuer, issuerKp, sigAlg, new Date(now - DAY), new Date(now + 30 * DAY),
                revoked);
    }

    private static X509CRL datedCrl(X500Name issuer, KeyPair issuerKp, String sigAlg,
                                    Date thisUpdate, Date nextUpdate) throws Exception
    {
        return buildCrl(issuer, issuerKp, sigAlg, thisUpdate, nextUpdate, null);
    }

    private static X509CRL buildCrl(X500Name issuer, KeyPair issuerKp, String sigAlg,
                                    Date thisUpdate, Date nextUpdate, BigInteger revoked)
            throws Exception
    {
        X509v2CRLBuilder b = new X509v2CRLBuilder(issuer, thisUpdate);
        b.setNextUpdate(nextUpdate);
        if (revoked != null)
        {
            b.addCRLEntry(revoked, new Date(System.currentTimeMillis() - DAY / 2),
                    CRLReason.keyCompromise);
        }
        b.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerKp.getPublic()));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        return (X509CRL) CertificateFactory.getInstance("X.509")
                .generateCRL(new ByteArrayInputStream(b.build(signer(issuerKp, sigAlg)).getEncoded()));
    }

    private static ContentSigner signer(KeyPair kp, String sigAlg) throws Exception
    {
        return new JcaContentSignerBuilder(sigAlg).setProvider(BC).build(kp.getPrivate());
    }

    private static X509Certificate convert(X509CertificateHolder holder) throws Exception
    {
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
    }
}
