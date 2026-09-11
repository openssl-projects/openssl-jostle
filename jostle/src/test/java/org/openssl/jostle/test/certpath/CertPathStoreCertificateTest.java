package org.openssl.jostle.test.certpath;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * What the caller's CertStore CERTIFICATES may and may not do.
 *
 * <p>With revocation on they are handed to OpenSSL so an indirect CRL issuer
 * can be resolved, and they are marshalled AFTER the path's intermediates
 * because OpenSSL takes the FIRST time-valid issuer in untrusted-stack order
 * ({@code get0_best_issuer_sk}, x509_vfy.c 3.5.8 :391-421) — a store copy
 * placed earlier would outrank the path's own certificate and fail a path the
 * JDK validates. PKITS has no same-subject same-key pair, so the fixture is
 * minted here: a root, an intermediate, an end entity, and a re-issued
 * intermediate differing only in serial and validity.
 *
 * <p>These cells say a store certificate must not DISTURB a path. That the
 * extras reach OpenSSL at all is proved behaviourally by
 * {@link PkitsPhase2Test}'s indirect-CRL cases, which cannot validate without
 * the CRL issuer's certificate.
 */
public class CertPathStoreCertificateTest
{
    private static X509Certificate root;
    private static X509Certificate ca;
    private static X509Certificate caReissued;
    private static X509Certificate ee;
    private static X509CRL rootCrl;
    private static X509CRL caCrl;
    private static KeyPair caKeyPair;

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair rootKp = kpg.generateKeyPair();
        KeyPair caKp = kpg.generateKeyPair();
        caKeyPair = caKp;
        KeyPair eeKp = kpg.generateKeyPair();

        X500Name rootName = new X500Name("CN=Store Test Root, O=Jostle Tests");
        X500Name caName = new X500Name("CN=Store Test CA, O=Jostle Tests");
        X500Name eeName = new X500Name("CN=Store Test EE, O=Jostle Tests");

        root = caCert(rootName, rootKp, rootName, rootKp, BigInteger.ONE, 0);
        ca = caCert(caName, caKp, rootName, rootKp, BigInteger.valueOf(2), 0);
        // Same subject, same key, different serial and a later notBefore, so
        // the bytes differ while both remain time-valid and both verify.
        caReissued = caCert(caName, caKp, rootName, rootKp, BigInteger.valueOf(3), -1);
        ee = eeCert(eeName, eeKp, caName, caKp);

        rootCrl = crl(rootName, rootKp);
        caCrl = crl(caName, caKp);

        Assertions.assertNotEquals(
                org.bouncycastle.util.encoders.Hex.toHexString(ca.getEncoded()),
                org.bouncycastle.util.encoders.Hex.toHexString(caReissued.getEncoded()),
                "the fixture is pointless unless the two encodings differ");
        Assertions.assertEquals(ca.getSubjectX500Principal(),
                caReissued.getSubjectX500Principal(), "same subject");
        Assertions.assertEquals(ca.getPublicKey(), caReissued.getPublicKey(), "same key");
    }

    private static X509Certificate caCert(X500Name subject, KeyPair subjectKp,
                                          X500Name issuer, KeyPair issuerKp,
                                          BigInteger serial, int daysEarlier) throws Exception
    {
        long day = 86400000L;
        Date from = new Date(System.currentTimeMillis() + daysEarlier * day - day);
        Date to = new Date(System.currentTimeMillis() + 365 * day);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuer, serial, from, to, subject, subjectKp.getPublic());
        // Critical, because X509_V_FLAG_X509_STRICT is always on here.
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        // X509_V_FLAG_X509_STRICT is always on here, and without an AKID the
        // verdict is code 85 MISSING_AUTHORITY_KEY_IDENTIFIER — the fixture
        // would then measure nothing about CertStores.
        addKeyIds(b, subjectKp, issuerKp);
        return convert(b.build(signer(issuerKp)));
    }

    private static X509Certificate eeCert(X500Name subject, KeyPair subjectKp,
                                          X500Name issuer, KeyPair issuerKp) throws Exception
    {
        long day = 86400000L;
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(100),
                new Date(System.currentTimeMillis() - day),
                new Date(System.currentTimeMillis() + 365 * day),
                subject, subjectKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        addKeyIds(b, subjectKp, issuerKp);
        return convert(b.build(signer(issuerKp)));
    }

    private static void addKeyIds(JcaX509v3CertificateBuilder b, KeyPair subjectKp,
                                  KeyPair issuerKp) throws Exception
    {
        JcaX509ExtensionUtils u = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false,
                u.createSubjectKeyIdentifier(subjectKp.getPublic()));
        b.addExtension(Extension.authorityKeyIdentifier, false,
                u.createAuthorityKeyIdentifier(issuerKp.getPublic()));
    }

    /** An empty CRL: revocation must RUN, and nothing here is revoked. */
    private static X509CRL crl(X500Name issuer, KeyPair issuerKp) throws Exception
    {
        long day = 86400000L;
        X509v2CRLBuilder b = new X509v2CRLBuilder(issuer, new Date(System.currentTimeMillis() - day));
        b.setNextUpdate(new Date(System.currentTimeMillis() + 30 * day));
        b.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerKp.getPublic()));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(
                new java.io.ByteArrayInputStream(b.build(signer(issuerKp)).getEncoded()));
    }

    private static X509CRL numberedCrl(int number) throws Exception
    {
        long day = 86400000L;
        X509v2CRLBuilder b = new X509v2CRLBuilder(
                new X500Name("CN=Store Test CA, O=Jostle Tests"),
                new Date(System.currentTimeMillis() - day));
        b.setNextUpdate(new Date(System.currentTimeMillis() + 30 * day));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(
                new java.io.ByteArrayInputStream(b.build(signer(caKeyPair)).getEncoded()));
    }

    private static ContentSigner signer(KeyPair kp) throws Exception
    {
        return new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate());
    }

    private static X509Certificate convert(org.bouncycastle.cert.X509CertificateHolder h)
            throws Exception
    {
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(h);
    }

    private static CertPath path() throws Exception
    {
        return CertificateFactory.getInstance("X.509")
                .generateCertPath(Arrays.asList(ee, ca));
    }

    private static PKIXParameters params(List<Object> storeContents) throws Exception
    {
        PKIXParameters p = new PKIXParameters(
                Collections.singleton(new TrustAnchor(root, null)));
        Assertions.assertTrue(p.isRevocationEnabled(), "revocation must be on for this fixture");
        List<Object> contents = new ArrayList<Object>(storeContents);
        contents.add(rootCrl);
        contents.add(caCrl);
        p.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(contents)));
        return p;
    }

    private static void validate(String provider, List<Object> storeContents) throws Exception
    {
        CertPathValidator.getInstance("PKIX", provider).validate(path(), params(storeContents));
    }

    /** The control: CRLs only, no store certificates. */
    @Test
    public void theSyntheticPathValidatesWithRevocationOn() throws Exception
    {
        validate(JostleProvider.PROVIDER_NAME, Collections.emptyList());
        validate("SUN", Collections.emptyList());
    }

    /**
     * A re-issued copy of a path CA in the store — same subject, same key,
     * different bytes — must not change the verdict.
     *
     * <p>Marshal the extras ahead of the path instead and this is the cell
     * that fails: the store copy outranks the path's own and the built-chain
     * check reports a certificate the path did not supply. The JDK, which
     * does not consult CertStores for path building, is the reference.
     */
    @Test
    public void aReissuedCopyOfAPathCaInTheStoreDoesNotChangeTheVerdict() throws Exception
    {
        List<Object> store = Collections.<Object>singletonList(caReissued);
        validate("SUN", store);
        validate(JostleProvider.PROVIDER_NAME, store);
    }

    /** The path's own intermediates in the store, verbatim: also unchanged. */
    @Test
    public void thePathsOwnIntermediatesInTheStoreDoNotChangeTheVerdict() throws Exception
    {
        List<Object> store = Arrays.<Object>asList(ca, root);
        validate("SUN", store);
        validate(JostleProvider.PROVIDER_NAME, store);
    }

    /**
     * Condition 2: a caller-controlled CRL count over the bridge's ceiling is
     * a PARAMETER error, not an OverflowException. Reaching the bridge yields
     * JO_INPUT_TOO_LONG_INT32, which baseErrorHandler turns into a
     * RuntimeException — the wrong shape for input a caller chose, and it
     * breaks JCE provider fallback.
     *
     * <p>The CRLs must be DISTINCT: a Collection CertStore collects into a
     * HashSet, so 257 copies of one CRL arrive as one and the cell would pass
     * while testing nothing.
     */
    @Test
    public void tooManyCrlsIsRefusedTypedRatherThanAsAnOverflow() throws Exception
    {
        // validate() adds the fixture's own two CRLs, so 254 lands exactly on
        // the 256 ceiling and 255 is one past it.
        List<Object> at = new ArrayList<Object>(distinctCrls(254));
        Assertions.assertEquals(254, new java.util.HashSet<Object>(at).size(),
                "the CRLs must be distinct or the store collapses them");
        // At the ceiling the parameter check ACCEPTS, and the path then
        // validates normally — the fixture's own CRLs are still present.
        validate(JostleProvider.PROVIDER_NAME, at);

        List<Object> over = new ArrayList<Object>(distinctCrls(255));
        java.security.InvalidAlgorithmParameterException e = Assertions.assertThrows(
                java.security.InvalidAlgorithmParameterException.class,
                () -> validate(JostleProvider.PROVIDER_NAME, over));
        Assertions.assertTrue(e.getMessage().contains("too many CRLs: 257"),
                "255 store CRLs plus the fixture's two: " + e.getMessage());
    }

    /** n CRLs from the CA key, distinguished by CRL number. */
    private static List<X509CRL> distinctCrls(int n) throws Exception
    {
        List<X509CRL> out = new ArrayList<X509CRL>();
        for (int i = 0; i < n; i++)
        {
            out.add(numberedCrl(i + 10));
        }
        return out;
    }

    /** Revocation still genuinely runs against this fixture. */
    @Test
    public void withoutTheCrlsTheSyntheticPathIsUndetermined() throws Exception
    {
        PKIXParameters p = new PKIXParameters(
                Collections.singleton(new TrustAnchor(root, null)));
        p.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(Collections.emptyList())));
        CertPathValidatorException e = Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME)
                        .validate(path(), p));
        Assertions.assertEquals(
                CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS,
                e.getReason(), e.getMessage());
    }
}
