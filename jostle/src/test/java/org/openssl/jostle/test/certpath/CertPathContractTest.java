package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.certpath.CertPathNI;

import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The validator's parameter contract: what it honours, what it refuses, and the
 * inputs that must never reach the native layer's invariant asserts.
 */
public class CertPathContractTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static CertPathValidator validator() throws Exception
    {
        return CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME);
    }

    private static CertPath goodPath() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> chain = new ArrayList<X509Certificate>();
        chain.add(PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt"));
        chain.add(PkitsCertificates.certificate("GoodCACert.crt"));
        return cf.generateCertPath(chain);
    }

    private static PKIXParameters anchoredAtRoot() throws Exception
    {
        PKIXParameters p = new PKIXParameters(Collections.singleton(
                new TrustAnchor(PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)));
        p.setRevocationEnabled(false);
        return p;
    }

    /**
     * P1, and the withheld-CRL negative. Revocation defaults ON, the
     * CertStores carry NO CRL, and a path whose certificates are all sound
     * must still fail for UNDETERMINED status — a caller who never opted out
     * must not get a green result with the check dropped.
     */
    @Test
    public void revocationEnabledWithNoCrlSuppliedIsUndeterminedRatherThanSilentlyPassed()
            throws Exception
    {
        PKIXParameters p = new PKIXParameters(Collections.singleton(
                new TrustAnchor(PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)));
        Assertions.assertTrue(p.isRevocationEnabled(), "the JCE default must still be true");

        CertPathValidatorException e = Assertions.assertThrows(
                CertPathValidatorException.class,
                () -> validator().validate(goodPath(), p));
        Assertions.assertEquals(
                CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS,
                e.getReason(),
                "no CRL supplied is undetermined status, not revoked: " + e.getMessage());
        Assertions.assertTrue(e.getMessage().matches("(?s).*failed: 3 .*"),
                "expected X509 error 3 (no CRL), got: " + e.getMessage());

        // The control: the SAME path validates when the caller opts out, so
        // the failure above is the revocation check and not a broken path.
        validator().validate(goodPath(), anchoredAtRoot());
    }

    /** P2: the policy inputs are refused, not ignored. */
    @Test
    public void policyInputsAreRefusedRatherThanIgnored() throws Exception
    {
        PKIXParameters explicit = anchoredAtRoot();
        explicit.setExplicitPolicyRequired(true);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> validator().validate(goodPath(), explicit));

        PKIXParameters mapping = anchoredAtRoot();
        mapping.setPolicyMappingInhibited(true);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> validator().validate(goodPath(), mapping));

        PKIXParameters any = anchoredAtRoot();
        any.setAnyPolicyInhibited(true);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> validator().validate(goodPath(), any));

        PKIXParameters initial = anchoredAtRoot();
        Set<String> policies = new HashSet<String>();
        policies.add("2.16.840.1.101.3.2.1.48.1");
        initial.setInitialPolicies(policies);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> validator().validate(goodPath(), initial));

        PKIXParameters checkers = anchoredAtRoot();
        checkers.addCertPathChecker(new PKIXCertPathChecker()
        {
            public void init(boolean forward)
            {
            }

            public boolean isForwardCheckingSupported()
            {
                return false;
            }

            public Set<String> getSupportedExtensions()
            {
                return null;
            }

            public void check(java.security.cert.Certificate cert, Collection<String> unresolved)
            {
            }
        });
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> validator().validate(goodPath(), checkers));
    }

    /** V3: anchor name constraints cannot be applied here, so they are refused. */
    @Test
    public void anchorNameConstraintsAreRefused() throws Exception
    {
        // TrustAnchor validates the encoding, so this must be a real
        // NameConstraints extension value rather than arbitrary DER.
        byte[] nc = new org.bouncycastle.asn1.x509.NameConstraints(
                new org.bouncycastle.asn1.x509.GeneralSubtree[]{
                        new org.bouncycastle.asn1.x509.GeneralSubtree(
                                new org.bouncycastle.asn1.x509.GeneralName(
                                        org.bouncycastle.asn1.x509.GeneralName.dNSName,
                                        "example.com"))},
                null).getEncoded();
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(
                PkitsCertificates.certificate(PkitsCertificates.ANCHOR), nc)));
        p.setRevocationEnabled(false);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> validator().validate(goodPath(), p));
        // Only the separate-BYTES form is refused: OpenSSL applies the
        // constraints carried IN an anchor certificate (x509_vfy.c
        // check_name_constraints, 3.1.2 :646, 3.5.8 :776).
        Assertions.assertTrue(e.getMessage().contains("name-constraint bytes beside its certificate"),
                e.getMessage());
    }

    /**
     * The same hole on the certificate side, open since phase 1: a path
     * longer than the bridge takes produced an OverflowException.
     *
     * <p>Probed at the boundary in both directions. One anchor plus 255 path
     * entries is exactly the 256 ceiling and must be ACCEPTED by the
     * parameter check — it then fails as an ordinary validation failure,
     * which is a different exception and is what proves the check sits where
     * it should rather than one short.
     */
    @Test
    public void tooManyCertificatesIsRefusedTypedRatherThanAsAnOverflow() throws Exception
    {
        X509Certificate ee = PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        CertPath atCeiling = cf.generateCertPath(
                new ArrayList<X509Certificate>(Collections.nCopies(255, ee)));
        CertPathValidatorException accepted = Assertions.assertThrows(
                CertPathValidatorException.class,
                () -> validator().validate(atCeiling, anchoredAtRoot()),
                "1 anchor + 255 path entries is exactly 256: the parameter check must accept, "
                        + "and the path then fails validation on its own merits");
        Assertions.assertFalse(accepted.getMessage().contains("too many certificates"),
                "at the ceiling this must NOT be the parameter refusal: " + accepted.getMessage());

        CertPath over = cf.generateCertPath(
                new ArrayList<X509Certificate>(Collections.nCopies(256, ee)));
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> validator().validate(over, anchoredAtRoot()));
        Assertions.assertTrue(e.getMessage().contains("too many certificates: 257"),
                e.getMessage());
    }

    /** N1: no anchors must be refused typed, never reach the native assert. */
    @Test
    public void anEmptyAnchorSetIsRefusedTyped() throws Exception
    {
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> new PKIXParameters(Collections.<TrustAnchor>emptySet()),
                "the JCE itself refuses an empty anchor set");
    }

    /** N1: an empty path must be refused typed, never reach the native assert. */
    @Test
    public void anEmptyCertPathIsRefusedTyped() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath empty = cf.generateCertPath(new ArrayList<X509Certificate>());
        Assertions.assertThrows(CertPathValidatorException.class,
                () -> validator().validate(empty, anchoredAtRoot()));
    }

    /**
     * P3: X509_V_FLAG_PARTIAL_CHAIN, so a chain may terminate at ANY trusted
     * certificate — JCE anchor semantics. Every PKITS anchor is self-signed and
     * cannot tell the two apart, so this anchors at Good CA, which is issued by
     * the root and is therefore NOT self-signed. Without PARTIAL_CHAIN OpenSSL
     * would demand a self-signed root and refuse for the wrong reason.
     */
    @Test
    public void aNonSelfSignedTrustAnchorIsAccepted() throws Exception
    {
        X509Certificate goodCa = PkitsCertificates.certificate("GoodCACert.crt");
        Assertions.assertNotEquals(goodCa.getSubjectX500Principal(), goodCa.getIssuerX500Principal(),
                "this test needs an anchor that is NOT self-signed");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath eeOnly = cf.generateCertPath(Collections.singletonList(
                PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt")));

        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(goodCa, null)));
        p.setRevocationEnabled(false);
        validator().validate(eeOnly, p);
    }

    /**
     * V1: a certificate that is not DER X.509 is refused with the index of the
     * offending certificate, driven at the NI because a CertificateFactory
     * cannot construct such a CertPath.
     */
    @Test
    public void anUndecodableCertificateIsRefusedWithItsIndex() throws Exception
    {
        byte[] anchor = PkitsCertificates.der(PkitsCertificates.ANCHOR);
        byte[] ca = PkitsCertificates.der("GoodCACert.crt").clone();
        byte[] ee = PkitsCertificates.der("ValidCertificatePathTest1EE.crt");
        for (int i = 8; i < Math.min(40, ca.length); i++)
        {
            ca[i] ^= (byte) 0xFF;
        }
        byte[] der = new byte[anchor.length + ca.length + ee.length];
        System.arraycopy(anchor, 0, der, 0, anchor.length);
        System.arraycopy(ca, 0, der, anchor.length, ca.length);
        System.arraycopy(ee, 0, der, anchor.length + ca.length, ee.length);
        int[] sizes = {anchor.length, ca.length, ee.length};
        int[] info = new int[3 + 3];

        int rc = NISelector.CertPathNI.ni_verify(der, sizes, 3, 0, 1,
                CertPathNI.TIME_NOW, 1, 0, new byte[der.length], info);

        Assertions.assertEquals(-175, rc, "JO_CERT_DECODE_FAILED");
        Assertions.assertEquals(-175, info[0], "the code must be reported in outInfo too");
        Assertions.assertEquals(1, info[1], "outInfo[1] must name WHICH certificate failed");
    }

    /**
     * V1 at the SPI, which is where a caller meets it. A CertificateFactory
     * cannot build a CertPath holding undecodable DER, so this wraps a real
     * certificate in an X509Certificate whose getEncoded() returns corrupt
     * bytes — it satisfies the instanceof check and reaches the native decode.
     * <p>
     * Red against the tree before T1: baseErrorHandler ran first and threw
     * IllegalStateException, so the typed exception below was unreachable.
     */
    @Test
    public void anUndecodableCertificateSurfacesTypedFromTheSpiWithItsIndex() throws Exception
    {
        X509Certificate ee = PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt");
        X509Certificate ca = PkitsCertificates.certificate("GoodCACert.crt");
        byte[] corrupt = ca.getEncoded().clone();
        for (int i = 8; i < Math.min(40, corrupt.length); i++)
        {
            corrupt[i] ^= (byte) 0xFF;
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath cp = cf.generateCertPath(java.util.Arrays.asList(ee, new CorruptEncoding(ca, corrupt)));

        CertPathValidatorException e = Assertions.assertThrows(CertPathValidatorException.class,
                () -> validator().validate(cp, anchoredAtRoot()));
        Assertions.assertTrue(e.getMessage().contains("not valid DER X.509"),
                "expected the typed decode message, got: " + e.getMessage());
        Assertions.assertEquals(1, e.getIndex(),
                "the exception must name the offending certificate's index in the path");
    }

    /** An X509Certificate that encodes to whatever it is told. */
    private static final class CorruptEncoding extends X509Certificate
    {
        private final X509Certificate delegate;
        private final byte[] encoding;

        CorruptEncoding(X509Certificate delegate, byte[] encoding)
        {
            this.delegate = delegate;
            this.encoding = encoding;
        }

        public byte[] getEncoded()
        {
            return encoding.clone();
        }

        public void checkValidity() { }
        public void checkValidity(java.util.Date d) { }
        public int getVersion() { return delegate.getVersion(); }
        public java.math.BigInteger getSerialNumber() { return delegate.getSerialNumber(); }
        public java.security.Principal getIssuerDN() { return delegate.getIssuerDN(); }
        public java.security.Principal getSubjectDN() { return delegate.getSubjectDN(); }
        public java.util.Date getNotBefore() { return delegate.getNotBefore(); }
        public java.util.Date getNotAfter() { return delegate.getNotAfter(); }
        public byte[] getTBSCertificate() throws java.security.cert.CertificateEncodingException
        { return delegate.getTBSCertificate(); }
        public byte[] getSignature() { return delegate.getSignature(); }
        public String getSigAlgName() { return delegate.getSigAlgName(); }
        public String getSigAlgOID() { return delegate.getSigAlgOID(); }
        public byte[] getSigAlgParams() { return delegate.getSigAlgParams(); }
        public boolean[] getIssuerUniqueID() { return delegate.getIssuerUniqueID(); }
        public boolean[] getSubjectUniqueID() { return delegate.getSubjectUniqueID(); }
        public boolean[] getKeyUsage() { return delegate.getKeyUsage(); }
        public int getBasicConstraints() { return delegate.getBasicConstraints(); }
        public void verify(java.security.PublicKey k) { }
        public void verify(java.security.PublicKey k, String s) { }
        public String toString() { return delegate.toString(); }
        public java.security.PublicKey getPublicKey() { return delegate.getPublicKey(); }
        public boolean hasUnsupportedCriticalExtension() { return false; }
        public java.util.Set<String> getCriticalExtensionOIDs() { return delegate.getCriticalExtensionOIDs(); }
        public java.util.Set<String> getNonCriticalExtensionOIDs() { return delegate.getNonCriticalExtensionOIDs(); }
        public byte[] getExtensionValue(String oid) { return delegate.getExtensionValue(oid); }
    }

    /**
     * P4: the path is validated EXACTLY as given. A path carrying a
     * certificate that is not on the end entity's chain must be REFUSED, not
     * quietly validated with that certificate skipped.
     *
     * <p>The fixture is the path our own harness used to build for PKITS
     * 4.5.6: the row lists {@code BasicSelfIssuedCRLSigningKeyCRLCert}
     * alongside the CA, that certificate signs the row's CRLs rather than the
     * end entity, and a naive reverse of the row put it at path index 1. We
     * accepted it — a self-issued skip in {@code assertBuiltChainMatches} let
     * it through — while the JDK refused it for "keyCertSign bit is not set"
     * and BouncyCastle for "lacks BasicConstraints". Accepting a path
     * containing a member we never validated was more lenient than either.
     *
     * <p>The JDK's refusal is asserted alongside ours: it is what makes this a
     * statement about the contract rather than about our implementation, and
     * it fails loudly if the fixture ever stops being a wrongly-built path.
     */
    @Test
    public void aPathCarryingACertificateOffTheChainIsRefused() throws Exception
    {
        PkitsCertificates.Case c = null;
        for (PkitsCertificates.Case cand : PkitsCertificates.cases())
        {
            if ("4.5.6".equals(cand.number))
            {
                c = cand;
            }
        }
        Assertions.assertNotNull(c, "vacuity guard: 4.5.6 is not in the committed table");

        // The chainer's answer: the CRL-signing certificate is NOT reached.
        List<X509Certificate> chained = PkitsCertificates.chain(c);
        Assertions.assertEquals(2, chained.size(),
                "4.5.6's real path is the end entity and its CA");

        // The old naive construction: every row certificate, reversed.
        List<X509Certificate> naive = new ArrayList<X509Certificate>();
        naive.add(PkitsCertificates.certificate(c.endEntity));
        for (int i = c.intermediates.size() - 1; i >= 0; i--)
        {
            naive.add(PkitsCertificates.certificate(c.intermediates.get(i)));
        }
        Assertions.assertEquals(3, naive.size(), "vacuity guard: the naive path must be longer");
        Assertions.assertFalse(chained.contains(naive.get(1)),
                "vacuity guard: the extra certificate must be one the chain does not reach");

        CertPath bad = CertificateFactory.getInstance("X.509").generateCertPath(naive);
        PKIXParameters p = new PKIXParameters(Collections.singleton(new TrustAnchor(
                PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)));
        p.setRevocationEnabled(false);

        Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME)
                        .validate(bad, p),
                "a path carrying a certificate off the chain must be refused");

        // The reference: the JDK refuses the same path.
        Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", "SUN").validate(bad, p),
                "the JDK must refuse it too, or this fixture is not what it claims");

        // The control: the CHAINED path still validates, so the refusal is
        // about the extra certificate and not about the fixture at large.
        CertPath good = CertificateFactory.getInstance("X.509").generateCertPath(chained);
        CertPathValidator.getInstance("PKIX", JostleProvider.PROVIDER_NAME).validate(good, p);
    }
}
