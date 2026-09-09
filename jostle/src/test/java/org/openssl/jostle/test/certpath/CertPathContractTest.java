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
     * P1. isRevocationEnabled() defaults TRUE, so a caller who never asked for
     * revocation to be dropped must not get a green result with it dropped.
     */
    @Test
    public void revocationEnabledIsRefusedRatherThanSilentlySkipped() throws Exception
    {
        PKIXParameters p = new PKIXParameters(Collections.singleton(
                new TrustAnchor(PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)));
        Assertions.assertTrue(p.isRevocationEnabled(), "the JCE default must still be true");

        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> validator().validate(goodPath(), p));
        Assertions.assertTrue(e.getMessage().contains("setRevocationEnabled(false)"),
                "the message must say how to proceed: " + e.getMessage());

        // And the same path validates once the caller opts out explicitly.
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
        Assertions.assertTrue(e.getMessage().contains("name constraints"), e.getMessage());
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

        int rc = NISelector.CertPathNI.ni_verify(der, sizes, 3, 1,
                CertPathNI.TIME_NOW, 1, new byte[der.length], info);

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
}
