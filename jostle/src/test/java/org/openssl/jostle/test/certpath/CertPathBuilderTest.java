package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Certification path building: the target is selected in Java, the chain by OpenSSL. */
public class CertPathBuilderTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static CertPathBuilder builder() throws Exception
    {
        return CertPathBuilder.getInstance("PKIX", JostleProvider.PROVIDER_NAME);
    }

    private static PKIXBuilderParameters params(X509CertSelector sel, X509Certificate... pool)
            throws Exception
    {
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(
                new TrustAnchor(PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)), sel);
        p.setRevocationEnabled(false);
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        Collections.addAll(certs, pool);
        p.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certs)));
        return p;
    }

    @Test
    public void buildsThePathToASelectedTarget() throws Exception
    {
        X509Certificate ee = PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt");
        X509Certificate ca = PkitsCertificates.certificate("GoodCACert.crt");

        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(ee);

        CertPathBuilderResult r = builder().build(params(sel, ee, ca));
        List<? extends java.security.cert.Certificate> built = r.getCertPath().getCertificates();

        Assertions.assertEquals(2, built.size(), "expected EE and CA, with the anchor excluded");
        Assertions.assertEquals(ee, built.get(0), "the path must start at the target");
        Assertions.assertEquals(ca, built.get(1));
    }

    /**
     * A target the store holds but that cannot chain to the anchor must fail as
     * a build failure, not succeed and not throw something untyped.
     */
    @Test
    public void aTargetThatCannotChainFailsTyped() throws Exception
    {
        X509Certificate orphan = PkitsCertificates.certificate("InvalidCASignatureTest2EE.crt");
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(orphan);
        // Its issuer is deliberately absent from the store.
        Assertions.assertThrows(CertPathBuilderException.class,
                () -> builder().build(params(sel, orphan)));
    }

    /** N1: no selector must be refused typed, never reach the native assert. */
    @Test
    public void noTargetConstraintsIsRefusedTyped() throws Exception
    {
        X509Certificate ee = PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt");
        PKIXBuilderParameters p = new PKIXBuilderParameters(Collections.singleton(
                new TrustAnchor(PkitsCertificates.certificate(PkitsCertificates.ANCHOR), null)),
                new X509CertSelector());
        p.setRevocationEnabled(false);
        p.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(Collections.singletonList(ee))));
        // An empty selector matches everything, so this exercises the
        // no-match-to-anchor path rather than the missing-selector one.
        Assertions.assertThrows(CertPathBuilderException.class, () -> builder().build(p));
    }

    /** P1 applies to the builder too: revocation is honoured, not dropped. */
    @Test
    public void revocationEnabledWithNoCrlSuppliedFailsTheBuildRatherThanPassingIt() throws Exception
    {
        X509Certificate ee = PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt");
        X509Certificate ca = PkitsCertificates.certificate("GoodCACert.crt");
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(ee);
        PKIXBuilderParameters p = params(sel, ee, ca);
        p.setRevocationEnabled(true);
        // The builder's CertStores hold certificates and no CRL, so the same
        // path that builds with revocation off must not build with it on.
        Assertions.assertThrows(CertPathBuilderException.class, () -> builder().build(p));

        p.setRevocationEnabled(false);
        Assertions.assertNotNull(builder().build(p), "the control: it builds without revocation");
    }

    /**
     * B1: maxPathLength is the caller's constraint. The same path that builds
     * under the default must be refused at 0, which admits no non-self-issued
     * intermediate at all.
     */
    @Test
    public void maxPathLengthIsHonouredRatherThanIgnored() throws Exception
    {
        X509Certificate ee = PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt");
        X509Certificate ca = PkitsCertificates.certificate("GoodCACert.crt");
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(ee);

        // Default (5) builds: one non-self-issued intermediate, Good CA.
        Assertions.assertEquals(2, builder().build(params(sel, ee, ca))
                .getCertPath().getCertificates().size());

        PKIXBuilderParameters strict = params(sel, ee, ca);
        strict.setMaxPathLength(0);
        CertPathBuilderException e = Assertions.assertThrows(CertPathBuilderException.class,
                () -> builder().build(strict));
        Assertions.assertTrue(e.getMessage().contains("maxPathLength 0")
                        && e.getMessage().contains("1 non-self-issued"),
                "the message must name both numbers, got: " + e.getMessage());
    }

    /**
     * B2: a selector can match several certificates, and the builder tries each
     * in turn. Both end entities here are issued by Good CA, so the selector
     * matches both, but only one can chain — the result must be that one
     * whichever order they come out of the store in.
     */
    @Test
    public void severalMatchingTargetsAreTriedUntilOneBuilds() throws Exception
    {
        X509Certificate good = PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt");
        X509Certificate bad = PkitsCertificates.certificate("InvalidEESignatureTest3EE.crt");
        X509Certificate ca = PkitsCertificates.certificate("GoodCACert.crt");

        X509CertSelector sel = new X509CertSelector();
        sel.setIssuer(ca.getSubjectX500Principal().getEncoded());
        Assertions.assertTrue(sel.match(good) && sel.match(bad),
                "this test needs a selector that matches BOTH end entities");

        // Both orders, so neither the success branch nor the "try the next
        // one" branch depends on which the store yields first.
        Assertions.assertEquals(good, builder().build(params(sel, bad, good, ca))
                .getCertPath().getCertificates().get(0));
        Assertions.assertEquals(good, builder().build(params(sel, good, bad, ca))
                .getCertPath().getCertificates().get(0));
    }

    /**
     * The certificates in the built path are decoded by JOSTLE's X.509
     * factory, not by whatever JCA order offers (MT-98).
     *
     * <p>They are the SPI's RESULT — the public key in the
     * {@code PKIXCertPathBuilderResult} comes from the first of them — so an
     * unpinned factory let an arbitrary provider, normally SUN, decide what we
     * hand back. Note {@code equals} cannot see this: the wrapper delegates,
     * so {@code buildsThePathToASelectedTarget} passed throughout.
     */
    @Test
    public void theBuiltPathsCertificatesAreDecodedByJostle() throws Exception
    {
        X509Certificate ee = PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt");
        X509Certificate ca = PkitsCertificates.certificate("GoodCACert.crt");

        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(ee);

        CertPathBuilderResult r = builder().build(params(sel, ee, ca));
        List<? extends java.security.cert.Certificate> built = r.getCertPath().getCertificates();
        Assertions.assertFalse(built.isEmpty(), "vacuity guard: the build produced no path");

        for (java.security.cert.Certificate c : built)
        {
            Assertions.assertTrue(
                    c.getClass().getName().startsWith("org.openssl.jostle."),
                    "a certificate in our own result was decoded elsewhere: "
                            + c.getClass().getName());
        }
        Assertions.assertTrue(
                r.getCertPath().getClass().getName().startsWith("org.openssl.jostle.")
                        || built.get(0).getClass().getName().startsWith("org.openssl.jostle."),
                "the CertPath must be built by the same factory that decoded its contents");
    }

    /**
     * A builder bound to an instance that cannot serve X.509 fails loudly
     * rather than borrowing the registered provider's factory.
     *
     * <p>The discriminator between an instance pin and a name pin: both
     * providers decode the same bytes, so only a deliberately incapable
     * instance separates them (see {@code StrippedJostleProvider}).
     */
    @Test
    public void aBoundBuilderDoesNotBorrowAnX509FactoryFromTheRegistry() throws Exception
    {
        Assertions.assertNotNull(Security.getProvider(JostleProvider.PROVIDER_NAME),
                "the capable provider must be registered, or the test proves nothing");

        java.security.Provider stripped =
                new org.openssl.jostle.test.provider.StrippedJostleProvider(
                        "CertificateFactory", "X.509");
        Assertions.assertNull(stripped.getService("CertificateFactory", "X.509"),
                "vacuity guard: the strip must actually have removed the service");
        Assertions.assertNotNull(stripped.getService("CertPathBuilder", "PKIX"),
                "the stripped instance must still serve the builder itself");

        X509Certificate ee = PkitsCertificates.certificate("ValidCertificatePathTest1EE.crt");
        X509Certificate ca = PkitsCertificates.certificate("GoodCACert.crt");
        X509CertSelector sel = new X509CertSelector();
        sel.setCertificate(ee);

        CertPathBuilder b = CertPathBuilder.getInstance("PKIX", stripped);
        PKIXBuilderParameters p = params(sel, ee, ca);
        Assertions.assertThrows(CertPathBuilderException.class, () -> b.build(p),
                "a builder bound to an instance lacking X.509 must FAIL, not borrow"
                        + " the registered provider's factory");
    }
}
