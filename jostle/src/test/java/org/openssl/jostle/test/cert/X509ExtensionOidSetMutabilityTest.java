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

package org.openssl.jostle.test.cert;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * The JDK's {@code DistributionPointFetcher} and {@code RevocationChecker},
 * and BouncyCastle's {@code PKIXCertPathReviewer}, call {@code remove()} on
 * the sets {@code getCriticalExtensionOIDs()}/{@code getNonCriticalExtensionOIDs()}
 * return; SUN and BC always hand back a fresh copy, so these do too.
 */
public class X509ExtensionOidSetMutabilityTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** A CA cert, an EE cert naming it via CRLDP, and a CRL the CA issued naming an IDP. */
    private static final class Fixture
    {
        final X509Certificate caCert;
        final X509Certificate eeCert;
        final X509CRL crl;

        Fixture(X509Certificate caCert, X509Certificate eeCert, X509CRL crl)
        {
            this.caCert = caCert;
            this.eeCert = eeCert;
            this.crl = crl;
        }
    }

    private static KeyPair rsaKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate selfSignedCa(X500Name caDn, KeyPair caKp, Date notBefore, Date notAfter)
        throws Exception
    {
        JcaX509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                caDn, BigInteger.valueOf(1), notBefore, notAfter, caDn, caKp.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        ContentSigner caSelfSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(JSL).build(caKp.getPrivate());
        return new JcaX509CertificateConverter().setProvider(JSL).getCertificate(caBuilder.build(caSelfSigner));
    }

    /** Distribution point with a directoryName equal to the CA's own DN. */
    private static Fixture buildFixture() throws Exception
    {
        KeyPair caKp = rsaKeyPair();
        KeyPair eeKp = rsaKeyPair();

        X500Name caDn = new X500Name("CN=Jostle Test CA");
        X500Name eeDn = new X500Name("CN=Jostle Test EE");
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L * 24 * 30);

        X509Certificate caCert = selfSignedCa(caDn, caKp, notBefore, notAfter);

        DistributionPointName dpName = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.directoryName, caDn)));
        DistributionPoint dp = new DistributionPoint(dpName, null, null);
        CRLDistPoint crldp = new CRLDistPoint(new DistributionPoint[]{dp});

        JcaX509v3CertificateBuilder eeBuilder = new JcaX509v3CertificateBuilder(
                caDn, BigInteger.valueOf(2), notBefore, notAfter, eeDn, eeKp.getPublic());
        eeBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        eeBuilder.addExtension(Extension.cRLDistributionPoints, false, crldp);
        ContentSigner eeSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(JSL).build(caKp.getPrivate());
        X509Certificate eeCert = new JcaX509CertificateConverter().setProvider(JSL)
                .getCertificate(eeBuilder.build(eeSigner));

        // No onlySomeReasons restriction: an IDP that only covers SOME reasons
        // can never satisfy the validator's "all reasons covered" requirement
        // from a single CRL, which fails validation for a reason unrelated to
        // this test and never reaches verifyCRL's critical-extension check.
        JcaX509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(caCert, notBefore);
        crlBuilder.setNextUpdate(notAfter);
        IssuingDistributionPoint idp = new IssuingDistributionPoint(dpName, false, false, null, false, false);
        crlBuilder.addExtension(Extension.issuingDistributionPoint, true, idp);
        crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        ContentSigner crlSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(JSL).build(caKp.getPrivate());
        X509CRL crl = new JcaX509CRLConverter().setProvider(JSL).getCRL(crlBuilder.build(crlSigner));

        return new Fixture(caCert, eeCert, crl);
    }

    /** Same as {@link #buildFixture()}, but the CRL lists the EE certificate as revoked, entry extensions included. */
    private static Fixture buildFixtureWithRevokedEntry() throws Exception
    {
        KeyPair caKp = rsaKeyPair();
        KeyPair eeKp = rsaKeyPair();

        X500Name caDn = new X500Name("CN=Jostle Test Revoking CA");
        X500Name eeDn = new X500Name("CN=Jostle Test Revoked EE");
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L * 24 * 30);

        X509Certificate caCert = selfSignedCa(caDn, caKp, notBefore, notAfter);

        JcaX509v3CertificateBuilder eeBuilder = new JcaX509v3CertificateBuilder(
                caDn, BigInteger.valueOf(3), notBefore, notAfter, eeDn, eeKp.getPublic());
        eeBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        ContentSigner eeSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(JSL).build(caKp.getPrivate());
        X509Certificate eeCert = new JcaX509CertificateConverter().setProvider(JSL)
                .getCertificate(eeBuilder.build(eeSigner));

        ExtensionsGenerator entryExtGen = new ExtensionsGenerator();
        // reasonCode critical: RevocationChecker.checkApprovedCRLs explicitly
        // recognises and strips a critical reasonCode/certificateIssuer
        // before checking for anything unrecognised left over
        // (RevocationChecker.java:653-655), so this is the one entry
        // extension that can be critical without the JDK refusing the whole
        // CRL for an unrecognised critical extension.
        entryExtGen.addExtension(Extension.reasonCode, true, CRLReason.lookup(CRLReason.keyCompromise));
        entryExtGen.addExtension(Extension.invalidityDate, false, new ASN1GeneralizedTime(notBefore));

        JcaX509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(caCert, notBefore);
        crlBuilder.setNextUpdate(notAfter);
        crlBuilder.addCRLEntry(eeCert.getSerialNumber(), notBefore, entryExtGen.generate());
        ContentSigner crlSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(JSL).build(caKp.getPrivate());
        X509CRL crl = new JcaX509CRLConverter().setProvider(JSL).getCRL(crlBuilder.build(crlSigner));

        return new Fixture(caCert, eeCert, crl);
    }

    // ----- direct cells: remove() on each of the six sets -----

    @Test
    public void certificateCriticalExtensionOidsSurvivesRemove() throws Exception
    {
        X509Certificate cert = buildFixture().eeCert;
        assertRemoveDoesNotAffectASecondCall(cert.getCriticalExtensionOIDs(),
                cert::getCriticalExtensionOIDs);
    }

    @Test
    public void certificateNonCriticalExtensionOidsSurvivesRemove() throws Exception
    {
        X509Certificate cert = buildFixture().eeCert;
        assertRemoveDoesNotAffectASecondCall(cert.getNonCriticalExtensionOIDs(),
                cert::getNonCriticalExtensionOIDs);
    }

    @Test
    public void crlCriticalExtensionOidsSurvivesRemove() throws Exception
    {
        X509CRL crl = buildFixture().crl;
        assertRemoveDoesNotAffectASecondCall(crl.getCriticalExtensionOIDs(),
                crl::getCriticalExtensionOIDs);
    }

    @Test
    public void crlNonCriticalExtensionOidsSurvivesRemove() throws Exception
    {
        X509CRL crl = buildFixture().crl;
        assertRemoveDoesNotAffectASecondCall(crl.getNonCriticalExtensionOIDs(),
                crl::getNonCriticalExtensionOIDs);
    }

    @Test
    public void crlEntryNonCriticalExtensionOidsSurvivesRemove() throws Exception
    {
        X509CRLEntry entry = soleEntry(buildFixtureWithRevokedEntry().crl);
        assertRemoveDoesNotAffectASecondCall(entry.getNonCriticalExtensionOIDs(),
                entry::getNonCriticalExtensionOIDs);
    }

    @Test
    public void crlEntryCriticalExtensionOidsSurvivesRemove() throws Exception
    {
        X509CRLEntry entry = soleEntry(buildFixtureWithRevokedEntry().crl);
        assertRemoveDoesNotAffectASecondCall(entry.getCriticalExtensionOIDs(),
                entry::getCriticalExtensionOIDs);
    }

    /** No entry extensions at all: both getters must return null, not an empty set. */
    @Test
    public void crlEntryWithNoExtensionsReportsNullSets() throws Exception
    {
        KeyPair caKp = rsaKeyPair();
        X500Name caDn = new X500Name("CN=Jostle Test Bare CA");
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 3600_000L * 24 * 30);
        X509Certificate caCert = selfSignedCa(caDn, caKp, notBefore, notAfter);

        JcaX509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(caCert, notBefore);
        crlBuilder.setNextUpdate(notAfter);
        crlBuilder.addCRLEntry(BigInteger.valueOf(9), notBefore, 0);
        ContentSigner crlSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(JSL).build(caKp.getPrivate());
        X509CRL crl = new JcaX509CRLConverter().setProvider(JSL).getCRL(crlBuilder.build(crlSigner));

        X509CRLEntry entry = soleEntry(crl);
        // reason 0 ("not to be used", X509v2CRLBuilder's own javadoc) adds no
        // reasonCode extension at all, so this entry carries none.
        Assertions.assertNull(entry.getCriticalExtensionOIDs());
        Assertions.assertNull(entry.getNonCriticalExtensionOIDs());
    }

    private static X509CRLEntry soleEntry(X509CRL crl)
    {
        Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
        Assertions.assertNotNull(entries, "test precondition: fixture CRL must carry one entry");
        Assertions.assertEquals(1, entries.size(), "test precondition: fixture CRL must carry exactly one entry");
        return entries.iterator().next();
    }

    private interface SetSupplier
    {
        Set<String> get();
    }

    private static void assertRemoveDoesNotAffectASecondCall(Set<String> first, SetSupplier supplier)
    {
        Assertions.assertNotNull(first, "test precondition: fixture must carry at least one extension");
        Assertions.assertFalse(first.isEmpty(), "test precondition: fixture must carry at least one extension");
        String someOid = first.iterator().next();

        Assertions.assertDoesNotThrow(() -> first.remove(someOid),
                "getCriticalExtensionOIDs()/getNonCriticalExtensionOIDs() must return a mutable copy");

        Set<String> second = supplier.get();
        Assertions.assertTrue(second.contains(someOid),
                "removing from a returned set must not affect what a later call returns");
    }

    // ----- the real callers: JDK PKIX revocation checking -----

    @Test
    public void pkixRevocationCheckThroughDistributionPointFetcherSucceeds() throws Exception
    {
        System.setProperty("com.sun.security.enableCRLDP", "true");
        Security.setProperty("ocsp.enable", "false");

        Fixture f = buildFixture();

        CertPath certPath = CertificateFactory.getInstance("X.509", JSL)
                .generateCertPath(Collections.singletonList(f.eeCert));

        PKIXParameters params = new PKIXParameters(
                Collections.singleton(new TrustAnchor(f.caCert, null)));
        params.setRevocationEnabled(true);
        List<Object> storeObjects = new ArrayList<>();
        storeObjects.add(f.crl);
        storeObjects.add(f.caCert);
        params.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(storeObjects)));
        params.setDate(new Date());

        Assertions.assertDoesNotThrow(() ->
                        CertPathValidator.getInstance("PKIX").validate(certPath, params),
                "revocation-enabled PKIX validation over a Jostle-parsed certificate and CRL, "
                        + "reached through DistributionPointFetcher, must not throw "
                        + "UnsupportedOperationException from an immutable extension-OID set");
    }

    @Test
    public void pkixRevocationCheckReportsRevokedNotUnsupportedOperation() throws Exception
    {
        Security.setProperty("ocsp.enable", "false");

        Fixture f = buildFixtureWithRevokedEntry();

        CertPath certPath = CertificateFactory.getInstance("X.509", JSL)
                .generateCertPath(Collections.singletonList(f.eeCert));

        PKIXParameters params = new PKIXParameters(
                Collections.singleton(new TrustAnchor(f.caCert, null)));
        params.setRevocationEnabled(true);
        params.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(Collections.singletonList(f.crl))));
        params.setDate(new Date());

        CertPathValidatorException thrown = Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX").validate(certPath, params));
        Assertions.assertEquals(CertPathValidatorException.BasicReason.REVOKED, thrown.getReason(),
                "a CRL entry extension must not turn a revocation finding into an "
                        + "UnsupportedOperationException");
    }
}
