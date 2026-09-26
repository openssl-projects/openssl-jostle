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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

/**
 * PKIX path validation. Revocation is checked by default, against CRLs from the caller's `CertStore`s, so a
 * certificate with no usable CRL fails rather than passing. Policy processing and `PKIXCertPathChecker` are not
 * supported and are refused rather than ignored. The PKITS certificates are valid 2010 to 2030, so the examples
 * validate at a fixed date.
 */
public class CertPathValidatorExamplesTest
        extends JslExamples
{
    /**
     * Validate end entity, then CA, against the root as trust anchor, with both CRLs supplied.
     */
    @Test
    public void validateAPath()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSL");
        X509Certificate root = (X509Certificate) cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCertificate.crt"));
        CertPath path = cf.generateCertPath(Arrays.asList(
                cf.generateCertificate(getClass().getResourceAsStream(
                        "/jostle/examples/pkits/ValidCertificatePathTest1EE.crt")),
                cf.generateCertificate(getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACert.crt"))));
        CertStore crls = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(
                cf.generateCRL(getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCRL.crl")),
                cf.generateCRL(getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACRL.crl")))));

        PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(root, null)));
        params.addCertStore(crls);
        params.setDate(new Date(1590969600000L)); // 2020-06-01
        CertPathValidator.getInstance("PKIX", "JSL").validate(path, params);
    }

    /**
     * A revoked end entity fails, with reason `REVOKED` naming the certificate's position in the path.
     */
    @Test
    public void aRevokedCertificateFails()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSL");
        X509Certificate root = (X509Certificate) cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCertificate.crt"));
        CertPath path = cf.generateCertPath(Arrays.asList(
                cf.generateCertificate(getClass().getResourceAsStream(
                        "/jostle/examples/pkits/InvalidRevokedEETest3EE.crt")),
                cf.generateCertificate(getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACert.crt"))));
        CertStore crls = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(
                cf.generateCRL(getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCRL.crl")),
                cf.generateCRL(getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACRL.crl")))));

        PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(root, null)));
        params.addCertStore(crls);
        params.setDate(new Date(1590969600000L)); // 2020-06-01
        CertPathValidatorException e = Assertions.assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX", "JSL").validate(path, params));
        Assertions.assertEquals(CertPathValidatorException.BasicReason.REVOKED, e.getReason());
        Assertions.assertEquals(0, e.getIndex());
    }
}
