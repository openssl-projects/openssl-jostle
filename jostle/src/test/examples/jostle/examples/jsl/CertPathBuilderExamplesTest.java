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

import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

/**
 * PKIX path building: from a target certificate and a pool of candidate certificates and CRLs, find a path to
 * a trust anchor. The path is validated as it is built, revocation included.
 */
public class CertPathBuilderExamplesTest
        extends JslExamples
{
    /**
     * Select the end entity by certificate and let the builder find its CA in the `CertStore`.
     */
    @Test
    public void buildAPathToATarget()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSL");
        X509Certificate root = (X509Certificate) cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCertificate.crt"));
        X509Certificate target = (X509Certificate) cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/ValidCertificatePathTest1EE.crt"));
        CertStore pool = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(
                cf.generateCertificate(getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACert.crt")),
                target,
                cf.generateCRL(getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCRL.crl")),
                cf.generateCRL(getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACRL.crl")))));

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(target);
        PKIXBuilderParameters params = new PKIXBuilderParameters(
                Collections.singleton(new TrustAnchor(root, null)), selector);
        params.addCertStore(pool);
        params.setDate(new Date(1590969600000L)); // 2020-06-01
        PKIXCertPathBuilderResult result =
                (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX", "JSL").build(params);
        Assertions.assertEquals(2, result.getCertPath().getCertificates().size());
        Assertions.assertEquals(root, result.getTrustAnchor().getTrustedCert());
    }
}
