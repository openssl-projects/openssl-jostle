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

import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.List;

/**
 * The Collection certificate store: certificates and CRLs held in a collection, selected by the standard
 * selectors, for a path builder or validator to search. The collection is not copied, so later changes to it are
 * seen.
 */
public class CertStoreExamplesTest
        extends JslExamples
{
    /**
     * Select a certificate by subject and a CRL by issuer; a null selector returns every object of its kind.
     */
    @Test
    public void selectCertificatesAndCrls()
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "JSL");
        List<Object> pool = new ArrayList<Object>();
        pool.add(cf.generateCertificate(getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACert.crt")));
        pool.add(cf.generateCertificate(
                getClass().getResourceAsStream("/jostle/examples/pkits/ValidCertificatePathTest1EE.crt")));
        pool.add(cf.generateCRL(getClass().getResourceAsStream("/jostle/examples/pkits/GoodCACRL.crl")));
        CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool), "JSL");

        X509CertSelector bySubject = new X509CertSelector();
        bySubject.setSubject("CN=Good CA, O=Test Certificates 2011, C=US");
        Assertions.assertEquals(1, store.getCertificates(bySubject).size());
        Assertions.assertEquals(2, store.getCertificates(null).size());

        X509CRLSelector byIssuer = new X509CRLSelector();
        byIssuer.addIssuerName("CN=Good CA, O=Test Certificates 2011, C=US");
        Assertions.assertEquals(1, store.getCRLs(byIssuer).size());

        pool.add(cf.generateCRL(getClass().getResourceAsStream("/jostle/examples/pkits/TrustAnchorRootCRL.crl")));
        Assertions.assertEquals(2, store.getCRLs(null).size());
    }
}
