/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.jcajce.provider.cert.X509CertificateFactorySpi;
import org.openssl.jostle.jcajce.provider.certpath.JostleCertPathBuilderSpi;
import org.openssl.jostle.jcajce.provider.certpath.JostleCertPathValidatorSpi;

import java.util.HashMap;
import java.util.Map;

class ProvX509
{

    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();
        provider.addAlgorithmImplementation("CertificateFactory", "X.509", X509CertificateFactorySpi.class.getName(), attr, (arg) -> new X509CertificateFactorySpi());
        provider.addAlias("CertificateFactory", "X.509", "X509");

        // PKIX certification path validation over OpenSSL's X509_verify_cert.
        // JSL only in this phase; no revocation, no policy processing — both
        // refused typed rather than ignored (see JostleCertPathValidatorSpi).
        provider.addAlgorithmImplementation("CertPathValidator", "PKIX",
                JostleCertPathValidatorSpi.class.getName(), attr,
                (arg) -> new JostleCertPathValidatorSpi());
        provider.addAlgorithmImplementation("CertPathBuilder", "PKIX",
                JostleCertPathBuilderSpi.class.getName(), attr,
                (arg) -> new JostleCertPathBuilderSpi());
    }
}
