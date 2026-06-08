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

import java.util.HashMap;
import java.util.Map;

class ProvX509
{
    private static final String PREFIX = ProvX509.class.getPackage().getName() + ".cert.";

    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();
        provider.addAlgorithmImplementation("CertificateFactory", "X.509", PREFIX + "X509CertificateFactorySpi", attr, (arg) -> new X509CertificateFactorySpi());
        provider.addAlias("CertificateFactory", "X.509", "X509");
    }
}
