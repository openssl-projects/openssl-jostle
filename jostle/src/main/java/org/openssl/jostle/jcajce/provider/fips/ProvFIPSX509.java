/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.cert.X509CertificateFactorySpi;

import java.util.HashMap;
import java.util.Map;

/**
 * X.509 CertificateFactory registration for the FIPS provider, mirroring
 * ProvX509 in provider-bound mode.
 *
 * <p>Parsing the certificate structure is ASN.1 work, not a cryptographic
 * service, so the SPI's SUN parsing delegate is FIPS-neutral. What this
 * registration binds to the FIPS boundary is everything cryptographic that
 * flows FROM a parsed certificate: public keys are re-derived exclusively
 * through JSLFIPS KeyFactories (no fallback to a JDK key — an algorithm the
 * module does not serve, e.g. EdDSA, fails loud with a ProviderException),
 * and one-argument {@code verify()} is pinned to JSLFIPS rather than left to
 * JCA provider search.</p>
 *
 * <p>CRLs currently pass through unwrapped: {@code X509CRL.verify()} on a
 * returned CRL is NOT provider-bound. Callers doing CRL signature checking
 * under FIPS must pin the provider themselves via
 * {@code crl.verify(key, JostleFIPSProvider.PROVIDER_NAME)}.</p>
 */
class ProvFIPSX509
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.cert.";

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();
        provider.addAlgorithmImplementation("CertificateFactory", "X.509",
                PREFIX + "X509CertificateFactorySpi", attr,
                (arg) -> new X509CertificateFactorySpi(JostleFIPSProvider.PROVIDER_NAME, true));
        provider.addAlias("CertificateFactory", "X.509", "X509");
    }
}
