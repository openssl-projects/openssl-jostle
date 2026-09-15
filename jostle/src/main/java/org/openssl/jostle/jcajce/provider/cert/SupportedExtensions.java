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

package org.openssl.jostle.jcajce.provider.cert;

import org.openssl.jostle.util.asn1.oids.X509ObjectIdentifiers;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Which critical extensions this provider understands.
 *
 * <p>This is a statement about US, not about OpenSSL, which is why it is a
 * list here rather than a native query: {@code hasUnsupportedCriticalExtension}
 * asks whether the CALLER can rely on us having honoured every critical
 * extension, and only we can answer that.
 *
 * <p>The corpus barely exercises it — across 578 PKITS files exactly one
 * certificate and one CRL carry a critical extension outside this set (the
 * private MISSI OID 2.16.840.1.101.2.1.12.2), and SUN and BouncyCastle agree
 * with each other on every file. So a test built only on the corpus cannot
 * tell this list from a different one, and the guard needs a synthetic
 * certificate carrying a critical extension deliberately left out.
 */
final class SupportedExtensions
{
    /** RFC 5280 §4.2 certificate extensions. */
    private static final Set<String> CERTIFICATE = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    X509ObjectIdentifiers.id_ce_keyUsage.getId(),
                    X509ObjectIdentifiers.id_ce_subjectAltName.getId(),
                    X509ObjectIdentifiers.id_ce_issuerAltName.getId(),
                    X509ObjectIdentifiers.id_ce_basicConstraints.getId(),
                    X509ObjectIdentifiers.id_ce_nameConstraints.getId(),
                    X509ObjectIdentifiers.id_ce_cRLDistributionPoints.getId(),
                    X509ObjectIdentifiers.id_ce_certificatePolicies.getId(),
                    X509ObjectIdentifiers.id_ce_policyMappings.getId(),
                    X509ObjectIdentifiers.id_ce_policyConstraints.getId(),
                    X509ObjectIdentifiers.id_ce_extKeyUsage.getId(),
                    X509ObjectIdentifiers.id_ce_inhibitAnyPolicy.getId())));

    /** RFC 5280 §5.2 CRL extensions. */
    private static final Set<String> CRL = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    X509ObjectIdentifiers.id_ce_issuerAltName.getId(),
                    X509ObjectIdentifiers.id_ce_cRLNumber.getId(),
                    X509ObjectIdentifiers.id_ce_deltaCRLIndicator.getId(),
                    X509ObjectIdentifiers.id_ce_issuingDistributionPoint.getId(),
                    X509ObjectIdentifiers.id_ce_authorityKeyIdentifier.getId(),
                    X509ObjectIdentifiers.id_ce_freshestCRL.getId())));

    /** RFC 5280 §5.3 CRL ENTRY extensions. */
    private static final Set<String> CRL_ENTRY = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    X509ObjectIdentifiers.id_ce_cRLReasons.getId(),
                    X509ObjectIdentifiers.id_ce_invalidityDate.getId(),
                    X509ObjectIdentifiers.id_ce_certificateIssuer.getId())));

    private SupportedExtensions()
    {
    }

    static boolean isSupportedOnCertificate(String oid)
    {
        return CERTIFICATE.contains(oid);
    }

    static boolean isSupportedOnCrl(String oid)
    {
        return CRL.contains(oid);
    }

    static boolean isSupportedOnCrlEntry(String oid)
    {
        return CRL_ENTRY.contains(oid);
    }
}
