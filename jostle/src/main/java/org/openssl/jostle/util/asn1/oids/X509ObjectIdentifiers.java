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

package org.openssl.jostle.util.asn1.oids;

import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;

/**
 * The X.509 certificate and CRL extension identifiers, {@code id-ce}.
 *
 * <p>Every arc here is cited to its definition line in RFC 5280 in the
 * standards library, read rather than recalled — these are the identifiers a
 * certificate parser compares against, so a single wrong digit silently
 * mis-classifies an extension rather than failing.
 */
public interface X509ObjectIdentifiers
{
    /**
     * 2.5.29 -- id-ce, RFC 5280 line 1485
     */
    ASN1ObjectIdentifier id_ce = new ASN1ObjectIdentifier("2.5.29").intern();

    /**
     * 2.5.29.15 -- id-ce-keyUsage, RFC 5280 line 1636
     */
    ASN1ObjectIdentifier id_ce_keyUsage = id_ce.branch("15").intern();

    /**
     * 2.5.29.17 -- id-ce-subjectAltName, RFC 5280 line 2087
     */
    ASN1ObjectIdentifier id_ce_subjectAltName = id_ce.branch("17").intern();

    /**
     * 2.5.29.18 -- id-ce-issuerAltName, RFC 5280 line 2124
     */
    ASN1ObjectIdentifier id_ce_issuerAltName = id_ce.branch("18").intern();

    /**
     * 2.5.29.19 -- id-ce-basicConstraints, RFC 5280 line 2198
     */
    ASN1ObjectIdentifier id_ce_basicConstraints = id_ce.branch("19").intern();

    /**
     * 2.5.29.20 -- id-ce-cRLNumber, RFC 5280 line 3408
     */
    ASN1ObjectIdentifier id_ce_cRLNumber = id_ce.branch("20").intern();

    /**
     * 2.5.29.21 -- id-ce-cRLReasons, RFC 5280 line 3871
     */
    ASN1ObjectIdentifier id_ce_cRLReasons = id_ce.branch("21").intern();

    /**
     * 2.5.29.24 -- id-ce-invalidityDate, RFC 5280 line 3905
     */
    ASN1ObjectIdentifier id_ce_invalidityDate = id_ce.branch("24").intern();

    /**
     * 2.5.29.27 -- id-ce-deltaCRLIndicator, RFC 5280 line 3591
     */
    ASN1ObjectIdentifier id_ce_deltaCRLIndicator = id_ce.branch("27").intern();

    /**
     * 2.5.29.28 -- id-ce-issuingDistributionPoint, RFC 5280 line 3678
     */
    ASN1ObjectIdentifier id_ce_issuingDistributionPoint = id_ce.branch("28").intern();

    /**
     * 2.5.29.29 -- id-ce-certificateIssuer, RFC 5280 line 3931
     */
    ASN1ObjectIdentifier id_ce_certificateIssuer = id_ce.branch("29").intern();

    /**
     * 2.5.29.30 -- id-ce-nameConstraints, RFC 5280 line 2343
     */
    ASN1ObjectIdentifier id_ce_nameConstraints = id_ce.branch("30").intern();

    /**
     * 2.5.29.31 -- id-ce-cRLDistributionPoints, RFC 5280 line 2609
     */
    ASN1ObjectIdentifier id_ce_cRLDistributionPoints = id_ce.branch("31").intern();

    /**
     * 2.5.29.32 -- id-ce-certificatePolicies, RFC 5280 line 1855
     */
    ASN1ObjectIdentifier id_ce_certificatePolicies = id_ce.branch("32").intern();

    /**
     * 2.5.29.33 -- id-ce-policyMappings, RFC 5280 line 1947
     */
    ASN1ObjectIdentifier id_ce_policyMappings = id_ce.branch("33").intern();

    /**
     * 2.5.29.35 -- id-ce-authorityKeyIdentifier, RFC 5280 line 1532
     */
    ASN1ObjectIdentifier id_ce_authorityKeyIdentifier = id_ce.branch("35").intern();

    /**
     * 2.5.29.36 -- id-ce-policyConstraints, RFC 5280 line 2415
     */
    ASN1ObjectIdentifier id_ce_policyConstraints = id_ce.branch("36").intern();

    /**
     * 2.5.29.37 -- id-ce-extKeyUsage, RFC 5280 line 2431
     */
    ASN1ObjectIdentifier id_ce_extKeyUsage = id_ce.branch("37").intern();

    /**
     * 2.5.29.46 -- id-ce-freshestCRL, RFC 5280 line 2681
     */
    ASN1ObjectIdentifier id_ce_freshestCRL = id_ce.branch("46").intern();

    /**
     * 2.5.29.54 -- id-ce-inhibitAnyPolicy, RFC 5280 line 2665
     */
    ASN1ObjectIdentifier id_ce_inhibitAnyPolicy = id_ce.branch("54").intern();
}
