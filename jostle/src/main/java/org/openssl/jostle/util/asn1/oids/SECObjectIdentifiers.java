/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.asn1.oids;

import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;

/**
 *
 * Certicom SEC arc:
 * iso(1) identified-organization(3) certicom(132)
 *
 * RFC 5480, RFC 5753.
 * Field names follow BouncyCastle so the cross-reference is mechanical.
 */
public interface SECObjectIdentifiers
{
    /**
     * 1.3.132 -- certicom arc label, RFC 5753 line 1272, within the secg-scheme definition
     */
    ASN1ObjectIdentifier certicom = new ASN1ObjectIdentifier("1.3.132").intern();

    /**
     * 1.3.132.1 -- secg-scheme, RFC 5753 line 1271
     */
    ASN1ObjectIdentifier secg_scheme = certicom.branch("1").intern();

    /**
     * 1.3.132.1.12 -- id-ecDH, RFC 5480 line 330
     */
    ASN1ObjectIdentifier ecdh = secg_scheme.branch("12").intern();

    /**
     * 1.3.132.1.11.0 -- dhSinglePass-stdDH-sha224kdf-scheme, RFC 5753 line 1213
     */
    ASN1ObjectIdentifier dhSinglePass_stdDH_sha224kdf_scheme = secg_scheme.branch("11.0").intern();

    /**
     * 1.3.132.1.11.1 -- dhSinglePass-stdDH-sha256kdf-scheme, RFC 5753 line 1216
     */
    ASN1ObjectIdentifier dhSinglePass_stdDH_sha256kdf_scheme = secg_scheme.branch("11.1").intern();

    /**
     * 1.3.132.1.11.2 -- dhSinglePass-stdDH-sha384kdf-scheme, RFC 5753 line 1219
     */
    ASN1ObjectIdentifier dhSinglePass_stdDH_sha384kdf_scheme = secg_scheme.branch("11.2").intern();

    /**
     * 1.3.132.1.11.3 -- dhSinglePass-stdDH-sha512kdf-scheme, RFC 5753 line 1222
     */
    ASN1ObjectIdentifier dhSinglePass_stdDH_sha512kdf_scheme = secg_scheme.branch("11.3").intern();
}
