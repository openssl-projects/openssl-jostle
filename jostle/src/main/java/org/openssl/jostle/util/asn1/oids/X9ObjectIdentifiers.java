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
 * ANSI X9 arcs:
 * iso(1) member-body(2) us(840) ansi-x942(10046) / ansi-x962(10045) / x9-57(10040)
 * iso(1) identified-organization(3) tc68(133) country(16) x9(840)
 *
 * RFC 3279, RFC 5480, RFC 5758, RFC 5753, RFC 9690.
 * Field names follow BouncyCastle so the cross-reference is mechanical.
 */
public interface X9ObjectIdentifiers
{
    /**
     * 1.2.840.10040.4.1 -- id-dsa, RFC 3279 line 470
     */
    ASN1ObjectIdentifier id_dsa = new ASN1ObjectIdentifier("1.2.840.10040.4.1").intern();

    /**
     * 1.2.840.10040.4.3 -- id-dsa-with-sha1, RFC 3279 line 309
     */
    ASN1ObjectIdentifier id_dsa_with_sha1 = new ASN1ObjectIdentifier("1.2.840.10040.4.3").intern();

    /**
     * 1.2.840.10045 -- ansi-X9-62, RFC 3279 line 349
     */
    ASN1ObjectIdentifier ansi_X9_62 = new ASN1ObjectIdentifier("1.2.840.10045").intern();

    /**
     * 1.2.840.10045.2 -- id-publicKeyType, RFC 3279 line 1244
     */
    ASN1ObjectIdentifier id_publicKeyType = ansi_X9_62.branch("2").intern();

    /**
     * 1.2.840.10045.2.1 -- id-ecPublicKey, RFC 3279 line 708
     */
    ASN1ObjectIdentifier id_ecPublicKey = id_publicKeyType.branch("1").intern();

    /**
     * 1.2.840.10045.3.1 -- primeCurve, RFC 3279 line 1276
     */
    ASN1ObjectIdentifier primeCurve = ansi_X9_62.branch("3.1").intern();

    /**
     * 1.2.840.10045.3.1.7 -- secp256r1, RFC 5480 line 290
     */
    ASN1ObjectIdentifier prime256v1 = primeCurve.branch("7").intern();

    /**
     * 1.2.840.10045.4 -- id-ecSigType, RFC 3279 line 352
     */
    ASN1ObjectIdentifier id_ecSigType = ansi_X9_62.branch("4").intern();

    /**
     * 1.2.840.10045.4.1 -- ecdsa-with-SHA1, RFC 3279 line 358
     */
    ASN1ObjectIdentifier ecdsa_with_SHA1 = id_ecSigType.branch("1").intern();

    /**
     * 1.2.840.10045.4.3 -- ecdsa-with-SHA2 arc label, RFC 5758 line 232, within the ecdsa-with-SHA224 definition
     */
    ASN1ObjectIdentifier ecdsa_with_SHA2 = id_ecSigType.branch("3").intern();

    /**
     * 1.2.840.10045.4.3.1 -- ecdsa-with-SHA224, RFC 5758 line 231
     */
    ASN1ObjectIdentifier ecdsa_with_SHA224 = ecdsa_with_SHA2.branch("1").intern();

    /**
     * 1.2.840.10045.4.3.2 -- ecdsa-with-SHA256, RFC 5758 line 234
     */
    ASN1ObjectIdentifier ecdsa_with_SHA256 = ecdsa_with_SHA2.branch("2").intern();

    /**
     * 1.2.840.10045.4.3.3 -- ecdsa-with-SHA384, RFC 5758 line 237
     */
    ASN1ObjectIdentifier ecdsa_with_SHA384 = ecdsa_with_SHA2.branch("3").intern();

    /**
     * 1.2.840.10045.4.3.4 -- ecdsa-with-SHA512, RFC 5758 line 240
     */
    ASN1ObjectIdentifier ecdsa_with_SHA512 = ecdsa_with_SHA2.branch("4").intern();

    /**
     * 1.2.840.10046 -- ansi-x942 arc label, RFC 3279 line 540, within the dhpublicnumber definition
     */
    ASN1ObjectIdentifier ansi_X9_42 = new ASN1ObjectIdentifier("1.2.840.10046").intern();

    /**
     * 1.2.840.10046.2.1 -- dhpublicnumber, RFC 3279 line 539
     */
    ASN1ObjectIdentifier dhpublicnumber = ansi_X9_42.branch("2.1").intern();

    /**
     * 1.3.133.16.840.63.0 -- x9-63-scheme, RFC 5753 line 1265
     */
    ASN1ObjectIdentifier x9_63_scheme = new ASN1ObjectIdentifier("1.3.133.16.840.63.0").intern();

    /**
     * 1.3.133.16.840.63.0.2 -- dhSinglePass-stdDH-sha1kdf-scheme, RFC 5753 line 1210
     */
    ASN1ObjectIdentifier dhSinglePass_stdDH_sha1kdf_scheme = x9_63_scheme.branch("2").intern();

    /**
     * 1.3.133.16.840.9.44 -- x9-44, RFC 9690 line 978
     */
    ASN1ObjectIdentifier x9_44 = new ASN1ObjectIdentifier("1.3.133.16.840.9.44").intern();

    /**
     * 1.3.133.16.840.9.44.1 -- x9-44-components, RFC 9690 line 981
     */
    ASN1ObjectIdentifier x9_44_components = x9_44.branch("1").intern();

    /**
     * 1.3.133.16.840.9.44.1.1 -- id-kdf-kdf2, RFC 9690 line 1074
     */
    ASN1ObjectIdentifier id_kdf_kdf2 = x9_44_components.branch("1").intern();

    /**
     * 1.3.133.16.840.9.44.1.2 -- id-kdf-kdf3, RFC 9690 line 853
     */
    ASN1ObjectIdentifier id_kdf_kdf3 = x9_44_components.branch("2").intern();
}
