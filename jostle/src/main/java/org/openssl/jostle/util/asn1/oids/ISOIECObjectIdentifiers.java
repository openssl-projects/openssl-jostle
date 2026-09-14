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
 * ISO/IEC 18033-2 arc:
 * iso(1) standard(0) is18033(18033) part2(2)
 *
 * RFC 9690.
 * Field names follow BouncyCastle so the cross-reference is mechanical.
 */
public interface ISOIECObjectIdentifiers
{
    /**
     * 1.0.18033.2 -- is18033-2, RFC 9690 line 964
     */
    ASN1ObjectIdentifier is18033_2 = new ASN1ObjectIdentifier("1.0.18033.2").intern();

    /**
     * 1.0.18033.2.2 -- key-encapsulation-mechanism arc label, RFC 9690 line 1015, within the id-kem-rsa definition
     */
    ASN1ObjectIdentifier id_kem = is18033_2.branch("2").intern();

    /**
     * 1.0.18033.2.2.4 -- id-kem-rsa, RFC 9690 line 1015
     */
    ASN1ObjectIdentifier id_kem_rsa = id_kem.branch("4").intern();
}
