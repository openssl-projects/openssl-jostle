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
 * OIW secsig arc:
 * iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2)
 *
 * RFC 8017 and RFC 8018.
 * Field names follow BouncyCastle so the cross-reference is mechanical.
 */
public interface OIWObjectIdentifiers
{
    /**
     * 1.3.14.3.2.7 -- desCBC, RFC 8018 line 1642
     */
    ASN1ObjectIdentifier desCBC = new ASN1ObjectIdentifier("1.3.14.3.2.7").intern();

    /**
     * 1.3.14.3.2.26 -- id-sha1, RFC 8017 line 3560
     */
    ASN1ObjectIdentifier idSHA1 = new ASN1ObjectIdentifier("1.3.14.3.2.26").intern();
}
