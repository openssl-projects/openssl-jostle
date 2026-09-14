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
 * GNU / miscellaneous private-enterprise arc:
 * iso(1) identified-organization(3) dod(6) internet(1) private(4)
 * enterprise(1) gnu(11591)
 *
 * RFC 7914.
 * Field names follow BouncyCastle so the cross-reference is mechanical.
 */
public interface MiscObjectIdentifiers
{
    /**
     * 1.3.6.1.4.1.11591.4.11 -- id-scrypt, RFC 7914 line 411
     */
    ASN1ObjectIdentifier id_scrypt = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.4.11").intern();
}
