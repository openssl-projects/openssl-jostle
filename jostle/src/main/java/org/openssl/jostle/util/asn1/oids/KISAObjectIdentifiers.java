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
 * Korean KISA arc:
 * iso(1) member-body(2) korea(410) kisa(200004)
 *
 * RFC 4010.
 * Field names follow BouncyCastle so the cross-reference is mechanical.
 */
public interface KISAObjectIdentifiers
{
    /**
     * 1.2.410.200004.1.4 -- id-seedCBC, RFC 4010 line 125
     */
    ASN1ObjectIdentifier id_seedCBC = new ASN1ObjectIdentifier("1.2.410.200004.1.4").intern();

    /**
     * 1.2.410.200004.7.1.1.1 -- id-npki-app-cmsSeed-wrap, RFC 4010 line 149
     */
    ASN1ObjectIdentifier id_npki_app_cmsSeed_wrap = new ASN1ObjectIdentifier("1.2.410.200004.7.1.1.1").intern();
}
