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
 * CryptoPro GOST arc:
 * iso(1) member-body(2) ru(643) rans(2) cryptopro(2)
 *
 * RFC 4357, RFC 4490.
 * Field names follow BouncyCastle so the cross-reference is mechanical.
 */
public interface CryptoProObjectIdentifiers
{
    /**
     * 1.2.643.2.2 -- id-CryptoPro-algorithms, RFC 4357 line 814
     */
    ASN1ObjectIdentifier GOST_id = new ASN1ObjectIdentifier("1.2.643.2.2").intern();

    /**
     * 1.2.643.2.2.21 -- id-Gost28147-89, RFC 4357 line 965
     */
    ASN1ObjectIdentifier gostR28147_gcfb = GOST_id.branch("21").intern();

    /**
     * 1.2.643.2.2.13.0 -- id-Gost28147-89-None-KeyWrap, RFC 4490 line 365
     */
    ASN1ObjectIdentifier id_Gost28147_89_None_KeyWrap = GOST_id.branch("13.0").intern();

    /**
     * 1.2.643.2.2.13.1 -- id-Gost28147-89-CryptoPro-KeyWrap, RFC 4490 line 353
     */
    ASN1ObjectIdentifier id_Gost28147_89_CryptoPro_KeyWrap = GOST_id.branch("13.1").intern();
}
