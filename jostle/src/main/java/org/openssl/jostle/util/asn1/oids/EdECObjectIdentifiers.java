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

public interface EdECObjectIdentifiers
{
    /**
     * 1.3.101 -- id-edwards-curve-algs, RFC 8410 line 491
     */
    ASN1ObjectIdentifier id_edwards_curve_algs = new ASN1ObjectIdentifier("1.3.101");

    /**
     * 1.3.101.110 -- id-X25519, RFC 8410 line 208
     */
    ASN1ObjectIdentifier id_X25519 = id_edwards_curve_algs.branch("110");
    /**
     * 1.3.101.111 -- id-X448, RFC 8410 line 209
     */
    ASN1ObjectIdentifier id_X448 = id_edwards_curve_algs.branch("111");
    /**
     * 1.3.101.112 -- id-Ed25519, RFC 8410 line 210
     */
    ASN1ObjectIdentifier id_Ed25519 = id_edwards_curve_algs.branch("112");
    /**
     * 1.3.101.113 -- id-Ed448, RFC 8410 line 211
     */
    ASN1ObjectIdentifier id_Ed448 = id_edwards_curve_algs.branch("113");
}
