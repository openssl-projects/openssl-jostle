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

package org.openssl.jostle.jcajce.provider;

public interface EdECObjectIdentifiers
{
    ASN1ObjectIdentifier id_edwards_curve_algs = new ASN1ObjectIdentifier("1.3.101");

    ASN1ObjectIdentifier id_X25519 = id_edwards_curve_algs.branch("110");
    ASN1ObjectIdentifier id_X448 = id_edwards_curve_algs.branch("111");
    ASN1ObjectIdentifier id_Ed25519 = id_edwards_curve_algs.branch("112");
    ASN1ObjectIdentifier id_Ed448 = id_edwards_curve_algs.branch("113");
}
