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
 * Chinese GM/T SM scheme arc:
 * iso(1) member-body(2) cn(156) ns(10197) algorithms(1)
 *
 * GM/T 0006-2012, for which the standards library holds no text. The SM4
 * mode values agree with OpenSSL objects.txt; the two wrap values do not
 * appear there in either supported module and rest on BouncyCastle alone.
 * Field names follow BouncyCastle so the cross-reference is mechanical.
 */
public interface GMObjectIdentifiers
{
    /**
     * 1.2.156.10197.1 -- sm-scheme, GM/T 0006-2012, no text in the standards library
     */
    ASN1ObjectIdentifier sm_scheme = new ASN1ObjectIdentifier("1.2.156.10197.1").intern();

    /**
     * 1.2.156.10197.1.104.2 -- SM4-CBC, OpenSSL objects.txt sm-scheme 104 2, both modules
     */
    ASN1ObjectIdentifier sms4_cbc = sm_scheme.branch("104.2").intern();

    /**
     * 1.2.156.10197.1.104.8 -- SM4-GCM, OpenSSL objects.txt sm-scheme 104 8, 3.5.8 only
     */
    ASN1ObjectIdentifier sms4_gcm = sm_scheme.branch("104.8").intern();

    /**
     * 1.2.156.10197.1.104.9 -- SM4-CCM, OpenSSL objects.txt sm-scheme 104 9, 3.5.8 only
     */
    ASN1ObjectIdentifier sms4_ccm = sm_scheme.branch("104.9").intern();

    /**
     * 1.2.156.10197.1.104.11 -- SM4 key wrap, BouncyCastle only; absent from OpenSSL 3.1.2 and 3.5.8
     */
    ASN1ObjectIdentifier sms4_wrap = sm_scheme.branch("104.11").intern();

    /**
     * 1.2.156.10197.1.104.12 -- SM4 key wrap with padding, BouncyCastle only; absent from OpenSSL 3.1.2 and 3.5.8
     */
    ASN1ObjectIdentifier sms4_wrap_pad = sm_scheme.branch("104.12").intern();
}
