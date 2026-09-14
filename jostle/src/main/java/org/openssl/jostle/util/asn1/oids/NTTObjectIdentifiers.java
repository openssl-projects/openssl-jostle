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
 * From <a href="https://tools.ietf.org/html/rfc3657">RFC 3657</a>
 * Use of the Camellia Encryption Algorithm
 * in Cryptographic Message Syntax (CMS)
 */
public interface NTTObjectIdentifiers
{
    /**
     * 1.2.392.200011.61.1.1.1.2 -- id-camellia128-cbc, RFC 3657 line 127
     */
    static final ASN1ObjectIdentifier id_camellia128_cbc = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.1.2");
    /**
     * 1.2.392.200011.61.1.1.1.3 -- id-camellia192-cbc, RFC 3657 line 132
     */
    static final ASN1ObjectIdentifier id_camellia192_cbc = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.1.3");
    /**
     * 1.2.392.200011.61.1.1.1.4 -- id-camellia256-cbc, RFC 3657 line 137
     */
    static final ASN1ObjectIdentifier id_camellia256_cbc = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.1.4");

    /**
     * 1.2.392.200011.61.1.1.3.2 -- id-camellia128-wrap, RFC 3657 line 161
     */
    static final ASN1ObjectIdentifier id_camellia128_wrap = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.3.2");
    /**
     * 1.2.392.200011.61.1.1.3.3 -- id-camellia192-wrap, RFC 3657 line 175
     */
    static final ASN1ObjectIdentifier id_camellia192_wrap = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.3.3");
    /**
     * 1.2.392.200011.61.1.1.3.4 -- id-camellia256-wrap, RFC 3657 line 180
     */
    static final ASN1ObjectIdentifier id_camellia256_wrap = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.3.4");
}

