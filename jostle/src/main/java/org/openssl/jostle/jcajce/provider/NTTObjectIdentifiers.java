/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider;

/**
 * From <a href="https://tools.ietf.org/html/rfc3657">RFC 3657</a>
 * Use of the Camellia Encryption Algorithm
 * in Cryptographic Message Syntax (CMS)
 */
public interface NTTObjectIdentifiers
{
    /** id-camellia128-cbc; OID 1.2.392.200011.61.1.1.1.2 */
    static final ASN1ObjectIdentifier id_camellia128_cbc = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.1.2");
    /** id-camellia192-cbc; OID 1.2.392.200011.61.1.1.1.3 */
    static final ASN1ObjectIdentifier id_camellia192_cbc = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.1.3");
    /** id-camellia256-cbc; OID 1.2.392.200011.61.1.1.1.4 */
    static final ASN1ObjectIdentifier id_camellia256_cbc = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.1.4");

    /** id-camellia128-wrap; OID 1.2.392.200011.61.1.1.3.2 */
    static final ASN1ObjectIdentifier id_camellia128_wrap = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.3.2");
    /** id-camellia192-wrap; OID 1.2.392.200011.61.1.1.3.3 */
    static final ASN1ObjectIdentifier id_camellia192_wrap = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.3.3");
    /** id-camellia256-wrap; OID 1.2.392.200011.61.1.1.3.4 */
    static final ASN1ObjectIdentifier id_camellia256_wrap = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.3.4");
}

