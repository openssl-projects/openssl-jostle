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


public interface NSRIObjectIdentifiers
{
    /**
     * 1.2.410.200046 -- nsri, RFC 5794 line 653, within the id-algorithm definition
     */
    ASN1ObjectIdentifier nsri = new ASN1ObjectIdentifier("1.2.410.200046");

    /**
     * 1.2.410.200046.1 -- id-algorithm, RFC 5794 line 653
     */
    ASN1ObjectIdentifier id_algorithm = nsri.branch("1");

    /**
     * 1.2.410.200046.1.1 -- id-sea, RFC 5794 line 656
     */
    ASN1ObjectIdentifier id_sea = id_algorithm.branch("1");
    /**
     * 1.2.410.200046.1.2 -- id-pad, RFC 5794 line 657
     */
    ASN1ObjectIdentifier id_pad = id_algorithm.branch("2");

    /**
     * 1.2.410.200046.1.0 -- id-pad-null, value as BouncyCastle registers it; RFC 5794 line 657 defines id-pad
     */
    ASN1ObjectIdentifier id_pad_null = id_algorithm.branch("0");
    /**
     * 1.2.410.200046.1.1 -- id-pad-1, value as BouncyCastle registers it; RFC 5794 line 657 places id-pad-1 under id-pad
     */
    ASN1ObjectIdentifier id_pad_1 = id_algorithm.branch("1");

    /**
     * 1.2.410.200046.1.1.1 -- id-aria128-ecb, RFC 5794 line 666
     */
    ASN1ObjectIdentifier id_aria128_ecb = id_sea.branch("1");
    /**
     * 1.2.410.200046.1.1.2 -- id-aria128-cbc, RFC 5794 line 667
     */
    ASN1ObjectIdentifier id_aria128_cbc = id_sea.branch("2");
    /**
     * 1.2.410.200046.1.1.3 -- id-aria128-cfb, RFC 5794 line 668
     */
    ASN1ObjectIdentifier id_aria128_cfb = id_sea.branch("3");
    /**
     * 1.2.410.200046.1.1.4 -- id-aria128-ofb, RFC 5794 line 669
     */
    ASN1ObjectIdentifier id_aria128_ofb = id_sea.branch("4");
    /**
     * 1.2.410.200046.1.1.5 -- id-aria128-ctr, RFC 5794 line 670
     */
    ASN1ObjectIdentifier id_aria128_ctr = id_sea.branch("5");

    /**
     * 1.2.410.200046.1.1.6 -- id-aria192-ecb, RFC 5794 line 679
     */
    ASN1ObjectIdentifier id_aria192_ecb = id_sea.branch("6");
    /**
     * 1.2.410.200046.1.1.7 -- id-aria192-cbc, RFC 5794 line 680
     */
    ASN1ObjectIdentifier id_aria192_cbc = id_sea.branch("7");
    /**
     * 1.2.410.200046.1.1.8 -- id-aria192-cfb, RFC 5794 line 681
     */
    ASN1ObjectIdentifier id_aria192_cfb = id_sea.branch("8");
    /**
     * 1.2.410.200046.1.1.9 -- id-aria192-ofb, RFC 5794 line 682
     */
    ASN1ObjectIdentifier id_aria192_ofb = id_sea.branch("9");
    /**
     * 1.2.410.200046.1.1.10 -- id-aria192-ctr, RFC 5794 line 683
     */
    ASN1ObjectIdentifier id_aria192_ctr = id_sea.branch("10");

    /**
     * 1.2.410.200046.1.1.11 -- id-aria256-ecb, RFC 5794 line 685
     */
    ASN1ObjectIdentifier id_aria256_ecb = id_sea.branch("11");
    /**
     * 1.2.410.200046.1.1.12 -- id-aria256-cbc, RFC 5794 line 686
     */
    ASN1ObjectIdentifier id_aria256_cbc = id_sea.branch("12");
    /**
     * 1.2.410.200046.1.1.13 -- id-aria256-cfb, RFC 5794 line 687
     */
    ASN1ObjectIdentifier id_aria256_cfb = id_sea.branch("13");
    /**
     * 1.2.410.200046.1.1.14 -- id-aria256-ofb, RFC 5794 line 688
     */
    ASN1ObjectIdentifier id_aria256_ofb = id_sea.branch("14");
    /**
     * 1.2.410.200046.1.1.15 -- id-aria256-ctr, RFC 5794 line 689
     */
    ASN1ObjectIdentifier id_aria256_ctr = id_sea.branch("15");

    /**
     * 1.2.410.200046.1.1.21 -- id-aria128-cmac, RFC 5794 line 693
     */
    ASN1ObjectIdentifier id_aria128_cmac = id_sea.branch("21");
    /**
     * 1.2.410.200046.1.1.22 -- id-aria192-cmac, RFC 5794 line 694
     */
    ASN1ObjectIdentifier id_aria192_cmac = id_sea.branch("22");
    /**
     * 1.2.410.200046.1.1.23 -- id-aria256-cmac, RFC 5794 line 695
     */
    ASN1ObjectIdentifier id_aria256_cmac = id_sea.branch("23");

    /**
     * 1.2.410.200046.1.1.31 -- id-aria128-ocb2, RFC 5794 line 700
     */
    ASN1ObjectIdentifier id_aria128_ocb2 = id_sea.branch("31");
    /**
     * 1.2.410.200046.1.1.32 -- id-aria192-ocb2, RFC 5794 line 701
     */
    ASN1ObjectIdentifier id_aria192_ocb2 = id_sea.branch("32");
    /**
     * 1.2.410.200046.1.1.33 -- id-aria256-ocb2, RFC 5794 line 702
     */
    ASN1ObjectIdentifier id_aria256_ocb2 = id_sea.branch("33");

    /**
     * 1.2.410.200046.1.1.34 -- id-aria128-gcm, RFC 5794 line 704
     */
    ASN1ObjectIdentifier id_aria128_gcm = id_sea.branch("34");
    /**
     * 1.2.410.200046.1.1.35 -- id-aria192-gcm, RFC 5794 line 705
     */
    ASN1ObjectIdentifier id_aria192_gcm = id_sea.branch("35");
    /**
     * 1.2.410.200046.1.1.36 -- id-aria256-gcm, RFC 5794 line 706
     */
    ASN1ObjectIdentifier id_aria256_gcm = id_sea.branch("36");

    /**
     * 1.2.410.200046.1.1.37 -- id-aria128-ccm, RFC 5794 line 708
     */
    ASN1ObjectIdentifier id_aria128_ccm = id_sea.branch("37");
    /**
     * 1.2.410.200046.1.1.38 -- id-aria192-ccm, RFC 5794 line 709
     */
    ASN1ObjectIdentifier id_aria192_ccm = id_sea.branch("38");
    /**
     * 1.2.410.200046.1.1.39 -- id-aria256-ccm, RFC 5794 line 710
     */
    ASN1ObjectIdentifier id_aria256_ccm = id_sea.branch("39");

    /**
     * 1.2.410.200046.1.1.40 -- id-aria128-kw, RFC 5794 line 712
     */
    ASN1ObjectIdentifier id_aria128_kw = id_sea.branch("40");
    /**
     * 1.2.410.200046.1.1.41 -- id-aria192-kw, RFC 5794 line 713
     */
    ASN1ObjectIdentifier id_aria192_kw = id_sea.branch("41");
    /**
     * 1.2.410.200046.1.1.42 -- id-aria256-kw, RFC 5794 line 714
     */
    ASN1ObjectIdentifier id_aria256_kw = id_sea.branch("42");

    /**
     * 1.2.410.200046.1.1.43 -- id-aria128-kwp, RFC 5794 line 718
     */
    ASN1ObjectIdentifier id_aria128_kwp = id_sea.branch("43");
    /**
     * 1.2.410.200046.1.1.44 -- id-aria192-kwp, RFC 5794 line 719
     */
    ASN1ObjectIdentifier id_aria192_kwp = id_sea.branch("44");
    /**
     * 1.2.410.200046.1.1.45 -- id-aria256-kwp, RFC 5794 line 720
     */
    ASN1ObjectIdentifier id_aria256_kwp = id_sea.branch("45");
}

