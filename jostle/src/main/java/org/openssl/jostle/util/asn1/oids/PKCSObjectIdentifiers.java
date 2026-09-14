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
 * RSA Security PKCS arcs:
 * iso(1) member-body(2) us(840) rsadsi(113549)
 *
 * RFC 8017 (PKCS #1), RFC 8018 (PKCS #5), RFC 3370 and RFC 3217 (CMS),
 * RFC 8103, RFC 8418, RFC 8619, RFC 9690, RFC 4231, RFC 3279.
 * Field names follow BouncyCastle so the cross-reference is mechanical.
 */
public interface PKCSObjectIdentifiers
{
    /**
     * 1.2.840.113549.1.1 -- pkcs-1, RFC 8017 line 3801
     */
    ASN1ObjectIdentifier pkcs_1 = new ASN1ObjectIdentifier("1.2.840.113549.1.1").intern();

    /**
     * 1.2.840.113549.1.1.1 -- rsaEncryption, RFC 8017 line 2989
     */
    ASN1ObjectIdentifier rsaEncryption = pkcs_1.branch("1").intern();

    /**
     * 1.2.840.113549.1.1.4 -- md5WithRSAEncryption, RFC 3279 line 275
     */
    ASN1ObjectIdentifier md5WithRSAEncryption = pkcs_1.branch("4").intern();

    /**
     * 1.2.840.113549.1.1.5 -- sha1WithRSAEncryption, RFC 8017 line 3843
     */
    ASN1ObjectIdentifier sha1WithRSAEncryption = pkcs_1.branch("5").intern();

    /**
     * 1.2.840.113549.1.1.10 -- id-RSASSA-PSS, RFC 8017 line 3325
     */
    ASN1ObjectIdentifier id_RSASSA_PSS = pkcs_1.branch("10").intern();

    /**
     * 1.2.840.113549.1.1.11 -- sha256WithRSAEncryption, RFC 8017 line 3845
     */
    ASN1ObjectIdentifier sha256WithRSAEncryption = pkcs_1.branch("11").intern();

    /**
     * 1.2.840.113549.1.1.12 -- sha384WithRSAEncryption, RFC 8017 line 3846
     */
    ASN1ObjectIdentifier sha384WithRSAEncryption = pkcs_1.branch("12").intern();

    /**
     * 1.2.840.113549.1.1.13 -- sha512WithRSAEncryption, RFC 8017 line 3847
     */
    ASN1ObjectIdentifier sha512WithRSAEncryption = pkcs_1.branch("13").intern();

    /**
     * 1.2.840.113549.1.1.14 -- sha224WithRSAEncryption, RFC 8017 line 3844
     */
    ASN1ObjectIdentifier sha224WithRSAEncryption = pkcs_1.branch("14").intern();

    /**
     * 1.2.840.113549.1.1.15 -- sha512-224WithRSAEncryption, RFC 8017 line 3848
     */
    ASN1ObjectIdentifier sha512_224WithRSAEncryption = pkcs_1.branch("15").intern();

    /**
     * 1.2.840.113549.1.1.16 -- sha512-256WithRSAEncryption, RFC 8017 line 3849
     */
    ASN1ObjectIdentifier sha512_256WithRSAEncryption = pkcs_1.branch("16").intern();

    /**
     * 1.2.840.113549.1.3 -- pkcs-3, PKCS #3 v1.4
     */
    ASN1ObjectIdentifier pkcs_3 = new ASN1ObjectIdentifier("1.2.840.113549.1.3").intern();

    /**
     * 1.2.840.113549.1.3.1 -- dhKeyAgreement, PKCS #3 v1.4 §9, which the standards library does not hold; OpenSSL objects.txt and BouncyCastle agree on the value
     */
    ASN1ObjectIdentifier dhKeyAgreement = pkcs_3.branch("1").intern();

    /**
     * 1.2.840.113549.1.5 -- pkcs-5, RFC 8018 line 1254
     */
    ASN1ObjectIdentifier pkcs_5 = new ASN1ObjectIdentifier("1.2.840.113549.1.5").intern();

    /**
     * 1.2.840.113549.1.5.12 -- id-PBKDF2, RFC 8018 line 1267
     */
    ASN1ObjectIdentifier id_PBKDF2 = pkcs_5.branch("12").intern();

    /**
     * 1.2.840.113549.1.9 -- pkcs-9, RFC 2985 line 1262
     */
    ASN1ObjectIdentifier pkcs_9 = new ASN1ObjectIdentifier("1.2.840.113549.1.9").intern();

    /**
     * 1.2.840.113549.1.9.16 -- smime, RFC 2985 line 1352
     */
    ASN1ObjectIdentifier id_smime = pkcs_9.branch("16").intern();

    /**
     * 1.2.840.113549.1.9.16.3 -- smime-alg, RFC 8418 line 488
     */
    ASN1ObjectIdentifier id_alg = id_smime.branch("3").intern();

    /**
     * 1.2.840.113549.1.9.16.3.5 -- id-alg-ESDH, RFC 3370 line 409
     */
    ASN1ObjectIdentifier id_alg_ESDH = id_alg.branch("5").intern();

    /**
     * 1.2.840.113549.1.9.16.3.6 -- id-alg-CMS3DESwrap, RFC 3370 line 595
     */
    ASN1ObjectIdentifier id_alg_CMS3DESwrap = id_alg.branch("6").intern();

    /**
     * 1.2.840.113549.1.9.16.3.10 -- id-alg-SSDH, RFC 3370 line 469
     */
    ASN1ObjectIdentifier id_alg_SSDH = id_alg.branch("10").intern();

    /**
     * 1.2.840.113549.1.9.16.3.14 -- id-rsa-kem, RFC 9690 line 985
     */
    ASN1ObjectIdentifier id_rsa_KEM = id_alg.branch("14").intern();

    /**
     * 1.2.840.113549.1.9.16.3.18 -- id-alg-AEADChaCha20Poly1305, RFC 8103 line 250
     */
    ASN1ObjectIdentifier id_alg_AEADChaCha20Poly1305 = id_alg.branch("18").intern();

    /**
     * 1.2.840.113549.1.9.16.3.19 -- dhSinglePass-stdDH-hkdf-sha256-scheme, RFC 8418 line 492
     */
    ASN1ObjectIdentifier dhSinglePass_stdDH_hkdf_sha256_scheme = id_alg.branch("19").intern();

    /**
     * 1.2.840.113549.1.9.16.3.20 -- dhSinglePass-stdDH-hkdf-sha384-scheme, RFC 8418 line 495
     */
    ASN1ObjectIdentifier dhSinglePass_stdDH_hkdf_sha384_scheme = id_alg.branch("20").intern();

    /**
     * 1.2.840.113549.1.9.16.3.21 -- dhSinglePass-stdDH-hkdf-sha512-scheme, RFC 8418 line 498
     */
    ASN1ObjectIdentifier dhSinglePass_stdDH_hkdf_sha512_scheme = id_alg.branch("21").intern();

    /**
     * 1.2.840.113549.1.9.16.3.28 -- id-alg-hkdf-with-sha256, RFC 8619 line 121
     */
    ASN1ObjectIdentifier id_alg_hkdf_with_sha256 = id_alg.branch("28").intern();

    /**
     * 1.2.840.113549.1.9.16.3.29 -- id-alg-hkdf-with-sha384, RFC 8619 line 124
     */
    ASN1ObjectIdentifier id_alg_hkdf_with_sha384 = id_alg.branch("29").intern();

    /**
     * 1.2.840.113549.1.9.16.3.30 -- id-alg-hkdf-with-sha512, RFC 8619 line 127
     */
    ASN1ObjectIdentifier id_alg_hkdf_with_sha512 = id_alg.branch("30").intern();

    /**
     * 1.2.840.113549.2 -- digestAlgorithm, RFC 8018 line 2037
     */
    ASN1ObjectIdentifier digestAlgorithm = new ASN1ObjectIdentifier("1.2.840.113549.2").intern();

    /**
     * 1.2.840.113549.2.7 -- id-hmacWithSHA1, RFC 8018 line 1556
     */
    ASN1ObjectIdentifier id_hmacWithSHA1 = digestAlgorithm.branch("7").intern();

    /**
     * 1.2.840.113549.2.8 -- id-hmacWithSHA224, RFC 4231 line 131
     */
    ASN1ObjectIdentifier id_hmacWithSHA224 = digestAlgorithm.branch("8").intern();

    /**
     * 1.2.840.113549.2.9 -- id-hmacWithSHA256, RFC 4231 line 132
     */
    ASN1ObjectIdentifier id_hmacWithSHA256 = digestAlgorithm.branch("9").intern();

    /**
     * 1.2.840.113549.2.10 -- id-hmacWithSHA384, RFC 4231 line 133
     */
    ASN1ObjectIdentifier id_hmacWithSHA384 = digestAlgorithm.branch("10").intern();

    /**
     * 1.2.840.113549.2.11 -- id-hmacWithSHA512, RFC 4231 line 134
     */
    ASN1ObjectIdentifier id_hmacWithSHA512 = digestAlgorithm.branch("11").intern();

    /**
     * 1.2.840.113549.2.12 -- id-hmacWithSHA512-224, RFC 8018 line 1609
     */
    ASN1ObjectIdentifier id_hmacWithSHA512_224 = digestAlgorithm.branch("12").intern();

    /**
     * 1.2.840.113549.2.13 -- id-hmacWithSHA512-256, RFC 8018 line 1610
     */
    ASN1ObjectIdentifier id_hmacWithSHA512_256 = digestAlgorithm.branch("13").intern();

    /**
     * 1.2.840.113549.3 -- encryptionAlgorithm, RFC 8018 line 2038
     */
    ASN1ObjectIdentifier encryptionAlgorithm = new ASN1ObjectIdentifier("1.2.840.113549.3").intern();

    /**
     * 1.2.840.113549.3.7 -- des-EDE3-CBC, RFC 8018 line 1662
     */
    ASN1ObjectIdentifier des_EDE3_CBC = encryptionAlgorithm.branch("7").intern();
}
