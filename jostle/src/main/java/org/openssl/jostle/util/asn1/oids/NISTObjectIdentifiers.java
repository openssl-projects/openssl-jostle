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
 * NIST:
 * iso/itu(2) joint-assign(16) us(840) organization(1) gov(101) csor(3)
 */
public interface NISTObjectIdentifiers
{
    //
    // nistalgorithms(4)
    //
    /**
     * 2.16.840.1.101.3.4 -- nistAlgorithms, NIST CSOR line 1
     */
    ASN1ObjectIdentifier nistAlgorithm = new ASN1ObjectIdentifier("2.16.840.1.101.3.4").intern();

    /**
     * 2.16.840.1.101.3.4.2 -- hashAlgs, NIST CSOR line 35
     */
    ASN1ObjectIdentifier hashAlgs = nistAlgorithm.branch("2").intern();

    /**
     * 2.16.840.1.101.3.4.2.1 -- id-sha256, NIST CSOR line 38
     */
    ASN1ObjectIdentifier id_sha256 = hashAlgs.branch("1").intern();
    /**
     * 2.16.840.1.101.3.4.2.2 -- id-sha384, NIST CSOR line 39
     */
    ASN1ObjectIdentifier id_sha384 = hashAlgs.branch("2").intern();
    /**
     * 2.16.840.1.101.3.4.2.3 -- id-sha512, NIST CSOR line 40
     */
    ASN1ObjectIdentifier id_sha512 = hashAlgs.branch("3").intern();
    /**
     * 2.16.840.1.101.3.4.2.4 -- id-sha224, NIST CSOR line 41
     */
    ASN1ObjectIdentifier id_sha224 = hashAlgs.branch("4").intern();
    /**
     * 2.16.840.1.101.3.4.2.5 -- id-sha512-224, NIST CSOR line 42
     */
    ASN1ObjectIdentifier id_sha512_224 = hashAlgs.branch("5").intern();
    /**
     * 2.16.840.1.101.3.4.2.6 -- id-sha512-256, NIST CSOR line 43
     */
    ASN1ObjectIdentifier id_sha512_256 = hashAlgs.branch("6").intern();

    /**
     * 2.16.840.1.101.3.4.2.7 -- id-sha3-224, NIST CSOR line 45
     */
    ASN1ObjectIdentifier id_sha3_224 = hashAlgs.branch("7").intern();
    /**
     * 2.16.840.1.101.3.4.2.8 -- id-sha3-256, NIST CSOR line 46
     */
    ASN1ObjectIdentifier id_sha3_256 = hashAlgs.branch("8").intern();
    /**
     * 2.16.840.1.101.3.4.2.9 -- id-sha3-384, NIST CSOR line 47
     */
    ASN1ObjectIdentifier id_sha3_384 = hashAlgs.branch("9").intern();
    /**
     * 2.16.840.1.101.3.4.2.10 -- id-sha3-512, NIST CSOR line 48
     */
    ASN1ObjectIdentifier id_sha3_512 = hashAlgs.branch("10").intern();
    /**
     * 2.16.840.1.101.3.4.2.11 -- id-shake128, NIST CSOR line 49
     */
    ASN1ObjectIdentifier id_shake128 = hashAlgs.branch("11").intern();
    /**
     * 2.16.840.1.101.3.4.2.12 -- id-shake256, NIST CSOR line 50
     */
    ASN1ObjectIdentifier id_shake256 = hashAlgs.branch("12").intern();
    /**
     * 2.16.840.1.101.3.4.2.13 -- id-hmacWithSHA3-224, NIST CSOR line 65
     */
    ASN1ObjectIdentifier id_hmacWithSHA3_224 = hashAlgs.branch("13").intern();
    /**
     * 2.16.840.1.101.3.4.2.14 -- id-hmacWithSHA3-256, NIST CSOR line 66
     */
    ASN1ObjectIdentifier id_hmacWithSHA3_256 = hashAlgs.branch("14").intern();
    /**
     * 2.16.840.1.101.3.4.2.15 -- id-hmacWithSHA3-384, NIST CSOR line 67
     */
    ASN1ObjectIdentifier id_hmacWithSHA3_384 = hashAlgs.branch("15").intern();
    /**
     * 2.16.840.1.101.3.4.2.16 -- id-hmacWithSHA3-512, NIST CSOR line 68
     */
    ASN1ObjectIdentifier id_hmacWithSHA3_512 = hashAlgs.branch("16").intern();
    /**
     * 2.16.840.1.101.3.4.2.17 -- id-shake128-len, NIST CSOR line 51
     */
    ASN1ObjectIdentifier id_shake128_len = hashAlgs.branch("17").intern();
    /**
     * 2.16.840.1.101.3.4.2.18 -- id-shake256-len, NIST CSOR line 52
     */
    ASN1ObjectIdentifier id_shake256_len = hashAlgs.branch("18").intern();
    /**
     * 2.16.840.1.101.3.4.2.19 -- id-KMACWithSHAKE128, NIST CSOR line 53
     */
    ASN1ObjectIdentifier id_KmacWithSHAKE128 = hashAlgs.branch("19").intern();
    /**
     * 2.16.840.1.101.3.4.2.20 -- id-KMACWithSHAKE256, NIST CSOR line 56
     */
    ASN1ObjectIdentifier id_KmacWithSHAKE256 = hashAlgs.branch("20").intern();
    /**
     * 2.16.840.1.101.3.4.2.21 -- id-KMAC128, NIST CSOR line 59
     */
    ASN1ObjectIdentifier id_Kmac128 = hashAlgs.branch("21").intern();
    /**
     * 2.16.840.1.101.3.4.2.22 -- id-KMAC256, NIST CSOR line 60
     */
    ASN1ObjectIdentifier id_Kmac256 = hashAlgs.branch("22").intern();

    /**
     * 2.16.840.1.101.3.4.1 -- aes, NIST CSOR line 6
     */
    ASN1ObjectIdentifier aes = nistAlgorithm.branch("1").intern();

    /**
     * 2.16.840.1.101.3.4.1.1 -- id-aes128-ECB, NIST CSOR line 7
     */
    ASN1ObjectIdentifier id_aes128_ECB = aes.branch("1").intern();
    /**
     * 2.16.840.1.101.3.4.1.2 -- id-aes128-CBC, NIST CSOR line 8
     */
    ASN1ObjectIdentifier id_aes128_CBC = aes.branch("2").intern();
    /**
     * 2.16.840.1.101.3.4.1.3 -- id-aes128-OFB, NIST CSOR line 9
     */
    ASN1ObjectIdentifier id_aes128_OFB = aes.branch("3").intern();
    /**
     * 2.16.840.1.101.3.4.1.4 -- id-aes128-CFB, NIST CSOR line 10
     */
    ASN1ObjectIdentifier id_aes128_CFB = aes.branch("4").intern();
    /**
     * 2.16.840.1.101.3.4.1.5 -- id-aes128-wrap, NIST CSOR line 11
     */
    ASN1ObjectIdentifier id_aes128_wrap = aes.branch("5").intern();
    /**
     * 2.16.840.1.101.3.4.1.6 -- id-aes128-GCM, NIST CSOR line 12
     */
    ASN1ObjectIdentifier id_aes128_GCM = aes.branch("6").intern();
    /**
     * 2.16.840.1.101.3.4.1.7 -- id-aes128-CCM, NIST CSOR line 13
     */
    ASN1ObjectIdentifier id_aes128_CCM = aes.branch("7").intern();
    /**
     * 2.16.840.1.101.3.4.1.8 -- id-aes128-wrap-pad, NIST CSOR line 14
     */
    ASN1ObjectIdentifier id_aes128_wrap_pad = aes.branch("8").intern();
    /**
     * 2.16.840.1.101.3.4.1.9 -- id-aes128-GMAC, NIST CSOR line 15
     */
    ASN1ObjectIdentifier id_aes128_GMAC = aes.branch("9").intern();


    /**
     * 2.16.840.1.101.3.4.1.21 -- id-aes192-ECB, NIST CSOR line 16
     */
    ASN1ObjectIdentifier id_aes192_ECB = aes.branch("21").intern();
    /**
     * 2.16.840.1.101.3.4.1.22 -- id-aes192-CBC, NIST CSOR line 17
     */
    ASN1ObjectIdentifier id_aes192_CBC = aes.branch("22").intern();
    /**
     * 2.16.840.1.101.3.4.1.23 -- id-aes192-OFB, NIST CSOR line 18
     */
    ASN1ObjectIdentifier id_aes192_OFB = aes.branch("23").intern();
    /**
     * 2.16.840.1.101.3.4.1.24 -- id-aes192-CFB, NIST CSOR line 19
     */
    ASN1ObjectIdentifier id_aes192_CFB = aes.branch("24").intern();
    /**
     * 2.16.840.1.101.3.4.1.25 -- id-aes192-wrap, NIST CSOR line 20
     */
    ASN1ObjectIdentifier id_aes192_wrap = aes.branch("25").intern();
    /**
     * 2.16.840.1.101.3.4.1.26 -- id-aes192-GCM, NIST CSOR line 21
     */
    ASN1ObjectIdentifier id_aes192_GCM = aes.branch("26").intern();
    /**
     * 2.16.840.1.101.3.4.1.27 -- id-aes192-CCM, NIST CSOR line 22
     */
    ASN1ObjectIdentifier id_aes192_CCM = aes.branch("27").intern();
    /**
     * 2.16.840.1.101.3.4.1.28 -- id-aes192-wrap-pad, NIST CSOR line 23
     */
    ASN1ObjectIdentifier id_aes192_wrap_pad = aes.branch("28").intern();

    /**
     * 2.16.840.1.101.3.4.1.29 -- id-aes192-GMAC, NIST CSOR line 24
     */
    ASN1ObjectIdentifier id_aes192_GMAC = aes.branch("29").intern();


    /**
     * 2.16.840.1.101.3.4.1.41 -- id-aes256-ECB, NIST CSOR line 25
     */
    ASN1ObjectIdentifier id_aes256_ECB = aes.branch("41").intern();
    /**
     * 2.16.840.1.101.3.4.1.42 -- id-aes256-CBC, NIST CSOR line 26
     */
    ASN1ObjectIdentifier id_aes256_CBC = aes.branch("42").intern();
    /**
     * 2.16.840.1.101.3.4.1.43 -- id-aes256-OFB, NIST CSOR line 27
     */
    ASN1ObjectIdentifier id_aes256_OFB = aes.branch("43").intern();
    /**
     * 2.16.840.1.101.3.4.1.44 -- id-aes256-CFB, NIST CSOR line 28
     */
    ASN1ObjectIdentifier id_aes256_CFB = aes.branch("44").intern();
    /**
     * 2.16.840.1.101.3.4.1.45 -- id-aes256-wrap, NIST CSOR line 29
     */
    ASN1ObjectIdentifier id_aes256_wrap = aes.branch("45").intern();
    /**
     * 2.16.840.1.101.3.4.1.46 -- id-aes256-GCM, NIST CSOR line 30
     */
    ASN1ObjectIdentifier id_aes256_GCM = aes.branch("46").intern();
    /**
     * 2.16.840.1.101.3.4.1.47 -- id-aes256-CCM, NIST CSOR line 31
     */
    ASN1ObjectIdentifier id_aes256_CCM = aes.branch("47").intern();
    /**
     * 2.16.840.1.101.3.4.1.48 -- id-aes256-wrap-pad, NIST CSOR line 32
     */
    ASN1ObjectIdentifier id_aes256_wrap_pad = aes.branch("48").intern();
    /**
     * 2.16.840.1.101.3.4.1.49 -- id-aes256-GMAC, NIST CSOR line 33
     */
    ASN1ObjectIdentifier id_aes256_GMAC = aes.branch("49").intern();


    //
    // signatures
    //
    /**
     * 2.16.840.1.101.3.4.3 -- sigAlgs, NIST CSOR line 70
     */
    ASN1ObjectIdentifier sigAlgs = nistAlgorithm.branch("3").intern();
    /**
     * 2.16.840.1.101.3.4.3 -- sigAlgs, NIST CSOR line 70
     */
    ASN1ObjectIdentifier id_dsa_with_sha2 = sigAlgs.intern();

    /**
     * 2.16.840.1.101.3.4.3.1 -- id-dsa-with-sha224, NIST CSOR line 71
     */
    ASN1ObjectIdentifier dsa_with_sha224 = sigAlgs.branch("1").intern();
    /**
     * 2.16.840.1.101.3.4.3.2 -- id-dsa-with-sha256, NIST CSOR line 72
     */
    ASN1ObjectIdentifier dsa_with_sha256 = sigAlgs.branch("2").intern();
    /**
     * 2.16.840.1.101.3.4.3.3 -- id-dsa-with-sha384, NIST CSOR line 73
     */
    ASN1ObjectIdentifier dsa_with_sha384 = sigAlgs.branch("3").intern();
    /**
     * 2.16.840.1.101.3.4.3.4 -- id-dsa-with-sha512, NIST CSOR line 74
     */
    ASN1ObjectIdentifier dsa_with_sha512 = sigAlgs.branch("4").intern();
    /**
     * 2.16.840.1.101.3.4.3.5 -- id-dsa-with-sha3-224, NIST CSOR line 75
     */
    ASN1ObjectIdentifier id_dsa_with_sha3_224 = sigAlgs.branch("5").intern();
    /**
     * 2.16.840.1.101.3.4.3.6 -- id-dsa-with-sha3-256, NIST CSOR line 76
     */
    ASN1ObjectIdentifier id_dsa_with_sha3_256 = sigAlgs.branch("6").intern();
    /**
     * 2.16.840.1.101.3.4.3.7 -- id-dsa-with-sha3-384, NIST CSOR line 77
     */
    ASN1ObjectIdentifier id_dsa_with_sha3_384 = sigAlgs.branch("7").intern();
    /**
     * 2.16.840.1.101.3.4.3.8 -- id-dsa-with-sha3-512, NIST CSOR line 78
     */
    ASN1ObjectIdentifier id_dsa_with_sha3_512 = sigAlgs.branch("8").intern();

    // ECDSA with SHA-3
    /**
     * 2.16.840.1.101.3.4.3.9 -- id-ecdsa-with-sha3-224, NIST CSOR line 79
     */
    ASN1ObjectIdentifier id_ecdsa_with_sha3_224 = sigAlgs.branch("9").intern();
    /**
     * 2.16.840.1.101.3.4.3.10 -- id-ecdsa-with-sha3-256, NIST CSOR line 80
     */
    ASN1ObjectIdentifier id_ecdsa_with_sha3_256 = sigAlgs.branch("10").intern();
    /**
     * 2.16.840.1.101.3.4.3.11 -- id-ecdsa-with-sha3-384, NIST CSOR line 81
     */
    ASN1ObjectIdentifier id_ecdsa_with_sha3_384 = sigAlgs.branch("11").intern();
    /**
     * 2.16.840.1.101.3.4.3.12 -- id-ecdsa-with-sha3-512, NIST CSOR line 82
     */
    ASN1ObjectIdentifier id_ecdsa_with_sha3_512 = sigAlgs.branch("12").intern();

    // RSA PKCS #1 v1.5 Signature with SHA-3 family.
    /**
     * 2.16.840.1.101.3.4.3.13 -- id-rsassa-pkcs1-v1-5-with-sha3-224, NIST CSOR line 90
     */
    ASN1ObjectIdentifier id_rsassa_pkcs1_v1_5_with_sha3_224 = sigAlgs.branch("13").intern();
    /**
     * 2.16.840.1.101.3.4.3.14 -- id-rsassa-pkcs1-v1-5-with-sha3-256, NIST CSOR line 91
     */
    ASN1ObjectIdentifier id_rsassa_pkcs1_v1_5_with_sha3_256 = sigAlgs.branch("14").intern();
    /**
     * 2.16.840.1.101.3.4.3.15 -- id-rsassa-pkcs1-v1-5-with-sha3-384, NIST CSOR line 92
     */
    ASN1ObjectIdentifier id_rsassa_pkcs1_v1_5_with_sha3_384 = sigAlgs.branch("15").intern();
    /**
     * 2.16.840.1.101.3.4.3.16 -- id-rsassa-pkcs1-v1-5-with-sha3-512, NIST CSOR line 93
     */
    ASN1ObjectIdentifier id_rsassa_pkcs1_v1_5_with_sha3_512 = sigAlgs.branch("16").intern();

    // "pure" ML-DSA
    /**
     * 2.16.840.1.101.3.4.3.17 -- id-ml-dsa-44, NIST CSOR line 84
     */
    ASN1ObjectIdentifier id_ml_dsa_44 = sigAlgs.branch("17").intern();
    /**
     * 2.16.840.1.101.3.4.3.18 -- id-ml-dsa-65, NIST CSOR line 85
     */
    ASN1ObjectIdentifier id_ml_dsa_65 = sigAlgs.branch("18").intern();
    /**
     * 2.16.840.1.101.3.4.3.19 -- id-ml-dsa-87, NIST CSOR line 86
     */
    ASN1ObjectIdentifier id_ml_dsa_87 = sigAlgs.branch("19").intern();
    // "pre-hash" ML-DSA
    /**
     * 2.16.840.1.101.3.4.3.32 -- id-hash-ml-dsa-44-with-sha512, NIST CSOR line 87
     */
    ASN1ObjectIdentifier id_hash_ml_dsa_44_with_sha512 = sigAlgs.branch("32").intern();
    /**
     * 2.16.840.1.101.3.4.3.33 -- id-hash-ml-dsa-65-with-sha512, NIST CSOR line 88
     */
    ASN1ObjectIdentifier id_hash_ml_dsa_65_with_sha512 = sigAlgs.branch("33").intern();
    /**
     * 2.16.840.1.101.3.4.3.34 -- id-hash-ml-dsa-87-with-sha512, NIST CSOR line 89
     */
    ASN1ObjectIdentifier id_hash_ml_dsa_87_with_sha512 = sigAlgs.branch("34").intern();

    // "pure" SLH-DSA
    /**
     * 2.16.840.1.101.3.4.3.20 -- id-slh-dsa-sha2-128s, NIST CSOR line 95
     */
    ASN1ObjectIdentifier id_slh_dsa_sha2_128s = sigAlgs.branch("20").intern();
    /**
     * 2.16.840.1.101.3.4.3.21 -- id-slh-dsa-sha2-128f, NIST CSOR line 96
     */
    ASN1ObjectIdentifier id_slh_dsa_sha2_128f = sigAlgs.branch("21").intern();
    /**
     * 2.16.840.1.101.3.4.3.22 -- id-slh-dsa-sha2-192s, NIST CSOR line 97
     */
    ASN1ObjectIdentifier id_slh_dsa_sha2_192s = sigAlgs.branch("22").intern();
    /**
     * 2.16.840.1.101.3.4.3.23 -- id-slh-dsa-sha2-192f, NIST CSOR line 98
     */
    ASN1ObjectIdentifier id_slh_dsa_sha2_192f = sigAlgs.branch("23").intern();
    /**
     * 2.16.840.1.101.3.4.3.24 -- id-slh-dsa-sha2-256s, NIST CSOR line 99
     */
    ASN1ObjectIdentifier id_slh_dsa_sha2_256s = sigAlgs.branch("24").intern();
    /**
     * 2.16.840.1.101.3.4.3.25 -- id-slh-dsa-sha2-256f, NIST CSOR line 100
     */
    ASN1ObjectIdentifier id_slh_dsa_sha2_256f = sigAlgs.branch("25").intern();
    /**
     * 2.16.840.1.101.3.4.3.26 -- id-slh-dsa-shake-128s, NIST CSOR line 101
     */
    ASN1ObjectIdentifier id_slh_dsa_shake_128s = sigAlgs.branch("26").intern();
    /**
     * 2.16.840.1.101.3.4.3.27 -- id-slh-dsa-shake-128f, NIST CSOR line 102
     */
    ASN1ObjectIdentifier id_slh_dsa_shake_128f = sigAlgs.branch("27").intern();
    /**
     * 2.16.840.1.101.3.4.3.28 -- id-slh-dsa-shake-192s, NIST CSOR line 103
     */
    ASN1ObjectIdentifier id_slh_dsa_shake_192s = sigAlgs.branch("28").intern();
    /**
     * 2.16.840.1.101.3.4.3.29 -- id-slh-dsa-shake-192f, NIST CSOR line 104
     */
    ASN1ObjectIdentifier id_slh_dsa_shake_192f = sigAlgs.branch("29").intern();
    /**
     * 2.16.840.1.101.3.4.3.30 -- id-slh-dsa-shake-256s, NIST CSOR line 105
     */
    ASN1ObjectIdentifier id_slh_dsa_shake_256s = sigAlgs.branch("30").intern();
    /**
     * 2.16.840.1.101.3.4.3.31 -- id-slh-dsa-shake-256f, NIST CSOR line 106
     */
    ASN1ObjectIdentifier id_slh_dsa_shake_256f = sigAlgs.branch("31").intern();
    // "pre-hash" SLH-DSA

    /**
     * 2.16.840.1.101.3.4.3.35 -- id-hash-slh-dsa-sha2-128s-with-sha256, NIST CSOR line 107
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_sha2_128s_with_sha256 = sigAlgs.branch("35").intern();
    /**
     * 2.16.840.1.101.3.4.3.36 -- id-hash-slh-dsa-sha2-128f-with-sha256, NIST CSOR line 108
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_sha2_128f_with_sha256 = sigAlgs.branch("36").intern();
    /**
     * 2.16.840.1.101.3.4.3.37 -- id-hash-slh-dsa-sha2-192s-with-sha512, NIST CSOR line 109
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_sha2_192s_with_sha512 = sigAlgs.branch("37").intern();
    /**
     * 2.16.840.1.101.3.4.3.38 -- id-hash-slh-dsa-sha2-192f-with-sha512, NIST CSOR line 110
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_sha2_192f_with_sha512 = sigAlgs.branch("38").intern();
    /**
     * 2.16.840.1.101.3.4.3.39 -- id-hash-slh-dsa-sha2-256s-with-sha512, NIST CSOR line 111
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_sha2_256s_with_sha512 = sigAlgs.branch("39").intern();
    /**
     * 2.16.840.1.101.3.4.3.40 -- id-hash-slh-dsa-sha2-256f-with-sha512, NIST CSOR line 112
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_sha2_256f_with_sha512 = sigAlgs.branch("40").intern();
    /**
     * 2.16.840.1.101.3.4.3.41 -- id-hash-slh-dsa-shake-128s-with-shake128, NIST CSOR line 113
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_shake_128s_with_shake128 = sigAlgs.branch("41").intern();
    /**
     * 2.16.840.1.101.3.4.3.42 -- id-hash-slh-dsa-shake-128f-with-shake128, NIST CSOR line 114
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_shake_128f_with_shake128 = sigAlgs.branch("42").intern();
    /**
     * 2.16.840.1.101.3.4.3.43 -- id-hash-slh-dsa-shake-192s-with-shake256, NIST CSOR line 115
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_shake_192s_with_shake256 = sigAlgs.branch("43").intern();
    /**
     * 2.16.840.1.101.3.4.3.44 -- id-hash-slh-dsa-shake-192f-with-shake256, NIST CSOR line 116
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_shake_192f_with_shake256 = sigAlgs.branch("44").intern();
    /**
     * 2.16.840.1.101.3.4.3.45 -- id-hash-slh-dsa-shake-256s-with-shake256, NIST CSOR line 117
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_shake_256s_with_shake256 = sigAlgs.branch("45").intern();
    /**
     * 2.16.840.1.101.3.4.3.46 -- id-hash-slh-dsa-shake-256f-with-shake256, NIST CSOR line 118
     */
    ASN1ObjectIdentifier id_hash_slh_dsa_shake_256f_with_shake256 = sigAlgs.branch("46").intern();


    //
    // KEMs - Key-Establishment Mechanisms
    //
    /**
     * 2.16.840.1.101.3.4.4 -- kems, NIST CSOR line 120
     */
    ASN1ObjectIdentifier kems = nistAlgorithm.branch("4").intern();

    // ML-KEM
    /**
     * 2.16.840.1.101.3.4.4.1 -- id-alg-ml-kem-512, NIST CSOR line 122
     */
    ASN1ObjectIdentifier id_alg_ml_kem_512 = kems.branch("1").intern();
    /**
     * 2.16.840.1.101.3.4.4.2 -- id-alg-ml-kem-768, NIST CSOR line 123
     */
    ASN1ObjectIdentifier id_alg_ml_kem_768 = kems.branch("2").intern();
    /**
     * 2.16.840.1.101.3.4.4.3 -- id-alg-ml-kem-1024, NIST CSOR line 124
     */
    ASN1ObjectIdentifier id_alg_ml_kem_1024 = kems.branch("3").intern();

}
