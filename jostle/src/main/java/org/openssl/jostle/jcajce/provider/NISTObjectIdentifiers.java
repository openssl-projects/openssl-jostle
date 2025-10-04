/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

/**
 *
 * NIST:
 *     iso/itu(2) joint-assign(16) us(840) organization(1) gov(101) csor(3) 
 */
interface NISTObjectIdentifiers
{
    //
    // nistalgorithms(4)
    //
    /** 2.16.840.1.101.3.4 -- algorithms */
    ASN1ObjectIdentifier    nistAlgorithm           = new ASN1ObjectIdentifier("2.16.840.1.101.3.4");

    /** 2.16.840.1.101.3.4.2 */
    ASN1ObjectIdentifier    hashAlgs                = nistAlgorithm.branch("2");

    /** 2.16.840.1.101.3.4.2.1 */
    ASN1ObjectIdentifier    id_sha256               = hashAlgs.branch("1");
    /** 2.16.840.1.101.3.4.2.2 */
    ASN1ObjectIdentifier    id_sha384               = hashAlgs.branch("2");
    /** 2.16.840.1.101.3.4.2.3 */
    ASN1ObjectIdentifier    id_sha512               = hashAlgs.branch("3");
    /** 2.16.840.1.101.3.4.2.4 */
    ASN1ObjectIdentifier    id_sha224               = hashAlgs.branch("4");
    /** 2.16.840.1.101.3.4.2.5 */
    ASN1ObjectIdentifier    id_sha512_224           = hashAlgs.branch("5");
    /** 2.16.840.1.101.3.4.2.6 */
    ASN1ObjectIdentifier    id_sha512_256           = hashAlgs.branch("6");

    /** 2.16.840.1.101.3.4.2.7 */
    ASN1ObjectIdentifier    id_sha3_224 = hashAlgs.branch("7");
    /** 2.16.840.1.101.3.4.2.8 */
    ASN1ObjectIdentifier    id_sha3_256 = hashAlgs.branch("8");
    /** 2.16.840.1.101.3.4.2.9 */
    ASN1ObjectIdentifier    id_sha3_384 = hashAlgs.branch("9");
    /** 2.16.840.1.101.3.4.2.10 */
    ASN1ObjectIdentifier    id_sha3_512 = hashAlgs.branch("10");
    /** 2.16.840.1.101.3.4.2.11 */
    ASN1ObjectIdentifier    id_shake128 = hashAlgs.branch("11");
    /** 2.16.840.1.101.3.4.2.12 */
    ASN1ObjectIdentifier    id_shake256 = hashAlgs.branch("12");
    /** 2.16.840.1.101.3.4.2.13 */
    ASN1ObjectIdentifier    id_hmacWithSHA3_224 = hashAlgs.branch("13");
    /** 2.16.840.1.101.3.4.2.14 */
    ASN1ObjectIdentifier    id_hmacWithSHA3_256 = hashAlgs.branch("14");
    /** 2.16.840.1.101.3.4.2.15 */
    ASN1ObjectIdentifier    id_hmacWithSHA3_384 = hashAlgs.branch("15");
    /** 2.16.840.1.101.3.4.2.16 */
    ASN1ObjectIdentifier    id_hmacWithSHA3_512 = hashAlgs.branch("16");
    /** 2.16.840.1.101.3.4.2.17 */
    ASN1ObjectIdentifier    id_shake128_len = hashAlgs.branch("17");
    /** 2.16.840.1.101.3.4.2.18 */
    ASN1ObjectIdentifier    id_shake256_len = hashAlgs.branch("18");
    /** 2.16.840.1.101.3.4.2.19 */
    ASN1ObjectIdentifier    id_KmacWithSHAKE128 = hashAlgs.branch("19");
    /** 2.16.840.1.101.3.4.2.20 */
    ASN1ObjectIdentifier    id_KmacWithSHAKE256 = hashAlgs.branch("20");
    /** 2.16.840.1.101.3.4.2.21 */
    ASN1ObjectIdentifier    id_Kmac128 = hashAlgs.branch("21");
    /** 2.16.840.1.101.3.4.2.22 */
    ASN1ObjectIdentifier    id_Kmac256 = hashAlgs.branch("22");

    /**
     * 2.16.840.1.101.3.4.1
     */
    ASN1ObjectIdentifier aes = nistAlgorithm.branch("1");

    /**
     * 2.16.840.1.101.3.4.1.1
     */
    ASN1ObjectIdentifier id_aes128_ECB = aes.branch("1");
    /**
     * 2.16.840.1.101.3.4.1.2
     */
    ASN1ObjectIdentifier id_aes128_CBC = aes.branch("2");
    /**
     * 2.16.840.1.101.3.4.1.3
     */
    ASN1ObjectIdentifier id_aes128_OFB = aes.branch("3");
    /**
     * 2.16.840.1.101.3.4.1.4
     */
    ASN1ObjectIdentifier id_aes128_CFB = aes.branch("4");
    /**
     * 2.16.840.1.101.3.4.1.5
     */
    ASN1ObjectIdentifier id_aes128_wrap = aes.branch("5");
    /**
     * 2.16.840.1.101.3.4.1.6
     */
    ASN1ObjectIdentifier id_aes128_GCM = aes.branch("6");
    /**
     * 2.16.840.1.101.3.4.1.7
     */
    ASN1ObjectIdentifier id_aes128_CCM = aes.branch("7");
    /**
     * 2.16.840.1.101.3.4.1.8
     */
    ASN1ObjectIdentifier id_aes128_wrap_pad = aes.branch("8");
    /**
     * 2.16.840.1.101.3.4.1.9
     */
    ASN1ObjectIdentifier id_aes128_GMAC = aes.branch("9");


    /**
     * 2.16.840.1.101.3.4.1.21
     */
    ASN1ObjectIdentifier id_aes192_ECB = aes.branch("21");
    /**
     * 2.16.840.1.101.3.4.1.22
     */
    ASN1ObjectIdentifier id_aes192_CBC = aes.branch("22");
    /**
     * 2.16.840.1.101.3.4.1.23
     */
    ASN1ObjectIdentifier id_aes192_OFB = aes.branch("23");
    /**
     * 2.16.840.1.101.3.4.1.24
     */
    ASN1ObjectIdentifier id_aes192_CFB = aes.branch("24");
    /**
     * 2.16.840.1.101.3.4.1.25
     */
    ASN1ObjectIdentifier id_aes192_wrap = aes.branch("25");
    /**
     * 2.16.840.1.101.3.4.1.26
     */
    ASN1ObjectIdentifier id_aes192_GCM = aes.branch("26");
    /**
     * 2.16.840.1.101.3.4.1.27
     */
    ASN1ObjectIdentifier id_aes192_CCM = aes.branch("27");
    /**
     * 2.16.840.1.101.3.4.1.28
     */
    ASN1ObjectIdentifier id_aes192_wrap_pad = aes.branch("28");

    /**
     * 2.16.840.1.101.3.4.1.29
     */
    ASN1ObjectIdentifier id_aes192_GMAC = aes.branch("29");


    /**
     * 2.16.840.1.101.3.4.1.41
     */
    ASN1ObjectIdentifier id_aes256_ECB = aes.branch("41");
    /**
     * 2.16.840.1.101.3.4.1.42
     */
    ASN1ObjectIdentifier id_aes256_CBC = aes.branch("42");
    /**
     * 2.16.840.1.101.3.4.1.43
     */
    ASN1ObjectIdentifier id_aes256_OFB = aes.branch("43");
    /**
     * 2.16.840.1.101.3.4.1.44
     */
    ASN1ObjectIdentifier id_aes256_CFB = aes.branch("44");
    /**
     * 2.16.840.1.101.3.4.1.45
     */
    ASN1ObjectIdentifier id_aes256_wrap = aes.branch("45");
    /**
     * 2.16.840.1.101.3.4.1.46
     */
    ASN1ObjectIdentifier id_aes256_GCM = aes.branch("46");
    /**
     * 2.16.840.1.101.3.4.1.47
     */
    ASN1ObjectIdentifier id_aes256_CCM = aes.branch("47");
    /**
     * 2.16.840.1.101.3.4.1.48
     */
    ASN1ObjectIdentifier id_aes256_wrap_pad = aes.branch("48");
    /**
     * 2.16.840.1.101.3.4.1.49
     */
    ASN1ObjectIdentifier id_aes256_GMAC = aes.branch("49");


    //
    // signatures
    //
    /**
     * 2.16.840.1.101.3.4.3
     */
    ASN1ObjectIdentifier sigAlgs = nistAlgorithm.branch("3");

    ASN1ObjectIdentifier id_dsa_with_sha2 = sigAlgs;

    /** 2.16.840.1.101.3.4.3.1 */
    ASN1ObjectIdentifier    dsa_with_sha224         = sigAlgs.branch("1");
    /** 2.16.840.1.101.3.4.3.2 */
    ASN1ObjectIdentifier    dsa_with_sha256         = sigAlgs.branch("2");
    /** 2.16.840.1.101.3.4.3.3 */
    ASN1ObjectIdentifier    dsa_with_sha384         = sigAlgs.branch("3");
    /** 2.16.840.1.101.3.4.3.4 */
    ASN1ObjectIdentifier    dsa_with_sha512         = sigAlgs.branch("4");
    /** 2.16.840.1.101.3.4.3.5 */
    ASN1ObjectIdentifier    id_dsa_with_sha3_224       = sigAlgs.branch("5");
    /** 2.16.840.1.101.3.4.3.6 */
    ASN1ObjectIdentifier    id_dsa_with_sha3_256       = sigAlgs.branch("6");
    /** 2.16.840.1.101.3.4.3.7 */
    ASN1ObjectIdentifier    id_dsa_with_sha3_384       = sigAlgs.branch("7");
    /** 2.16.840.1.101.3.4.3.8 */
    ASN1ObjectIdentifier    id_dsa_with_sha3_512       = sigAlgs.branch("8");

    // ECDSA with SHA-3
    /** 2.16.840.1.101.3.4.3.9 */
    ASN1ObjectIdentifier    id_ecdsa_with_sha3_224       = sigAlgs.branch("9");
    /** 2.16.840.1.101.3.4.3.10 */
    ASN1ObjectIdentifier    id_ecdsa_with_sha3_256       = sigAlgs.branch("10");
    /** 2.16.840.1.101.3.4.3.11 */
    ASN1ObjectIdentifier    id_ecdsa_with_sha3_384       = sigAlgs.branch("11");
    /** 2.16.840.1.101.3.4.3.12 */
    ASN1ObjectIdentifier    id_ecdsa_with_sha3_512       = sigAlgs.branch("12");

    // RSA PKCS #1 v1.5 Signature with SHA-3 family.
    /** 2.16.840.1.101.3.4.3.13 */
    ASN1ObjectIdentifier    id_rsassa_pkcs1_v1_5_with_sha3_224       = sigAlgs.branch("13");
    /** 2.16.840.1.101.3.4.3.14 */
    ASN1ObjectIdentifier    id_rsassa_pkcs1_v1_5_with_sha3_256       = sigAlgs.branch("14");
    /** 2.16.840.1.101.3.4.3.15 */
    ASN1ObjectIdentifier    id_rsassa_pkcs1_v1_5_with_sha3_384       = sigAlgs.branch("15");
    /** 2.16.840.1.101.3.4.3.16 */
    ASN1ObjectIdentifier    id_rsassa_pkcs1_v1_5_with_sha3_512       = sigAlgs.branch("16");

    // "pure" ML-DSA
    /** 2.16.840.1.101.3.4.3.17 */
    ASN1ObjectIdentifier    id_ml_dsa_44       = sigAlgs.branch("17");
    /** 2.16.840.1.101.3.4.3.18 */
    ASN1ObjectIdentifier    id_ml_dsa_65       = sigAlgs.branch("18");
    /** 2.16.840.1.101.3.4.3.19 */
    ASN1ObjectIdentifier    id_ml_dsa_87       = sigAlgs.branch("19");
    // "pre-hash" ML-DSA
    /** 2.16.840.1.101.3.4.3.32 */
    ASN1ObjectIdentifier    id_hash_ml_dsa_44_with_sha512    = sigAlgs.branch("32");
    /** 2.16.840.1.101.3.4.3.33 */
    ASN1ObjectIdentifier    id_hash_ml_dsa_65_with_sha512    = sigAlgs.branch("33");
    /** 2.16.840.1.101.3.4.3.34 */
    ASN1ObjectIdentifier    id_hash_ml_dsa_87_with_sha512    = sigAlgs.branch("34");

    // "pure" SLH-DSA
    /** 2.16.840.1.101.3.4.3.20 */
    ASN1ObjectIdentifier    id_slh_dsa_sha2_128s       = sigAlgs.branch("20");
    /** 2.16.840.1.101.3.4.3.21 */
    ASN1ObjectIdentifier    id_slh_dsa_sha2_128f       = sigAlgs.branch("21");
    /** 2.16.840.1.101.3.4.3.22 */
    ASN1ObjectIdentifier    id_slh_dsa_sha2_192s       = sigAlgs.branch("22");
    /** 2.16.840.1.101.3.4.3.23 */
    ASN1ObjectIdentifier    id_slh_dsa_sha2_192f       = sigAlgs.branch("23");
    /** 2.16.840.1.101.3.4.3.24 */
    ASN1ObjectIdentifier    id_slh_dsa_sha2_256s       = sigAlgs.branch("24");
    /** 2.16.840.1.101.3.4.3.25 */
    ASN1ObjectIdentifier    id_slh_dsa_sha2_256f       = sigAlgs.branch("25");
    /** 2.16.840.1.101.3.4.3.26 */
    ASN1ObjectIdentifier    id_slh_dsa_shake_128s      = sigAlgs.branch("26");
    /** 2.16.840.1.101.3.4.3.27 */
    ASN1ObjectIdentifier    id_slh_dsa_shake_128f      = sigAlgs.branch("27");
    /** 2.16.840.1.101.3.4.3.28 */
    ASN1ObjectIdentifier    id_slh_dsa_shake_192s      = sigAlgs.branch("28");
    /** 2.16.840.1.101.3.4.3.29 */
    ASN1ObjectIdentifier    id_slh_dsa_shake_192f      = sigAlgs.branch("29");
    /** 2.16.840.1.101.3.4.3.30 */
    ASN1ObjectIdentifier    id_slh_dsa_shake_256s      = sigAlgs.branch("30");
    /** 2.16.840.1.101.3.4.3.31 */
    ASN1ObjectIdentifier    id_slh_dsa_shake_256f      = sigAlgs.branch("31");
    // "pre-hash" SLH-DSA

    /** 2.16.840.1.101.3.4.3.35 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_sha2_128s_with_sha256     = sigAlgs.branch("35");
    /** 2.16.840.1.101.3.4.3.36 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_sha2_128f_with_sha256     = sigAlgs.branch("36");
    /** 2.16.840.1.101.3.4.3.37 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_sha2_192s_with_sha512     = sigAlgs.branch("37");
    /** 2.16.840.1.101.3.4.3.38 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_sha2_192f_with_sha512     = sigAlgs.branch("38");
    /** 2.16.840.1.101.3.4.3.39 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_sha2_256s_with_sha512     = sigAlgs.branch("39");
    /** 2.16.840.1.101.3.4.3.40 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_sha2_256f_with_sha512     = sigAlgs.branch("40");
    /** 2.16.840.1.101.3.4.3.41 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_shake_128s_with_shake128  = sigAlgs.branch("41");
    /** 2.16.840.1.101.3.4.3.42 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_shake_128f_with_shake128  = sigAlgs.branch("42");
    /** 2.16.840.1.101.3.4.3.43 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_shake_192s_with_shake256  = sigAlgs.branch("43");
    /** 2.16.840.1.101.3.4.3.44 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_shake_192f_with_shake256  = sigAlgs.branch("44");
    /** 2.16.840.1.101.3.4.3.45 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_shake_256s_with_shake256  = sigAlgs.branch("45");
    /** 2.16.840.1.101.3.4.3.46 */
    ASN1ObjectIdentifier    id_hash_slh_dsa_shake_256f_with_shake256  = sigAlgs.branch("46");


    //
    // KEMs - Key-Establishment Mechanisms
    //
    /**
     * 2.16.840.1.101.3.4.4
     */
    ASN1ObjectIdentifier kems = nistAlgorithm.branch("4");

    // ML-KEM
    /** 2.16.840.1.101.3.4.4.1 */
    ASN1ObjectIdentifier    id_alg_ml_kem_512      = kems.branch("1");
    /** 2.16.840.1.101.3.4.4.2 */
    ASN1ObjectIdentifier    id_alg_ml_kem_768      = kems.branch("2");
    /** 2.16.840.1.101.3.4.4.3 */
    ASN1ObjectIdentifier    id_alg_ml_kem_1024     = kems.branch("3");

}
