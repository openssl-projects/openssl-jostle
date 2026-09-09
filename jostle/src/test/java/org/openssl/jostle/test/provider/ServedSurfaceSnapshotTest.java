/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLNI;
import org.openssl.jostle.test.util.CipherFamilies;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The golden snapshot of what the base provider ({@code JSL}) registers, and
 * the guard that every registered service is CLAIMED by a family prefix.
 * <p>
 * Base-side counterpart of {@code FIPSServedSurfaceSnapshotTest}, and the guard
 * the family agreement classes lean on. Each of those discovers its own surface
 * by SPI class-name prefix and asserts what it finds is non-empty — which
 * catches a package RENAMED out from under it, loudly. What it cannot catch is
 * the PARTIAL case: a registrar split across two packages, or a service moved
 * into a package no family prefix covers. Those services silently leave every
 * family's discovered set while each family's own non-emptiness assertion still
 * holds. {@link #everyRegisteredServiceIsClaimedByAFamilyPrefix()} is what sees
 * that, by requiring the union of the prefixes to account for every service.
 * <p>
 * It also carries the per-NAME removal direction that no base-side guard had:
 * the family classes discover from the provider, so discovery cannot notice a
 * REMOVED registration — deriving the expected set from the provider would
 * compare the provider against itself. A transcribed golden set is the only
 * thing that can fail when a service disappears, which is why this one is
 * hand-held rather than generated at runtime.
 * <p>
 * <b>The PQC families are GATED on the base provider too</b>, not only under
 * FIPS: {@code ProvMLDSA}, {@code ProvMLKEM}, {@code ProvMLXKEM} and
 * {@code ProvSLHDSA} each require OpenSSL 3.5 or later and register nothing
 * against an older mainline. Their absence is therefore permitted, but only
 * when the loaded OpenSSL genuinely cannot serve them — asked of OpenSSL, not
 * assumed, so a build that silently stopped registering a family it CAN serve
 * fails here.
 */
public class ServedSurfaceSnapshotTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final String[] GOLDEN = {
            "AlgorithmParameterGenerator.DH", "AlgorithmParameterGenerator.DSA",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.2",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.22",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.26",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.27",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.42",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.46",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.47",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.6",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.7", "AlgorithmParameters.AES",
            "AlgorithmParameters.ARIA", "AlgorithmParameters.CAMELLIA", "AlgorithmParameters.CCM",
            "AlgorithmParameters.CHACHA20-POLY1305", "AlgorithmParameters.DESEDE",
            "AlgorithmParameters.DH", "AlgorithmParameters.DSA", "AlgorithmParameters.EC",
            "AlgorithmParameters.GCM", "AlgorithmParameters.SM4", "CertificateFactory.X.509",
            "Cipher.1.2.392.200011.61.1.1.1.2", "Cipher.1.2.392.200011.61.1.1.1.3",
            "Cipher.1.2.392.200011.61.1.1.1.4", "Cipher.1.2.410.200046.1.1.12",
            "Cipher.1.2.410.200046.1.1.2", "Cipher.1.2.410.200046.1.1.7",
            "Cipher.1.2.840.113549.3.7", "Cipher.2.16.840.1.101.3.4.1.2",
            "Cipher.2.16.840.1.101.3.4.1.22", "Cipher.2.16.840.1.101.3.4.1.25",
            "Cipher.2.16.840.1.101.3.4.1.26", "Cipher.2.16.840.1.101.3.4.1.27",
            "Cipher.2.16.840.1.101.3.4.1.28",
            "Cipher.2.16.840.1.101.3.4.1.42", "Cipher.2.16.840.1.101.3.4.1.45",
            "Cipher.2.16.840.1.101.3.4.1.46", "Cipher.2.16.840.1.101.3.4.1.48",
            "Cipher.2.16.840.1.101.3.4.1.47",
            "Cipher.2.16.840.1.101.3.4.1.5", "Cipher.2.16.840.1.101.3.4.1.6",
            "Cipher.2.16.840.1.101.3.4.1.7",
            "Cipher.2.16.840.1.101.3.4.1.8", "Cipher.AES", "Cipher.AES/CBC/CS3PADDING",
            "Cipher.AES/CCM/NOPADDING", "Cipher.AES/CTS/NOPADDING", "Cipher.AES/XTS/NOPADDING",
            "Cipher.AES128", "Cipher.AES192", "Cipher.AES256", "Cipher.AESRFC3211WRAP", "Cipher.AESWRAP",
            "Cipher.AESWRAPINV", "Cipher.AESWRAPPAD", "Cipher.ARIA", "Cipher.ARIA/CCM/NOPADDING",
            "Cipher.ARIA128", "Cipher.ARIA192", "Cipher.ARIA256", "Cipher.CAMELLIA",
            "Cipher.CAMELLIARFC3211WRAP",
            "Cipher.CAMELLIA128", "Cipher.CAMELLIA192", "Cipher.CAMELLIA256", "Cipher.CHACHA20",
            "Cipher.CHACHA20-POLY1305", "Cipher.DESEDE", "Cipher.DESEDERFC3211WRAP",
            "Cipher.ML-KEM", "Cipher.RSA",
            "Cipher.RSA-KTS-KEM-KWS", "Cipher.RSA/ECB/PKCS1PADDING", "Cipher.SM4",
            "Cipher.SM4/CCM/NOPADDING", "KeyAgreement.DH", "KeyAgreement.DHWITHRFC2631KDF",
            "KeyAgreement.ECDH", "KeyAgreement.ECDHWITHSHA1KDF", "KeyAgreement.ECDHWITHSHA224KDF",
            "KeyAgreement.ECDHWITHSHA256KDF", "KeyAgreement.ECDHWITHSHA384KDF",
            "KeyAgreement.ECDHWITHSHA512KDF", "KeyAgreement.X25519", "KeyAgreement.X448",
            "KeyAgreement.XDH", "KeyFactory.DH", "KeyFactory.DSA", "KeyFactory.EC",
            "KeyFactory.ED", "KeyFactory.ED25519", "KeyFactory.ED448", "KeyFactory.ML-DSA-44",
            "KeyFactory.ML-DSA-65", "KeyFactory.ML-DSA-87", "KeyFactory.ML-KEM-1024",
            "KeyFactory.ML-KEM-512", "KeyFactory.ML-KEM-768", "KeyFactory.MLDSA",
            "KeyFactory.MLKEM", "KeyFactory.RSA", "KeyFactory.SECP256R1MLKEM768",
            "KeyFactory.SECP384R1MLKEM1024", "KeyFactory.SLH-DSA-SHA2-128F",
            "KeyFactory.SLH-DSA-SHA2-128S", "KeyFactory.SLH-DSA-SHA2-192F",
            "KeyFactory.SLH-DSA-SHA2-192S", "KeyFactory.SLH-DSA-SHA2-256F",
            "KeyFactory.SLH-DSA-SHA2-256S", "KeyFactory.SLH-DSA-SHAKE-128F",
            "KeyFactory.SLH-DSA-SHAKE-128S", "KeyFactory.SLH-DSA-SHAKE-192F",
            "KeyFactory.SLH-DSA-SHAKE-192S", "KeyFactory.SLH-DSA-SHAKE-256F",
            "KeyFactory.SLH-DSA-SHAKE-256S", "KeyFactory.SLHDSA", "KeyFactory.X25519",
            "KeyFactory.X25519MLKEM768", "KeyFactory.X448", "KeyFactory.X448MLKEM1024",
            "KeyFactory.XDH", "KeyGenerator.AES", "KeyGenerator.AES128", "KeyGenerator.AES192",
            "KeyGenerator.AES256", "KeyGenerator.ARIA", "KeyGenerator.CAMELLIA",
            "KeyGenerator.CHACHA20", "KeyGenerator.DESEDE", "KeyGenerator.SM4",
            "KeyGenerator.ML-KEM-1024", "KeyGenerator.ML-KEM-512", "KeyGenerator.ML-KEM-768",
            "KeyGenerator.MLKEM", "KeyGenerator.SECP256R1MLKEM768",
            "KeyGenerator.SECP384R1MLKEM1024", "KeyGenerator.X25519MLKEM768",
            "KeyGenerator.X448MLKEM1024", "KeyPairGenerator.DH", "KeyPairGenerator.DSA",
            "KeyPairGenerator.EC", "KeyPairGenerator.ED", "KeyPairGenerator.ED25519",
            "KeyPairGenerator.ED448", "KeyPairGenerator.ML-DSA-44", "KeyPairGenerator.ML-DSA-65",
            "KeyPairGenerator.ML-DSA-87", "KeyPairGenerator.ML-KEM-1024",
            "KeyPairGenerator.ML-KEM-512", "KeyPairGenerator.ML-KEM-768", "KeyPairGenerator.MLDSA",
            "KeyPairGenerator.MLKEM", "KeyPairGenerator.RSA", "KeyPairGenerator.SECP256R1MLKEM768",
            "KeyPairGenerator.SECP384R1MLKEM1024", "KeyPairGenerator.SLH-DSA-SHA2-128F",
            "KeyPairGenerator.SLH-DSA-SHA2-128S", "KeyPairGenerator.SLH-DSA-SHA2-192F",
            "KeyPairGenerator.SLH-DSA-SHA2-192S", "KeyPairGenerator.SLH-DSA-SHA2-256F",
            "KeyPairGenerator.SLH-DSA-SHA2-256S", "KeyPairGenerator.SLH-DSA-SHAKE-128F",
            "KeyPairGenerator.SLH-DSA-SHAKE-128S", "KeyPairGenerator.SLH-DSA-SHAKE-192F",
            "KeyPairGenerator.SLH-DSA-SHAKE-192S", "KeyPairGenerator.SLH-DSA-SHAKE-256F",
            "KeyPairGenerator.SLH-DSA-SHAKE-256S", "KeyPairGenerator.SLHDSA",
            "KeyPairGenerator.X25519", "KeyPairGenerator.X25519MLKEM768", "KeyPairGenerator.X448",
            "KeyPairGenerator.X448MLKEM1024", "KeyStore.PKCS12", "KeyStore.PKCS12-3DES-3DES",
            "KeyStore.PKCS12-AES256-AES128", "KeyStore.PKCS12-PBMAC1", "Mac.AESCMAC",
            "Mac.AESGMAC", "Mac.HMACMD5", "Mac.HMACMD5SHA1", "Mac.HMACRIPEMD160", "Mac.HMACSHA1",
            "Mac.HMACSHA224", "Mac.HMACSHA256", "Mac.HMACSHA3-224", "Mac.HMACSHA3-256",
            "Mac.HMACSHA3-384", "Mac.HMACSHA3-512", "Mac.HMACSHA384", "Mac.HMACSHA512",
            "Mac.HMACSHA512/224", "Mac.HMACSHA512/256", "Mac.HMACSM3", "Mac.KMAC128",
            "Mac.KMAC256", "Mac.POLY1305", "MessageDigest.BLAKE2B-512",
            "MessageDigest.BLAKE2S-256", "MessageDigest.MD5", "MessageDigest.MD5-SHA1",
            "MessageDigest.RIPEMD-160", "MessageDigest.SHA1", "MessageDigest.SHA2-224",
            "MessageDigest.SHA2-256", "MessageDigest.SHA2-384", "MessageDigest.SHA2-512",
            "MessageDigest.SHA2-512/224", "MessageDigest.SHA2-512/256", "MessageDigest.SHA3-224",
            "MessageDigest.SHA3-256", "MessageDigest.SHA3-384", "MessageDigest.SHA3-512",
            "MessageDigest.SHAKE-128", "MessageDigest.SHAKE-256", "MessageDigest.SHAKE128-256",
            "MessageDigest.SHAKE256-512", "MessageDigest.SM3",
            "SecretKeyFactory.1.3.6.1.4.1.11591.4.11", "SecretKeyFactory.ARGON2",
            "SecretKeyFactory.HKDF-SHA256", "SecretKeyFactory.HKDF-SHA384",
            "SecretKeyFactory.HKDF-SHA512", "SecretKeyFactory.KBKDF-CMAC-AES128",
            "SecretKeyFactory.KBKDF-CMAC-AES192", "SecretKeyFactory.KBKDF-CMAC-AES256",
            "SecretKeyFactory.KBKDF-HMAC-SHA1", "SecretKeyFactory.KBKDF-HMAC-SHA224",
            "SecretKeyFactory.KBKDF-HMAC-SHA256", "SecretKeyFactory.KBKDF-HMAC-SHA384",
            "SecretKeyFactory.KBKDF-HMAC-SHA512", "SecretKeyFactory.PBKDF2",
            "SecretKeyFactory.PBKDF2WITHHMACBLAKE2B-512",
            "SecretKeyFactory.PBKDF2WITHHMACBLAKE2S-256", "SecretKeyFactory.PBKDF2WITHHMACMD5",
            "SecretKeyFactory.PBKDF2WITHHMACMD5-SHA1", "SecretKeyFactory.PBKDF2WITHHMACRIPEMD160",
            "SecretKeyFactory.PBKDF2WITHASCII",
            "SecretKeyFactory.PBKDF2WITHHMACSHA1", "SecretKeyFactory.PBKDF2WITHHMACSHA224",
            "SecretKeyFactory.PBKDF2WITHHMACSHA256", "SecretKeyFactory.PBKDF2WITHHMACSHA3-224",
            "SecretKeyFactory.PBKDF2WITHHMACSHA3-256", "SecretKeyFactory.PBKDF2WITHHMACSHA3-384",
            "SecretKeyFactory.PBKDF2WITHHMACSHA3-512", "SecretKeyFactory.PBKDF2WITHHMACSHA384",
            "SecretKeyFactory.PBKDF2WITHHMACSHA512", "SecretKeyFactory.PBKDF2WITHHMACSHA512-224",
            "SecretKeyFactory.PBKDF2WITHHMACSHA512-256", "SecretKeyFactory.PBKDF2WITHHMACSM3",
            "SecretKeyFactory.SCRYPT", "SecretKeyFactory.SSHKDF-SHA1",
            "SecretKeyFactory.SSHKDF-SHA224", "SecretKeyFactory.SSHKDF-SHA256",
            "SecretKeyFactory.SSHKDF-SHA384", "SecretKeyFactory.SSHKDF-SHA512",
            "SecretKeyFactory.SSKDF-SHA1", "SecretKeyFactory.SSKDF-SHA224",
            "SecretKeyFactory.SSKDF-SHA256", "SecretKeyFactory.SSKDF-SHA384",
            "SecretKeyFactory.SSKDF-SHA512", "SecureRandom.CTR-DRBG",
            "SecureRandom.CTR-DRBG-AES128", "SecureRandom.CTR-DRBG-AES192",
            "SecureRandom.CTR-DRBG-AES256", "SecureRandom.DEFAULT", "SecureRandom.DRBG",
            "SecureRandom.HASH-DRBG", "SecureRandom.HASH-DRBG-SHA1",
            "SecureRandom.HASH-DRBG-SHA224", "SecureRandom.HASH-DRBG-SHA256",
            "SecureRandom.HASH-DRBG-SHA384", "SecureRandom.HASH-DRBG-SHA512",
            "SecureRandom.HMAC-DRBG", "SecureRandom.HMAC-DRBG-SHA1",
            "SecureRandom.HMAC-DRBG-SHA224", "SecureRandom.HMAC-DRBG-SHA256",
            "SecureRandom.HMAC-DRBG-SHA384", "SecureRandom.HMAC-DRBG-SHA512",
            "Signature.DET-SLH-DSA-NONE", "Signature.DET-SLH-DSA-PURE", "Signature.ED25519",
            "Signature.ED25519CTX", "Signature.ED25519PH", "Signature.ED448", "Signature.ED448PH",
            "Signature.EDDSA", "Signature.MD5WITHRSA", "Signature.ML-DSA-44",
            "Signature.ML-DSA-65", "Signature.ML-DSA-87", "Signature.ML-DSA-CALCULATE-MU",
            "Signature.ML-DSA-EXTERNAL-MU", "Signature.MLDSA", "Signature.NONEWITHDSA",
            "Signature.NONEWITHECDSA", "Signature.NONEWITHRSA", "Signature.RSASSA-PSS",
            "Signature.SHA1WITHDSA", "Signature.SHA1WITHECDSA", "Signature.SHA1WITHRSA",
            "Signature.SHA1WITHRSAANDMGF1", "Signature.SHA224WITHDSA", "Signature.SHA224WITHECDSA",
            "Signature.SHA224WITHRSA", "Signature.SHA224WITHRSAANDMGF1", "Signature.SHA256WITHDSA",
            "Signature.SHA256WITHECDSA", "Signature.SHA256WITHRSA",
            "Signature.SHA256WITHRSAANDMGF1", "Signature.SHA3-224WITHDSA",
            "Signature.SHA3-224WITHECDSA", "Signature.SHA3-224WITHRSA",
            "Signature.SHA3-224WITHRSAANDMGF1", "Signature.SHA3-256WITHDSA",
            "Signature.SHA3-256WITHECDSA", "Signature.SHA3-256WITHRSA",
            "Signature.SHA3-256WITHRSAANDMGF1", "Signature.SHA3-384WITHDSA",
            "Signature.SHA3-384WITHECDSA", "Signature.SHA3-384WITHRSA",
            "Signature.SHA3-384WITHRSAANDMGF1", "Signature.SHA3-512WITHDSA",
            "Signature.SHA3-512WITHECDSA", "Signature.SHA3-512WITHRSA",
            "Signature.SHA3-512WITHRSAANDMGF1", "Signature.SHA384WITHDSA",
            "Signature.SHA384WITHECDSA", "Signature.SHA384WITHRSA",
            "Signature.SHA384WITHRSAANDMGF1", "Signature.SHA512WITHDSA",
            "Signature.SHA512(224)WITHRSA", "Signature.SHA512(256)WITHRSA",
            "Signature.SHA512WITHECDSA", "Signature.SHA512WITHRSA",
            "Signature.SHA512WITHRSAANDMGF1", "Signature.SLH-DSA-NONE", "Signature.SLH-DSA-PURE",
            "Signature.SLH-DSA-SHA2-128F", "Signature.SLH-DSA-SHA2-128S",
            "Signature.SLH-DSA-SHA2-192F", "Signature.SLH-DSA-SHA2-192S",
            "Signature.SLH-DSA-SHA2-256F", "Signature.SLH-DSA-SHA2-256S",
            "Signature.SLH-DSA-SHAKE-128F", "Signature.SLH-DSA-SHAKE-128S",
            "Signature.SLH-DSA-SHAKE-192F", "Signature.SLH-DSA-SHAKE-192S",
            "Signature.SLH-DSA-SHAKE-256F", "Signature.SLH-DSA-SHAKE-256S", "Signature.SLHDSA"
    };
    private static final String[] MLDSA_GATED = {
            "KeyFactory.ML-DSA-44", "KeyFactory.ML-DSA-65", "KeyFactory.ML-DSA-87",
            "KeyFactory.MLDSA", "KeyPairGenerator.ML-DSA-44", "KeyPairGenerator.ML-DSA-65",
            "KeyPairGenerator.ML-DSA-87", "KeyPairGenerator.MLDSA", "Signature.ML-DSA-44",
            "Signature.ML-DSA-65", "Signature.ML-DSA-87", "Signature.ML-DSA-CALCULATE-MU",
            "Signature.ML-DSA-EXTERNAL-MU", "Signature.MLDSA"
    };
    private static final String[] MLKEM_GATED = {
            "Cipher.ML-KEM", "KeyFactory.ML-KEM-1024", "KeyFactory.ML-KEM-512",
            "KeyFactory.ML-KEM-768", "KeyFactory.MLKEM", "KeyGenerator.ML-KEM-1024",
            "KeyGenerator.ML-KEM-512", "KeyGenerator.ML-KEM-768", "KeyGenerator.MLKEM",
            "KeyPairGenerator.ML-KEM-1024", "KeyPairGenerator.ML-KEM-512",
            "KeyPairGenerator.ML-KEM-768", "KeyPairGenerator.MLKEM"
    };
    private static final String[] MLXKEM_GATED = {
            "KeyFactory.SECP256R1MLKEM768", "KeyFactory.SECP384R1MLKEM1024",
            "KeyFactory.X25519MLKEM768", "KeyFactory.X448MLKEM1024",
            "KeyGenerator.SECP256R1MLKEM768", "KeyGenerator.SECP384R1MLKEM1024",
            "KeyGenerator.X25519MLKEM768", "KeyGenerator.X448MLKEM1024",
            "KeyPairGenerator.SECP256R1MLKEM768", "KeyPairGenerator.SECP384R1MLKEM1024",
            "KeyPairGenerator.X25519MLKEM768", "KeyPairGenerator.X448MLKEM1024"
    };
    private static final String[] SLHDSA_GATED = {
            "KeyFactory.SLH-DSA-SHA2-128F", "KeyFactory.SLH-DSA-SHA2-128S",
            "KeyFactory.SLH-DSA-SHA2-192F", "KeyFactory.SLH-DSA-SHA2-192S",
            "KeyFactory.SLH-DSA-SHA2-256F", "KeyFactory.SLH-DSA-SHA2-256S",
            "KeyFactory.SLH-DSA-SHAKE-128F", "KeyFactory.SLH-DSA-SHAKE-128S",
            "KeyFactory.SLH-DSA-SHAKE-192F", "KeyFactory.SLH-DSA-SHAKE-192S",
            "KeyFactory.SLH-DSA-SHAKE-256F", "KeyFactory.SLH-DSA-SHAKE-256S", "KeyFactory.SLHDSA",
            "KeyPairGenerator.SLH-DSA-SHA2-128F", "KeyPairGenerator.SLH-DSA-SHA2-128S",
            "KeyPairGenerator.SLH-DSA-SHA2-192F", "KeyPairGenerator.SLH-DSA-SHA2-192S",
            "KeyPairGenerator.SLH-DSA-SHA2-256F", "KeyPairGenerator.SLH-DSA-SHA2-256S",
            "KeyPairGenerator.SLH-DSA-SHAKE-128F", "KeyPairGenerator.SLH-DSA-SHAKE-128S",
            "KeyPairGenerator.SLH-DSA-SHAKE-192F", "KeyPairGenerator.SLH-DSA-SHAKE-192S",
            "KeyPairGenerator.SLH-DSA-SHAKE-256F", "KeyPairGenerator.SLH-DSA-SHAKE-256S",
            "KeyPairGenerator.SLHDSA", "Signature.DET-SLH-DSA-NONE", "Signature.DET-SLH-DSA-PURE",
            "Signature.SLH-DSA-NONE", "Signature.SLH-DSA-PURE", "Signature.SLH-DSA-SHA2-128F",
            "Signature.SLH-DSA-SHA2-128S", "Signature.SLH-DSA-SHA2-192F",
            "Signature.SLH-DSA-SHA2-192S", "Signature.SLH-DSA-SHA2-256F",
            "Signature.SLH-DSA-SHA2-256S", "Signature.SLH-DSA-SHAKE-128F",
            "Signature.SLH-DSA-SHAKE-128S", "Signature.SLH-DSA-SHAKE-192F",
            "Signature.SLH-DSA-SHAKE-192S", "Signature.SLH-DSA-SHAKE-256F",
            "Signature.SLH-DSA-SHAKE-256S", "Signature.SLHDSA"
    };
    /**
     * Every SPI package the provider registers from, mapped to the family that
     * claims it. The VALUE is documentation for the failure message; the keys
     * are what {@link #everyRegisteredServiceIsClaimedByAFamilyPrefix()}
     * checks.
     * <p>
     * Families with an agreement class use that class's own prefix constant, so
     * a prefix edited there is edited here too and the two cannot drift. The
     * remainder is named explicitly rather than left as a wildcard — an
     * unlisted package is the orphan this guard exists to find.
     */
    private static final Map<String, String> CLAIMED_PREFIXES = new LinkedHashMap<String, String>();

    static
    {
        // Families with an agreement class, keyed on that class's constant.
        CLAIMED_PREFIXES.put(CipherFamilies.DH_PREFIX, "DHAgreementTest");
        CLAIMED_PREFIXES.put(CipherFamilies.EC_PREFIX, "ECAgreementTest");
        CLAIMED_PREFIXES.put(CipherFamilies.ED_PREFIX, "EdAgreementTest");
        CLAIMED_PREFIXES.put(CipherFamilies.RSA_PREFIX, "RSAAgreementTest");
        CLAIMED_PREFIXES.put(CipherFamilies.MLKEM_PREFIX, "MLKEMAgreementTest");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.dsa.", "DSAAgreementTest");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.md.", "MDAgreementTest");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.mac.", "MacAgreementTest");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.kdf.", "KDFAgreementTest");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.blockcipher.",
                "AESAgreementTest and the per-cipher agreement classes");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.ks.", "KSServiceAgreementTest");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.mlxkem.", "MLXKEMAgreementTest");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.wrap.", "RFC3211WrapTest");

        // The named remainder: registered, but with NO family agreement class.
        // Listed so the absence is a recorded decision rather than an orphan.
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.rand.",
                "no agreement class - SecureRandom output cannot be compared across "
                        + "implementations; covered by the rand/ tests");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.cert.",
                "no agreement class - covered by X509CertificateFactoryTest");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.xec.",
                "no agreement class - covered by the xec/ tests");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.mldsa.",
                "NO AGREEMENT CLASS - a known MT-1 gap, recorded in the plan");
        CLAIMED_PREFIXES.put("org.openssl.jostle.jcajce.provider.slhdsa.",
                "NO AGREEMENT CLASS - a known MT-1 gap, recorded in the plan");
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** {@code "<Type>.<ALGORITHM>"} for every primary the provider registers. */
    private static SortedSet<String> registeredSurface()
    {
        Provider provider = Security.getProvider(JSL);
        Assertions.assertNotNull(provider, "JSL provider is not registered");

        SortedSet<String> out = new TreeSet<String>();
        for (Provider.Service s : provider.getServices())
        {
            out.add(s.getType() + "." + s.getAlgorithm());
        }
        Assertions.assertFalse(out.isEmpty(), "JSL registered no services at all");
        return out;
    }

    private static boolean openSslCanFetchKeyMgmt(String name)
    {
        return NISelector.OpenSSLNI.canFetch(OpenSSLNI.OP_KEYMGMT, name) != 0;
    }

    /**
     * The registered set equals the golden snapshot, except that a gated PQC
     * family may be absent when the loaded OpenSSL cannot serve it.
     * <p>
     * This is the only base-side check that can fail when a service is REMOVED.
     */
    @Test
    public void registeredSurfaceEqualsGolden()
    {
        SortedSet<String> registered = registeredSurface();
        SortedSet<String> golden = new TreeSet<String>(Arrays.asList(GOLDEN));

        SortedSet<String> unexpected = new TreeSet<String>(registered);
        unexpected.removeAll(golden);
        Assertions.assertTrue(unexpected.isEmpty(),
                "JSL registers services the golden snapshot does not list: " + unexpected
                        + "\nIf this is a deliberate addition, add them to GOLDEN in the same change.");

        SortedSet<String> missing = new TreeSet<String>(golden);
        missing.removeAll(registered);
        if (missing.isEmpty())
        {
            return;
        }

        // Whatever is missing must belong to a gated family AND that family
        // must genuinely be unfetchable, asked of OpenSSL.
        assertGatedAbsenceIsJustified("ML-DSA", MLDSA_GATED, "ML-DSA-65", missing);
        assertGatedAbsenceIsJustified("ML-KEM", MLKEM_GATED, "ML-KEM-768", missing);
        assertGatedAbsenceIsJustified("ML-KEM hybrids", MLXKEM_GATED, "ML-KEM-768", missing);
        assertGatedAbsenceIsJustified("SLH-DSA", SLHDSA_GATED, "SLH-DSA-SHA2-128S", missing);

        Assertions.assertTrue(missing.isEmpty(),
                "JSL no longer registers services the golden snapshot lists, and they are not "
                        + "explained by a gated family: " + missing);
    }

    /**
     * Removes {@code group} from {@code missing} when the whole group is absent
     * AND OpenSSL confirms it cannot serve the family. A PARTIALLY absent group
     * is never justified — that is a registration bug, not a gate.
     */
    private static void assertGatedAbsenceIsJustified(String family, String[] group,
                                                      String probeName, SortedSet<String> missing)
    {
        SortedSet<String> groupSet = new TreeSet<String>(Arrays.asList(group));
        SortedSet<String> absent = new TreeSet<String>(groupSet);
        absent.retainAll(missing);
        if (absent.isEmpty())
        {
            return;
        }

        Assertions.assertEquals(groupSet, absent,
                family + " is only PARTIALLY absent, which no gate produces — the gate registers "
                        + "the family or none of it. Present: "
                        + minus(groupSet, absent) + ", absent: " + absent);

        Assertions.assertFalse(openSslCanFetchKeyMgmt(probeName),
                family + " is absent from the provider, but the loaded OpenSSL CAN fetch "
                        + probeName + " — a working family was dropped from callers");

        missing.removeAll(absent);
    }

    private static SortedSet<String> minus(SortedSet<String> a, SortedSet<String> b)
    {
        SortedSet<String> out = new TreeSet<String>(a);
        out.removeAll(b);
        return out;
    }

    /**
     * Every registered service's SPI class lives under a CLAIMED prefix.
     * <p>
     * This is the check the per-family guards structurally cannot make. Each of
     * them discovers by its own prefix and asserts non-emptiness, so a package
     * renamed wholesale fails them loudly — but a service moved into a package
     * NO prefix covers simply vanishes from every family's discovered set while
     * each stays non-empty. Requiring the union of prefixes to account for all
     * 340 services is what turns that silence into a named failure.
     */
    @Test
    public void everyRegisteredServiceIsClaimedByAFamilyPrefix()
    {
        Provider provider = Security.getProvider(JSL);
        Assertions.assertNotNull(provider, "JSL provider is not registered");

        Map<String, List<String>> orphans = new TreeMap<String, List<String>>();
        int claimed = 0;

        for (Provider.Service s : provider.getServices())
        {
            String cn = s.getClassName();
            String entry = s.getType() + "." + s.getAlgorithm();
            Assertions.assertNotNull(cn, entry + ": registered with no class name");

            boolean isClaimed = false;
            for (String prefix : CLAIMED_PREFIXES.keySet())
            {
                if (cn.startsWith(prefix))
                {
                    isClaimed = true;
                    break;
                }
            }
            if (isClaimed)
            {
                claimed++;
            }
            else
            {
                String pkg = cn.substring(0, cn.lastIndexOf('.') + 1);
                List<String> list = orphans.get(pkg);
                if (list == null)
                {
                    list = new ArrayList<String>();
                    orphans.put(pkg, list);
                }
                list.add(entry);
            }
        }

        Assertions.assertTrue(orphans.isEmpty(),
                "these registered services live in packages no family prefix claims, so every "
                        + "family agreement guard is blind to them while still passing its own "
                        + "non-emptiness check:\n  " + orphans
                        + "\nAdd the package to CLAIMED_PREFIXES naming the class that covers it, "
                        + "or move the service under an existing family's package.");

        // Non-vacuity ONLY — deliberately loose. Pinning the SIZE is
        // registeredSurfaceEqualsGolden's job, and it tolerates a whole gated
        // PQC family being absent (~84 services). A tight floor here would fail
        // on exactly the older-OpenSSL build that check accepts, and the two
        // would tell contradictory stories about the same tree.
        Assertions.assertTrue(claimed >= 100,
                "only " + claimed + " services were claimed — getServices() is not returning "
                        + "what it used to, so this loop proves nothing");
    }

    /**
     * Every claimed prefix matches at least one registered service.
     * <p>
     * The reverse of the orphan check, and what stops {@link #CLAIMED_PREFIXES}
     * accumulating entries for packages that no longer exist — a stale prefix
     * would silently keep claiming nothing while looking like coverage.
     */
    @Test
    public void everyClaimedPrefixMatchesSomething()
    {
        Provider provider = Security.getProvider(JSL);
        SortedSet<String> unused = new TreeSet<String>(CLAIMED_PREFIXES.keySet());

        for (Provider.Service s : provider.getServices())
        {
            String cn = s.getClassName();
            if (cn == null)
            {
                continue;
            }
            SortedSet<String> matched = new TreeSet<String>();
            for (String prefix : unused)
            {
                if (cn.startsWith(prefix))
                {
                    matched.add(prefix);
                }
            }
            unused.removeAll(matched);
        }

        // A gated PQC family legitimately registers nothing on an older
        // OpenSSL, so its prefix matching nothing is not a stale entry.
        //
        // Probed PER FAMILY, with the same probe names
        // registeredSurfaceEqualsGolden uses. A single ML-DSA probe standing
        // for all four would false-fail here on a build that serves ML-DSA and
        // not SLH-DSA — that build is fine by the golden check, and the two
        // must tell one story. Note MLKEM_PREFIX IS the mlkem package, so it
        // is exempted once by that constant rather than twice by two spellings.
        exemptWhenUnfetchable(unused, "ML-DSA-65", "org.openssl.jostle.jcajce.provider.mldsa.");
        exemptWhenUnfetchable(unused, "ML-KEM-768", CipherFamilies.MLKEM_PREFIX);
        exemptWhenUnfetchable(unused, "ML-KEM-768", "org.openssl.jostle.jcajce.provider.mlxkem.");
        exemptWhenUnfetchable(unused, "SLH-DSA-SHA2-128S", "org.openssl.jostle.jcajce.provider.slhdsa.");

        Assertions.assertTrue(unused.isEmpty(),
                "CLAIMED_PREFIXES lists packages nothing is registered from: " + unused
                        + "\nA stale prefix claims nothing while reading as coverage.");
    }

    /**
     * Drops {@code prefix} from the stale-candidate set when OpenSSL cannot
     * fetch {@code probeName} — the family is gated off, so its prefix matching
     * nothing is expected rather than stale.
     */
    private static void exemptWhenUnfetchable(SortedSet<String> unused, String probeName,
                                              String prefix)
    {
        if (!openSslCanFetchKeyMgmt(probeName))
        {
            unused.remove(prefix);
        }
    }
}
