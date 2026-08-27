/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;

import java.security.Provider;
import java.util.Arrays;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Exhaustive served-surface golden snapshot for the FIPS provider ("JSLFIPS").
 * <p>
 * This is the strongest single regression guard on the provider's served
 * surface: it enumerates every service {@code JostleFIPSProvider} registers (as
 * {@code type.algorithm} primaries, aliases excluded) and asserts the set is
 * <b>exactly</b> the checked-in golden set below. A per-family absence or
 * presence test can pass while a NEW non-approved service slips in under some
 * other family, or an approved service is silently dropped — this test fails on
 * either, naming precisely what was added or removed.
 * <p>
 * <b>The golden set is a deliberate snapshot, not a transcribed lookup table.</b>
 * It records what JSLFIPS SERVES — which is what the FIPS module implements, not
 * a subset filtered against the security policy's approved-services tables (see
 * {@code JostleFIPSProvider.setup}). It must only change on purpose. To
 * regenerate after an intentional change, list {@code provider.getServices()}
 * (sorted {@code type + "." + algorithm}) and paste it below — the diff in the
 * commit is then the reviewable record of exactly which services changed.
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSServedSurfaceSnapshotTest
{
    // Sorted "type.algorithm" of every primary service JSLFIPS registers.
    // Regenerate deliberately (see class Javadoc) — do NOT relax to a subset.
    private static final String[] GOLDEN = {
            "AlgorithmParameterGenerator.DH",
            "AlgorithmParameterGenerator.DSA",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.2",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.22",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.26",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.27",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.42",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.46",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.47",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.6",
            "AlgorithmParameters.2.16.840.1.101.3.4.1.7",
            "AlgorithmParameters.CCM",
            "AlgorithmParameters.DH",
            "AlgorithmParameters.DSA",
            "AlgorithmParameters.EC",
            "AlgorithmParameters.GCM",
            "CertificateFactory.X.509",
            "Cipher.1.2.840.113549.3.7",   // Triple-DES, capability-gated (see TDES_GATED)
            "Cipher.2.16.840.1.101.3.4.1.2",
            "Cipher.2.16.840.1.101.3.4.1.22",
            "Cipher.2.16.840.1.101.3.4.1.25",
            "Cipher.2.16.840.1.101.3.4.1.26",
            "Cipher.2.16.840.1.101.3.4.1.28",
            "Cipher.2.16.840.1.101.3.4.1.42",
            "Cipher.2.16.840.1.101.3.4.1.45",
            "Cipher.2.16.840.1.101.3.4.1.46",
            "Cipher.2.16.840.1.101.3.4.1.48",
            "Cipher.2.16.840.1.101.3.4.1.5",
            "Cipher.2.16.840.1.101.3.4.1.6",
            "Cipher.2.16.840.1.101.3.4.1.8",
            "Cipher.AES",
            "Cipher.AES/CBC/CS3PADDING",
            "Cipher.AES/CCM/NOPADDING",
            "Cipher.AES/CTS/NOPADDING",
            "Cipher.AES/XTS/NOPADDING",
            "Cipher.AES128",
            "Cipher.AES192",
            "Cipher.AES256",
            "Cipher.AESWRAP",
            "Cipher.AESWRAPINV",
            "Cipher.AESWRAPPAD",
            "Cipher.DESEDE",   // Triple-DES, capability-gated (see TDES_GATED)
            "Cipher.ML-KEM",   // PQC, capability-gated (see PQC_GATED)
            "Cipher.RSA",
            "Cipher.RSA-KTS-KEM-KWS",
            "KeyAgreement.DH",
            "KeyAgreement.DHWITHRFC2631KDF",
            "KeyAgreement.ECDH",
            "KeyAgreement.ECDHWITHSHA1KDF",
            "KeyAgreement.ECDHWITHSHA224KDF",
            "KeyAgreement.ECDHWITHSHA256KDF",
            "KeyAgreement.ECDHWITHSHA384KDF",
            "KeyAgreement.ECDHWITHSHA512KDF",
            "KeyAgreement.X25519",
            "KeyAgreement.X448",
            "KeyAgreement.XDH",
            "KeyFactory.DH",
            "KeyFactory.DSA",
            "KeyFactory.EC",
            "KeyFactory.ED",   // EdDSA, capability-gated (see ED_GATED)
            "KeyFactory.ED25519",   // EdDSA, capability-gated (see ED_GATED)
            "KeyFactory.ED448",   // EdDSA, capability-gated (see ED_GATED)
            "KeyFactory.ML-DSA-44",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.ML-DSA-65",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.ML-DSA-87",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.ML-KEM-1024",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.ML-KEM-512",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.ML-KEM-768",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.MLDSA",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.MLKEM",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.RSA",
            "KeyFactory.SECP256R1MLKEM768",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyFactory.SECP384R1MLKEM1024",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyFactory.SLH-DSA-SHA2-128F",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHA2-128S",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHA2-192F",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHA2-192S",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHA2-256F",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHA2-256S",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHAKE-128F",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHAKE-128S",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHAKE-192F",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHAKE-192S",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHAKE-256F",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLH-DSA-SHAKE-256S",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.SLHDSA",   // PQC, capability-gated (see PQC_GATED)
            "KeyFactory.X25519",
            "KeyFactory.X25519MLKEM768",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyFactory.X448",
            "KeyFactory.X448MLKEM1024",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyFactory.XDH",
            "KeyGenerator.AES",
            "KeyGenerator.AES128",
            "KeyGenerator.AES192",
            "KeyGenerator.AES256",
            "KeyGenerator.DESEDE",   // Triple-DES, capability-gated (see TDES_GATED)
            "KeyGenerator.ML-KEM-1024",   // PQC, capability-gated (see PQC_GATED)
            "KeyGenerator.ML-KEM-512",   // PQC, capability-gated (see PQC_GATED)
            "KeyGenerator.ML-KEM-768",   // PQC, capability-gated (see PQC_GATED)
            "KeyGenerator.MLKEM",   // PQC, capability-gated (see PQC_GATED)
            "KeyGenerator.SECP256R1MLKEM768",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyGenerator.SECP384R1MLKEM1024",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyGenerator.X25519MLKEM768",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyGenerator.X448MLKEM1024",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyPairGenerator.DH",
            "KeyPairGenerator.DSA",
            "KeyPairGenerator.EC",
            "KeyPairGenerator.ED",   // EdDSA, capability-gated (see ED_GATED)
            "KeyPairGenerator.ED25519",   // EdDSA, capability-gated (see ED_GATED)
            "KeyPairGenerator.ED448",   // EdDSA, capability-gated (see ED_GATED)
            "KeyPairGenerator.ML-DSA-44",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.ML-DSA-65",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.ML-DSA-87",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.ML-KEM-1024",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.ML-KEM-512",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.ML-KEM-768",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.MLDSA",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.MLKEM",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.RSA",
            "KeyPairGenerator.SECP256R1MLKEM768",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyPairGenerator.SECP384R1MLKEM1024",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyPairGenerator.SLH-DSA-SHA2-128F",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHA2-128S",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHA2-192F",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHA2-192S",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHA2-256F",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHA2-256S",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHAKE-128F",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHAKE-128S",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHAKE-192F",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHAKE-192S",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHAKE-256F",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLH-DSA-SHAKE-256S",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.SLHDSA",   // PQC, capability-gated (see PQC_GATED)
            "KeyPairGenerator.X25519",
            "KeyPairGenerator.X25519MLKEM768",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "KeyPairGenerator.X448",
            "KeyPairGenerator.X448MLKEM1024",   // hybrid KEM, capability-gated per VARIANT (see HYBRID_GATED)
            "Mac.AESCMAC",
            "Mac.AESGMAC",
            "Mac.HMACSHA1",
            "Mac.HMACSHA224",
            "Mac.HMACSHA256",
            "Mac.HMACSHA3-224",
            "Mac.HMACSHA3-256",
            "Mac.HMACSHA3-384",
            "Mac.HMACSHA3-512",
            "Mac.HMACSHA384",
            "Mac.HMACSHA512",
            "Mac.HMACSHA512/224",
            "Mac.HMACSHA512/256",
            "Mac.KMAC128",
            "Mac.KMAC256",
            "MessageDigest.SHA1",
            "MessageDigest.SHA2-224",
            "MessageDigest.SHA2-256",
            "MessageDigest.SHA2-384",
            "MessageDigest.SHA2-512",
            "MessageDigest.SHA2-512/224",
            "MessageDigest.SHA2-512/256",
            "MessageDigest.SHA3-224",
            "MessageDigest.SHA3-256",
            "MessageDigest.SHA3-384",
            "MessageDigest.SHA3-512",
            "MessageDigest.SHAKE-128",
            "MessageDigest.SHAKE-256",
            "MessageDigest.SHAKE128-256",
            "MessageDigest.SHAKE256-512",
            "SecretKeyFactory.HKDF-SHA256",
            "SecretKeyFactory.HKDF-SHA384",
            "SecretKeyFactory.HKDF-SHA512",
            "SecretKeyFactory.KBKDF-CMAC-AES128",
            "SecretKeyFactory.KBKDF-CMAC-AES192",
            "SecretKeyFactory.KBKDF-CMAC-AES256",
            "SecretKeyFactory.KBKDF-HMAC-SHA1",
            "SecretKeyFactory.KBKDF-HMAC-SHA224",
            "SecretKeyFactory.KBKDF-HMAC-SHA256",
            "SecretKeyFactory.KBKDF-HMAC-SHA384",
            "SecretKeyFactory.KBKDF-HMAC-SHA512",
            "SecretKeyFactory.PBKDF2",
            "SecretKeyFactory.PBKDF2WITHHMACSHA1",
            "SecretKeyFactory.PBKDF2WITHHMACSHA224",
            "SecretKeyFactory.PBKDF2WITHHMACSHA256",
            "SecretKeyFactory.PBKDF2WITHHMACSHA3-224",
            "SecretKeyFactory.PBKDF2WITHHMACSHA3-256",
            "SecretKeyFactory.PBKDF2WITHHMACSHA3-384",
            "SecretKeyFactory.PBKDF2WITHHMACSHA3-512",
            "SecretKeyFactory.PBKDF2WITHHMACSHA384",
            "SecretKeyFactory.PBKDF2WITHHMACSHA512",
            "SecretKeyFactory.PBKDF2WITHHMACSHA512-224",
            "SecretKeyFactory.PBKDF2WITHHMACSHA512-256",
            "SecretKeyFactory.SSHKDF-SHA1",
            "SecretKeyFactory.SSHKDF-SHA224",
            "SecretKeyFactory.SSHKDF-SHA256",
            "SecretKeyFactory.SSHKDF-SHA384",
            "SecretKeyFactory.SSHKDF-SHA512",
            "SecretKeyFactory.SSKDF-SHA1",
            "SecretKeyFactory.SSKDF-SHA224",
            "SecretKeyFactory.SSKDF-SHA256",
            "SecretKeyFactory.SSKDF-SHA384",
            "SecretKeyFactory.SSKDF-SHA512",
            "SecureRandom.CTR-DRBG",
            "SecureRandom.CTR-DRBG-AES128",
            "SecureRandom.CTR-DRBG-AES192",
            "SecureRandom.CTR-DRBG-AES256",
            "SecureRandom.DEFAULT",
            "SecureRandom.DRBG",
            "SecureRandom.HASH-DRBG",
            "SecureRandom.HASH-DRBG-SHA1",
            "SecureRandom.HASH-DRBG-SHA256",
            "SecureRandom.HASH-DRBG-SHA512",
            "SecureRandom.HMAC-DRBG",
            "SecureRandom.HMAC-DRBG-SHA1",
            "SecureRandom.HMAC-DRBG-SHA256",
            "SecureRandom.HMAC-DRBG-SHA512",
            "Signature.DET-SLH-DSA-NONE",   // PQC, capability-gated (see PQC_GATED)
            "Signature.DET-SLH-DSA-PURE",   // PQC, capability-gated (see PQC_GATED)
            "Signature.ED25519",   // EdDSA, capability-gated (see ED_GATED)
            "Signature.ED25519CTX",   // EdDSA, capability-gated per NAME (see ED_CTX_GATED)
            "Signature.ED25519PH",   // EdDSA, capability-gated (see ED_GATED)
            "Signature.ED448",   // EdDSA, capability-gated (see ED_GATED)
            "Signature.ED448PH",   // EdDSA, capability-gated (see ED_GATED)
            "Signature.EDDSA",   // EdDSA, capability-gated (see ED_GATED)
            "Signature.ML-DSA-44",   // PQC, capability-gated (see PQC_GATED)
            "Signature.ML-DSA-65",   // PQC, capability-gated (see PQC_GATED)
            "Signature.ML-DSA-87",   // PQC, capability-gated (see PQC_GATED)
            "Signature.ML-DSA-CALCULATE-MU",   // PQC, capability-gated (see PQC_GATED)
            "Signature.ML-DSA-EXTERNAL-MU",   // PQC, capability-gated (see PQC_GATED)
            "Signature.MLDSA",   // PQC, capability-gated (see PQC_GATED)
            "Signature.NONEWITHDSA",
            "Signature.NONEWITHECDSA",
            "Signature.NONEWITHRSA",
            "Signature.RSASSA-PSS",
            "Signature.SHA1WITHDSA",
            "Signature.SHA1WITHECDSA",
            "Signature.SHA1WITHRSA",
            "Signature.SHA1WITHRSAANDMGF1",
            "Signature.SHA224WITHDSA",
            "Signature.SHA224WITHECDSA",
            "Signature.SHA224WITHRSA",
            "Signature.SHA224WITHRSAANDMGF1",
            "Signature.SHA256WITHDSA",
            "Signature.SHA256WITHECDSA",
            "Signature.SHA256WITHRSA",
            "Signature.SHA256WITHRSAANDMGF1",
            "Signature.SHA3-224WITHDSA",
            "Signature.SHA3-224WITHECDSA",
            "Signature.SHA3-224WITHRSA",
            "Signature.SHA3-224WITHRSAANDMGF1",
            "Signature.SHA3-256WITHDSA",
            "Signature.SHA3-256WITHECDSA",
            "Signature.SHA3-256WITHRSA",
            "Signature.SHA3-256WITHRSAANDMGF1",
            "Signature.SHA3-384WITHDSA",
            "Signature.SHA3-384WITHECDSA",
            "Signature.SHA3-384WITHRSA",
            "Signature.SHA3-384WITHRSAANDMGF1",
            "Signature.SHA3-512WITHDSA",
            "Signature.SHA3-512WITHECDSA",
            "Signature.SHA3-512WITHRSA",
            "Signature.SHA3-512WITHRSAANDMGF1",
            "Signature.SHA384WITHDSA",
            "Signature.SHA384WITHECDSA",
            "Signature.SHA384WITHRSA",
            "Signature.SHA384WITHRSAANDMGF1",
            "Signature.SHA512WITHDSA",
            "Signature.SHA512WITHECDSA",
            "Signature.SHA512WITHRSA",
            "Signature.SHA512WITHRSAANDMGF1",
            "Signature.SLH-DSA-NONE",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-PURE",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHA2-128F",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHA2-128S",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHA2-192F",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHA2-192S",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHA2-256F",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHA2-256S",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHAKE-128F",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHAKE-128S",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHAKE-192F",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHAKE-192S",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHAKE-256F",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLH-DSA-SHAKE-256S",   // PQC, capability-gated (see PQC_GATED)
            "Signature.SLHDSA",   // PQC, capability-gated (see PQC_GATED)
    };

    /**
     * Services that may legitimately be ABSENT from {@link #GOLDEN}, because
     * the loaded module cannot perform them at all.
     * <p>
     * JSLFIPS ships one build for two modules that disagree about what they
     * implement, so a single hardcoded golden set cannot be right for both.
     * Rather than keep one golden per module — which would let a real
     * regression hide behind "wrong module, wrong list" — the golden set stays
     * the FULL surface and each capability-gated group is recorded here with
     * its measured evidence and its probe. Absence is then only acceptable
     * when the module genuinely refuses, and only for the whole group at once.
     * <p>
     * XDH (X25519 / X448), measured through the keymgmt fetch under
     * {@code fips=yes}: 3.1.2 resolves it and JSLFIPS registers; 3.5.7 answers
     * {@code inner_evp_generic_fetch: unsupported ... Non-default} and
     * ProvFIPSXDH registers nothing. See {@code FIPSCapabilities} for the
     * scoping rule and {@code FIPSXDHKDFTest} for the operation-level lock.
     */
    private static final String[] XDH_GATED = {
            "KeyAgreement.X25519",
            "KeyAgreement.X448",
            "KeyAgreement.XDH",
            "KeyFactory.X25519",
            "KeyFactory.X448",
            "KeyFactory.XDH",
            "KeyPairGenerator.X25519",
            "KeyPairGenerator.X448",
    };


    /**
     * EdDSA, the third capability-gated group — and the one that runs the
     * OPPOSITE way to {@link #XDH_GATED}: 3.1.2 refuses the whole family
     * ({@code EVP_PKEY_CTX_new_from_name("ED25519")} → "unsupported", and every
     * {@code EVP_SIGNATURE} name refused), while 3.5.7 serves it. A reader
     * looking for "newer module, fewer algorithms" will not find that pattern
     * here. Measured by {@code fips-c-review/probes/ed_gate_probe.c}; ProvFIPSED
     * gates the family on the keymgmt fetch.
     * <p>
     * {@code Signature.ED25519CTX} is deliberately NOT in this array — see
     * {@link #ED_CTX_GATED}. Putting it here would break the all-or-nothing
     * check on 3.5.7, which serves everything else in the family.
     */
    private static final String[] ED_GATED = {
            "KeyFactory.ED",
            "KeyFactory.ED25519",
            "KeyFactory.ED448",
            "KeyPairGenerator.ED",
            "KeyPairGenerator.ED25519",
            "KeyPairGenerator.ED448",
            "Signature.ED25519",
            "Signature.ED25519PH",
            "Signature.ED448",
            "Signature.ED448PH",
            "Signature.EDDSA",
    };

    /**
     * {@code Signature.ED25519CTX}, gated on its own — the only per-NAME gate
     * in the provider.
     * <p>
     * The 3.5.x module registers ED25519, ED25519PH, ED448 and ED448PH as
     * signature algorithms but NOT ED25519CTX, so the family's keymgmt fetch
     * (which answers only "is there an Ed25519 key type?") says yes while this
     * one name is unusable: driving {@code EVP_DigestSignInit_ex} with
     * {@code instance="Ed25519ctx"} returns "invalid eddsa instance for
     * attempted operation". {@code EdSignatureSpi} passes that instance
     * unconditionally for the forced type, so a registration would resolve and
     * then fail at every init. Probed with {@code OP_SIGNATURE}, not
     * {@code OP_KEYMGMT}, which is why {@link #assertGatedAbsenceIsJustified}
     * takes the operation type.
     */
    private static final String[] ED_CTX_GATED = {
            "Signature.ED25519CTX",
    };


    /**
     * PQC, the second capability-gated group. ML-KEM, ML-DSA and SLH-DSA are
     * implemented by the 3.5.x module and by no 3.1.2 module, so
     * ProvFIPS{MLKEM,MLDSA,SLHDSA} register them only when the keymgmt fetch
     * resolves.
     * <p>
     * Unlike DSA signing, this is a module-VERSION difference and not a
     * fipsinstall configuration one: real operations succeed identically under
     * both the -pedantic and the default config
     * ({@code fips-c-review/probes/pqc_op_probe.c}), so a fetch is a complete
     * answer and a registration-time gate is sound.
     */
    private static final String[] PQC_GATED = {
            "Cipher.ML-KEM",
            "KeyFactory.ML-DSA-44",
            "KeyFactory.ML-DSA-65",
            "KeyFactory.ML-DSA-87",
            "KeyFactory.ML-KEM-1024",
            "KeyFactory.ML-KEM-512",
            "KeyFactory.ML-KEM-768",
            "KeyFactory.MLDSA",
            "KeyFactory.MLKEM",
            "KeyFactory.SLH-DSA-SHA2-128F",
            "KeyFactory.SLH-DSA-SHA2-128S",
            "KeyFactory.SLH-DSA-SHA2-192F",
            "KeyFactory.SLH-DSA-SHA2-192S",
            "KeyFactory.SLH-DSA-SHA2-256F",
            "KeyFactory.SLH-DSA-SHA2-256S",
            "KeyFactory.SLH-DSA-SHAKE-128F",
            "KeyFactory.SLH-DSA-SHAKE-128S",
            "KeyFactory.SLH-DSA-SHAKE-192F",
            "KeyFactory.SLH-DSA-SHAKE-192S",
            "KeyFactory.SLH-DSA-SHAKE-256F",
            "KeyFactory.SLH-DSA-SHAKE-256S",
            "KeyFactory.SLHDSA",
            "KeyGenerator.ML-KEM-1024",
            "KeyGenerator.ML-KEM-512",
            "KeyGenerator.ML-KEM-768",
            "KeyGenerator.MLKEM",
            "KeyPairGenerator.ML-DSA-44",
            "KeyPairGenerator.ML-DSA-65",
            "KeyPairGenerator.ML-DSA-87",
            "KeyPairGenerator.ML-KEM-1024",
            "KeyPairGenerator.ML-KEM-512",
            "KeyPairGenerator.ML-KEM-768",
            "KeyPairGenerator.MLDSA",
            "KeyPairGenerator.MLKEM",
            "KeyPairGenerator.SLH-DSA-SHA2-128F",
            "KeyPairGenerator.SLH-DSA-SHA2-128S",
            "KeyPairGenerator.SLH-DSA-SHA2-192F",
            "KeyPairGenerator.SLH-DSA-SHA2-192S",
            "KeyPairGenerator.SLH-DSA-SHA2-256F",
            "KeyPairGenerator.SLH-DSA-SHA2-256S",
            "KeyPairGenerator.SLH-DSA-SHAKE-128F",
            "KeyPairGenerator.SLH-DSA-SHAKE-128S",
            "KeyPairGenerator.SLH-DSA-SHAKE-192F",
            "KeyPairGenerator.SLH-DSA-SHAKE-192S",
            "KeyPairGenerator.SLH-DSA-SHAKE-256F",
            "KeyPairGenerator.SLH-DSA-SHAKE-256S",
            "KeyPairGenerator.SLHDSA",
            "Signature.DET-SLH-DSA-NONE",
            "Signature.DET-SLH-DSA-PURE",
            "Signature.ML-DSA-44",
            "Signature.ML-DSA-65",
            "Signature.ML-DSA-87",
            "Signature.ML-DSA-CALCULATE-MU",
            "Signature.ML-DSA-EXTERNAL-MU",
            "Signature.MLDSA",
            "Signature.SLH-DSA-NONE",
            "Signature.SLH-DSA-PURE",
            "Signature.SLH-DSA-SHA2-128F",
            "Signature.SLH-DSA-SHA2-128S",
            "Signature.SLH-DSA-SHA2-192F",
            "Signature.SLH-DSA-SHA2-192S",
            "Signature.SLH-DSA-SHA2-256F",
            "Signature.SLH-DSA-SHA2-256S",
            "Signature.SLH-DSA-SHAKE-128F",
            "Signature.SLH-DSA-SHAKE-128S",
            "Signature.SLH-DSA-SHAKE-192F",
            "Signature.SLH-DSA-SHAKE-192S",
            "Signature.SLH-DSA-SHAKE-256F",
            "Signature.SLH-DSA-SHAKE-256S",
            "Signature.SLHDSA",
    };

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    /**
     * The configured JSLFIPS provider serves EXACTLY the golden set — no more
     * (a non-approved service crept in), no fewer (an approved service was
     * dropped) — and every service reports the JSLFIPS instance as its provider.
     * <p>
     * The single sanctioned exception is a capability-gated group
     * ({@link #XDH_GATED}, {@link #PQC_GATED}, {@link #ED_GATED},
     * {@link #ED_CTX_GATED}, {@link #TDES_GATED}), which may be absent only
     * when the loaded module
     * genuinely cannot serve it. That is verified against the module here, not
     * assumed: see {@link #assertGatedAbsenceIsJustified}.
     */
    @Test
    public void servedServiceSetEqualsApprovedGolden()
    {
        JostleFIPSProvider provider = FIPSTestUtil.assumeFipsProvider();

        SortedSet<String> golden = new TreeSet<>(Arrays.asList(GOLDEN));
        SortedSet<String> actual = new TreeSet<>();
        for (Provider.Service s : provider.getServices())
        {
            actual.add(s.getType() + "." + s.getAlgorithm());
            Assertions.assertSame(provider, s.getProvider(),
                    s.getType() + "." + s.getAlgorithm() + " reports a foreign provider");
        }

        SortedSet<String> added = new TreeSet<>(actual);
        added.removeAll(golden);
        SortedSet<String> removed = new TreeSet<>(golden);
        removed.removeAll(actual);

        Assertions.assertTrue(added.isEmpty(),
                "JSLFIPS served surface grew beyond the golden set."
                        + "\n  ADDED (present now, not in golden — review against the security policy): " + added
                        + "\nIf the change is intentional, regenerate the golden set (see class Javadoc).");

        SortedSet<String> unexplained = new TreeSet<>(removed);
        unexplained.removeAll(Arrays.asList(XDH_GATED));
        unexplained.removeAll(Arrays.asList(PQC_GATED));
        unexplained.removeAll(Arrays.asList(ED_GATED));
        unexplained.removeAll(Arrays.asList(ED_CTX_GATED));
        unexplained.removeAll(Arrays.asList(TDES_GATED));
        unexplained.removeAll(Arrays.asList(HYBRID_GATED));
        Assertions.assertTrue(unexplained.isEmpty(),
                "JSLFIPS dropped services that are not capability-gated."
                        + "\n  REMOVED (in golden, gone now, no recorded gate): " + unexplained
                        + "\nIf the change is intentional, regenerate the golden set (see class Javadoc).");

        assertGatedAbsenceIsJustified("XDH", XDH_GATED, OpenSSLFIPSNI.OP_KEYMGMT, "X25519", removed);
        // One probe per family: each is registered as a unit, and the
        // all-or-nothing check below is what proves the unit held.
        assertGatedAbsenceIsJustified("ML-KEM", pqcSubset("ML-KEM", "MLKEM"), OpenSSLFIPSNI.OP_KEYMGMT, "ML-KEM-768", removed);
        assertGatedAbsenceIsJustified("ML-DSA", pqcSubset("ML-DSA", "MLDSA"), OpenSSLFIPSNI.OP_KEYMGMT, "ML-DSA-65", removed);
        assertGatedAbsenceIsJustified("SLH-DSA", pqcSubset("SLH-DSA", "SLHDSA"), OpenSSLFIPSNI.OP_KEYMGMT, "SLH-DSA-SHA2-128S", removed);
        assertGatedAbsenceIsJustified("EdDSA", ED_GATED, OpenSSLFIPSNI.OP_KEYMGMT, "ED25519", removed);
        // Per-NAME, and probed as a SIGNATURE: the family's keymgmt resolves on
        // 3.5.7 while this one instance does not.
        assertGatedAbsenceIsJustified("Ed25519ctx", ED_CTX_GATED, OpenSSLFIPSNI.OP_SIGNATURE, "ED25519CTX", removed);
        // Probed as a CIPHER: the family has no keymgmt of its own.
        assertGatedAbsenceIsJustified("Triple-DES", TDES_GATED, OpenSSLFIPSNI.OP_CIPHER, "DES-EDE3-CBC", removed);
        // Per VARIANT, not per family: 3.5.8 serves three of the four hybrid
        // groups, so one probe for the set would be wrong in one direction or
        // the other. The name is spelled as OpenSSL spells it, which is what
        // the registrar gates on.
        for (org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec hybrid
                : org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec.all())
        {
            String upper = hybrid.getName().toUpperCase(java.util.Locale.ROOT);
            assertGatedAbsenceIsJustified(hybrid.getName(), hybridGated(upper),
                    OpenSSLFIPSNI.OP_KEYMGMT, hybrid.getName(), removed);
        }
    }

    /**
     * Triple-DES, the third capability-gated group, and the same straight flip
     * as {@link #ED_GATED}: {@code fips=no} on 3.1.2 (every DES-EDE3 name
     * unfetchable under the lib ctx's {@code fips=yes} default properties),
     * {@code fips=yes} on 3.5.x. ProvFIPSDESede registers on the cipher fetch.
     * <p>
     * The two alias names ({@code TripleDES} for both Cipher and KeyGenerator)
     * are deliberately absent — {@code addAlias} does not create a Service, so
     * they never appear in {@code getServices()}. {@code FIPSDESedeAgreementTest}
     * is what pins the aliases resolving.
     * <p>
     * Absence here means the module does not implement Triple-DES at all. It
     * does NOT track the {@code tdes-encrypt-disabled} fipsinstall switch: that
     * refuses only the ENCRYPT direction, at operation time, and decryption
     * keeps working — so the services stay registered on a -pedantic 3.5.x and
     * this group must not be gated on it. Measured by
     * {@code fips-c-review/probes/tdes_gate_probe.c}.
     */
    private static final String[] TDES_GATED = {
            "Cipher.1.2.840.113549.3.7",
            "Cipher.DESEDE",
            "KeyGenerator.DESEDE",
    };


    /**
     * The four TLS hybrid KEM groups, and the only gate in this file that is
     * PER VARIANT rather than per family. The groups do not arrive and depart
     * together - measured through the FIPS lib ctx
     * ({@code fips-c-review/probes/hybrid_kem_probe.c}):
     *
     * <pre>
     *                        3.1.2    3.5.8
     *   X25519MLKEM768       no       yes
     *   X448MLKEM1024        no       NO
     *   SecP256r1MLKEM768    no       yes
     *   SecP384r1MLKEM1024   no       yes
     * </pre>
     *
     * <p>So a single family-level group keyed on any one name would be wrong
     * on 3.5.8: it would either accept the absence of all four when only one
     * is missing, or demand all four on a module that serves three.
     * {@code ProvFIPSMLXKEM} gates each variant on its own keymgmt fetch, and
     * each variant is checked here against that same probe.
     *
     * <p>The all-or-nothing rule still applies WITHIN a variant - its three
     * services are registered as a unit.
     *
     * <p>The probe check is NOT sufficient on its own - see
     * {@link #hybridMembershipMatchesThePinnedTable}, which pins the expected
     * set per module version because a probe that asks the same question the
     * registrar asked cannot notice the wrong module being loaded.
     */
    private static String[] hybridGated(String variant)
    {
        return new String[]{
                "KeyFactory." + variant,
                "KeyGenerator." + variant,
                "KeyPairGenerator." + variant,
        };
    }

    /** Every hybrid entry, for the "is this absence explained" subtraction. */
    private static final String[] HYBRID_GATED = {
            "KeyFactory.SECP256R1MLKEM768",
            "KeyFactory.SECP384R1MLKEM1024",
            "KeyFactory.X25519MLKEM768",
            "KeyFactory.X448MLKEM1024",
            "KeyGenerator.SECP256R1MLKEM768",
            "KeyGenerator.SECP384R1MLKEM1024",
            "KeyGenerator.X25519MLKEM768",
            "KeyGenerator.X448MLKEM1024",
            "KeyPairGenerator.SECP256R1MLKEM768",
            "KeyPairGenerator.SECP384R1MLKEM1024",
            "KeyPairGenerator.X25519MLKEM768",
            "KeyPairGenerator.X448MLKEM1024",
    };


    /**
     * Expected hybrid membership PER MODULE VERSION, hand-written.
     *
     * <p>This exists because {@link #assertGatedAbsenceIsJustified} is not
     * enough on its own, and the gap is not hypothetical. That helper asks the
     * module the same question the registrar asked, so it catches
     * registrar-vs-module drift and nothing else: if the wrong module — or the
     * wrong <i>libcrypto</i> — is loaded, every absence is "justified" and the
     * suite is green. That failure mode occurred in this repo on 2026-08-27,
     * when a stale install path had dyld silently resolving to 3.6.2 while
     * every script claimed 3.5.7.
     *
     * <p>So: the probe answers "does the registrar agree with the module?",
     * and this table answers "is this the module we think we are testing?".
     * Both are needed; neither substitutes for the other.
     *
     * <p><b>An unrecognised module version FAILS.</b> That is deliberate, and
     * it is what makes the supported set enforceable rather than aspirational:
     * JSLFIPS supports 3.1.2 (the CMVP-validated module, cert #4985) and 3.5.8
     * (the LTS). Running against any other module — including 3.5.7, which was
     * a supported target until 2026-08-27 — stops here with an instruction to
     * decide and update the table, rather than quietly reporting a surface
     * nobody has reviewed.
     *
     * <p>Note this is a TEST pinning an expectation, not production code
     * branching on a version. {@code FIPSCapabilities.describeModule}'s "never
     * branch on this" rule still stands for the provider itself: the registrar
     * asks the module what it can do, and this table asks whether the answer
     * is the one we signed off.
     */
    private static final Map<String, SortedSet<String>> HYBRIDS_BY_MODULE_VERSION = hybridsByModuleVersion();

    private static Map<String, SortedSet<String>> hybridsByModuleVersion()
    {
        Map<String, SortedSet<String>> m = new java.util.LinkedHashMap<>();
        m.put("OpenSSL FIPS Provider 3.1.2", new TreeSet<>());
        m.put("OpenSSL FIPS Provider 3.5.8", new TreeSet<>(Arrays.asList(
                "SECP256R1MLKEM768", "SECP384R1MLKEM1024", "X25519MLKEM768")));
        return java.util.Collections.unmodifiableMap(m);
    }

    /**
     * The hybrid groups JSLFIPS serves are EXACTLY the ones pinned for this
     * module version — no more, no fewer.
     *
     * <p>Asserts membership over all three service types rather than just
     * KeyPairGenerator: a variant registered with two of its three services is
     * a real defect, and one that {@code assertGatedAbsenceIsJustified}'s
     * all-or-nothing check only catches when the variant is absent from the
     * golden set entirely.
     */
    @Test
    public void hybridMembershipMatchesThePinnedTable()
    {
        JostleFIPSProvider provider = FIPSTestUtil.assumeFipsProvider();
        String version = FIPSNISelector.OpenSSLFIPSNI.moduleVersion();

        SortedSet<String> expected = HYBRIDS_BY_MODULE_VERSION.get(version);
        Assertions.assertNotNull(expected,
                "unrecognised FIPS module \"" + version + "\".\n"
                        + "JSLFIPS supports 3.1.2 (CMVP cert #4985) and 3.5.8 (LTS). Decide whether "
                        + "this module is supported and add its expected hybrid set to "
                        + "HYBRIDS_BY_MODULE_VERSION, or test against a supported module.\n"
                        + "Known: " + HYBRIDS_BY_MODULE_VERSION.keySet());

        for (String type : new String[]{"KeyPairGenerator", "KeyGenerator", "KeyFactory"})
        {
            SortedSet<String> actual = new TreeSet<>();
            for (org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec spec
                    : org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec.all())
            {
                String upper = spec.getName().toUpperCase(java.util.Locale.ROOT);
                if (provider.getService(type, upper) != null)
                {
                    actual.add(upper);
                }
            }
            Assertions.assertEquals(expected, actual,
                    type + ": hybrid groups served by " + version + " differ from the pinned set");
        }
    }

    /** The {@link #PQC_GATED} entries belonging to one family. */
    private static String[] pqcSubset(String... markers)
    {
        SortedSet<String> out = new TreeSet<>();
        for (String s : PQC_GATED)
        {
            for (String m : markers)
            {
                if (s.contains(m))
                {
                    out.add(s);
                }
            }
        }
        Assertions.assertFalse(out.isEmpty(), "no PQC_GATED entries matched " + Arrays.toString(markers));
        return out.toArray(new String[0]);
    }

    /**
     * A capability-gated group may be absent only if the module actually
     * refuses it, and only as a whole.
     * <p>
     * Without the module check this degrades into "absence is always fine",
     * and a bug that dropped XDH on a module that serves it would pass — the
     * regression the golden set exists to catch. The all-or-nothing check
     * catches the other half: a partial registration is a real defect, not a
     * capability.
     */
    private static void assertGatedAbsenceIsJustified(String family, String[] group,
                                                      int probeOp, String probeName,
                                                      SortedSet<String> removed)
    {
        SortedSet<String> gated = new TreeSet<>(Arrays.asList(group));
        SortedSet<String> missing = new TreeSet<>(gated);
        missing.retainAll(removed);

        if (missing.isEmpty())
        {
            return;
        }

        Assertions.assertEquals(gated, missing,
                family + " is only partly registered — a capability gate is all-or-nothing."
                        + "\n  MISSING: " + missing);

        // Ask the module itself. Same probe the registrar gates on, so a green
        // result here means the registrar and the module agree.
        int fetch = FIPSNISelector.OpenSSLFIPSNI.canFetch(probeOp, probeName);
        Assertions.assertEquals(0, fetch,
                family + " is unregistered but the loaded module ("
                        + FIPSNISelector.OpenSSLFIPSNI.moduleVersion()
                        + ") resolves " + probeName
                        + " — a working algorithm was removed from callers");
    }
}
