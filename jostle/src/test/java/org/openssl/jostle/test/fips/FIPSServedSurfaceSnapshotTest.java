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
            "Cipher.AES/CCM/NOPADDING",
            "Cipher.AES128",
            "Cipher.AES192",
            "Cipher.AES256",
            // Key wrap by name (RFC 3394 / RFC 5649 — approved). Same
            // implementation the wrap OIDs above already serve; naming gap only.
            // Upper-cased because the provider upper-cases on registration;
            // aliases AESKW / AESKWP are excluded here, as all aliases are.
            "Cipher.AESWRAP",
            "Cipher.AESWRAPPAD",
            "Cipher.RSA",
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
            "KeyFactory.RSA",
            "KeyFactory.X25519",
            "KeyFactory.X448",
            "KeyFactory.XDH",
            "KeyGenerator.AES",
            "KeyGenerator.AES128",
            "KeyGenerator.AES192",
            "KeyGenerator.AES256",
            "KeyPairGenerator.DH",
            "KeyPairGenerator.DSA",
            "KeyPairGenerator.EC",
            "KeyPairGenerator.RSA",
            "KeyPairGenerator.X25519",
            "KeyPairGenerator.X448",
            "Mac.AESCMAC",
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
     * ({@link #XDH_GATED}), which may be absent only when the loaded module
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
        Assertions.assertTrue(unexplained.isEmpty(),
                "JSLFIPS dropped services that are not capability-gated."
                        + "\n  REMOVED (in golden, gone now, no recorded gate): " + unexplained
                        + "\nIf the change is intentional, regenerate the golden set (see class Javadoc).");

        assertGatedAbsenceIsJustified(removed);
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
    private static void assertGatedAbsenceIsJustified(SortedSet<String> removed)
    {
        SortedSet<String> gated = new TreeSet<>(Arrays.asList(XDH_GATED));
        SortedSet<String> missing = new TreeSet<>(gated);
        missing.retainAll(removed);

        if (missing.isEmpty())
        {
            return;
        }

        Assertions.assertEquals(gated, missing,
                "XDH is only partly registered — a capability gate is all-or-nothing."
                        + "\n  MISSING: " + missing);

        // Ask the module itself. Same probe ProvFIPSXDH gates on, so a green
        // result here means the registrar and the module agree.
        int fetch = FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_KEYMGMT, "X25519");
        Assertions.assertEquals(0, fetch,
                "XDH is unregistered but the loaded module ("
                        + FIPSNISelector.OpenSSLFIPSNI.moduleVersion()
                        + ") resolves X25519 — a working algorithm was removed from callers");
    }
}
