/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.dh;

import org.openssl.jostle.jcajce.provider.kdf.KeyAgreementKDF;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Finite-field DH key agreement followed by the ANSI X9.42 / RFC 2631 KDF —
 * the {@code DHwithRFC2631KDF} that CMS {@code KeyAgreeRecipientInfo} uses for
 * {@code id-alg-ESDH} (ephemeral-static) and {@code id-alg-SSDH}
 * (static-static). Both schemes share this SPI; ephemeral-vs-static is a
 * property of which keys the caller supplies, not of the KDF.
 *
 * <p>Builds on {@link DHKeyAgreementSpi} for the raw {@code EVP_PKEY_derive}
 * shared secret, then layers the KDF (which builds the {@code OtherInfo}
 * structure and hashes {@code ZZ || DER(OtherInfo)}) in pure Java —
 * {@link KeyAgreementKDF#x942}. The wrap-algorithm name passed to
 * {@link #engineGenerateSecret(String)} selects the KEK length and is embedded
 * in {@code OtherInfo}.
 *
 * <p>RFC 2631 fixes the KDF digest at SHA-1; the constructor takes the digest
 * name so future scheme registrations can reuse the class.
 */
public class DHWithKDFKeyAgreementSpi extends DHKeyAgreementSpi
{
    private final String digest;
    private byte[] ukm;

    public DHWithKDFKeyAgreementSpi(String digest)
    {
        this.digest = digest;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // Capture the optional UKM (partyAInfo) — this also validates the spec
        // type — but only commit it once the standard DH init has succeeded, so
        // a failed init can't leave stale keying material bound to the SPI.
        byte[] newUkm = KeyAgreementKDF.extractUkm(params);
        super.engineInit(key, random);
        this.ukm = newUkm;
    }

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException
    {
        this.ukm = null;
        super.engineInit(key, random);
    }

    /**
     * BC parity: the raw pre-KDF shared secret must never escape a KDF
     * agreement — keys are only produced via
     * {@link #engineGenerateSecret(String)}.
     */
    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException
    {
        throw new UnsupportedOperationException("KDF can only be used when algorithm is known");
    }

    /**
     * BC parity: the raw pre-KDF shared secret must never escape a KDF
     * agreement — keys are only produced via
     * {@link #engineGenerateSecret(String)}.
     */
    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException
    {
        throw new UnsupportedOperationException("KDF can only be used when algorithm is known");
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException
    {
        if (algorithm == null || algorithm.trim().isEmpty())
        {
            throw new NoSuchAlgorithmException(
                    "algorithm name must be non-null and non-blank");
        }

        int keyLen = KeyAgreementKDF.wrapKeyLenBytes(algorithm);
        String keyAlg = KeyAgreementKDF.wrapKeyAlgName(algorithm);
        if (keyLen < 0 || keyAlg == null)
        {
            throw new NoSuchAlgorithmException("unknown algorithm encountered: " + algorithm);
        }

        // super: the local raw-form override deliberately throws.
        byte[] zz = super.engineGenerateSecret();
        byte[] kek = null;
        try
        {
            // Raw KDF output verbatim, including DESede — matches BouncyCastle
            // byte-for-byte (BC's KeyAgreement surface does not odd-parity-adjust
            // the 3DES KEK; DES wrapping ignores the parity bits). An earlier
            // parity adjustment here broke BC agreement and was removed.
            kek = KeyAgreementKDF.x942(digest, zz, algorithm, keyLen, ukm);
            return new SecretKeySpec(kek, keyAlg);
        }
        finally
        {
            Arrays.fill(zz, (byte) 0);
            // SecretKeySpec copies the bytes — scrub our working copy.
            if (kek != null)
            {
                Arrays.fill(kek, (byte) 0);
            }
        }
    }
}
