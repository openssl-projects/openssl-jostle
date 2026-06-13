/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.ec;

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
 * ECDH key agreement followed by the ANSI X9.63 KDF (= ISO-18033 KDF2) — the
 * {@code dhSinglePass-stdDH-sha*kdf-scheme} family CMS
 * {@code KeyAgreeRecipientInfo} uses for EC recipients.
 *
 * <p>Builds on {@link ECDHKeyAgreementSpi} for the raw {@code EVP_PKEY_derive}
 * shared secret, then runs {@link KeyAgreementKDF#x963} which hashes
 * {@code ZZ || counter || sharedInfo}. Unlike the X9.42 DH KDF, the SPI does
 * <em>not</em> build any ASN.1 here: the {@code SharedInfo} is the UKM passed
 * verbatim — for CMS that is the {@code ECC-CMS-SharedInfo} the CMS layer
 * pre-builds and hands over via the {@code UserKeyingMaterialSpec}.
 *
 * <p>The digest is fixed per scheme OID (SHA-1/224/256/384/512); the
 * constructor takes its JCA name. Cofactor ({@code ECCDH}) and MQV schemes are
 * out of scope — they need native cofactor / MQV agreement Jostle does not yet
 * expose.
 */
public class ECWithKDFKeyAgreementSpi extends ECDHKeyAgreementSpi
{
    private final String digest;
    private byte[] ukm;

    public ECWithKDFKeyAgreementSpi(String digest)
    {
        this.digest = digest;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // Extract the SharedInfo (carried as the UKM) first — this also
        // validates the spec type — but only commit it once the standard
        // ECDH init has succeeded, so a failed init can't leave stale
        // keying material bound to the SPI.
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
            // Return the raw KDF output verbatim — including for DESede. This
            // matches BouncyCastle byte-for-byte: BC's KeyAgreement surface does
            // NOT odd-parity-adjust the derived 3DES KEK (DES wrapping ignores
            // the parity bits anyway). An earlier parity adjustment here broke
            // byte-exact agreement with BC and was removed.
            kek = KeyAgreementKDF.x963(digest, zz, keyLen, ukm);
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
