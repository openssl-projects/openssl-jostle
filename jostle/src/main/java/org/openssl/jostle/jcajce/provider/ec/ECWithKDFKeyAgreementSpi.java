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
        // Capture the SharedInfo (carried as the UKM), then run the standard
        // ECDH init.
        this.ukm = KeyAgreementKDF.extractUkm(params);
        super.engineInit(key, random);
    }

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException
    {
        this.ukm = null;
        super.engineInit(key, random);
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

        byte[] zz = engineGenerateSecret();
        try
        {
            byte[] kek = KeyAgreementKDF.x963(digest, zz, keyLen, ukm);
            return new SecretKeySpec(kek, keyAlg);
        }
        finally
        {
            Arrays.fill(zz, (byte) 0);
        }
    }
}
