/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.xec;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
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
 * X25519 / X448 key agreement followed by HKDF — RFC 8418's
 * {@code dhSinglePass-stdDH-hkdf-sha*-scheme} family, which CMS
 * {@code KeyAgreeRecipientInfo} uses for Montgomery recipients.
 *
 * <p>Builds on {@link XDHKeyAgreementSpi} for the raw {@code EVP_PKEY_derive}
 * shared secret, then runs HKDF natively through the NI this SPI was
 * constructed with, so the derivation happens in the same {@code OSSL_LIB_CTX}
 * as the agreement.
 *
 * <p><b>This SPI builds no ASN.1.</b> The HKDF {@code info} is the UKM passed
 * verbatim — for CMS that is the {@code ECC-CMS-SharedInfo} the CMS layer
 * pre-builds and hands over through the parameter spec, exactly as
 * {@code ECWithKDFKeyAgreementSpi} takes it. An SPI that built the structure
 * here would wrap what the caller already wrapped.
 *
 * <p><b>The salt is the caller's.</b> RFC 8418 §2.2 makes the salt the UKM;
 * BouncyCastle leaves it to the caller and never sets it in CMS. We do the
 * same, for byte-equality. A caller wanting the RFC's derivation passes the
 * same bytes as both.
 *
 * <p>The digest is fixed per scheme OID (SHA-256/384/512); the constructor
 * takes its JCA name. One SPI serves both curves — the key carries its type.
 */
public class XDHWithHKDFKeyAgreementSpi extends XDHKeyAgreementSpi
{
    private final KdfNI kdfNI;
    private final String digest;

    private byte[] ukm;
    private byte[] salt;

    public XDHWithHKDFKeyAgreementSpi(String digest)
    {
        this(NISelector.ECServiceNI, new XECKeyFactorySpi(), NISelector.KdfNI, digest);
    }

    /**
     * NI-binding constructor. The KDF NI must come from the same selector as
     * the agreement NI, or the derivation would run in the other library's lib
     * ctx.
     */
    public XDHWithHKDFKeyAgreementSpi(ECServiceNI ecServiceNI, XECKeyFactorySpi keyFactory,
            KdfNI kdfNI, String digest)
    {
        super(ecServiceNI, keyFactory);
        this.kdfNI = kdfNI;
        this.digest = digest;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // Read and validate the spec first, but commit only once the agreement
        // init has succeeded — a failed init must not leave stale keying
        // material bound to the SPI.
        byte[] newUkm = KeyAgreementKDF.extractUkm(params);
        byte[] newSalt = KeyAgreementKDF.extractSalt(params);
        super.engineInit(key, random);
        this.ukm = newUkm;
        this.salt = newSalt;
    }

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException
    {
        this.ukm = null;
        this.salt = null;
        super.engineInit(key, random);
    }

    /**
     * The KDF output at the raw secret's own length — 32 bytes for X25519, 56
     * for X448. BouncyCastle answers this call rather than refusing it, and
     * uses the same length, so refusing would break a caller that works
     * against BouncyCastle today. Before doPhase it raises instead, pinned
     * against live BouncyCastle in {@code ExceptionTypeDivergencePinTest}.
     */
    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException
    {
        byte[] zz = super.engineGenerateSecret();
        if (zz == null)
        {
            // BouncyCastle's KDF path dereferences the absent secret to size
            // the key, so it raises here where its raw path returns null.
            // The type is the parity; the message is ours.
            throw new NullPointerException(
                    "XDH HKDF generateSecret: doPhase has not been called");
        }
        try
        {
            return hkdf(zz, zz.length);
        }
        finally
        {
            Arrays.clear(zz);
        }
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException
    {
        if (sharedSecret == null)
        {
            throw new IllegalArgumentException("output buffer is null");
        }
        if (offset < 0 || offset > sharedSecret.length)
        {
            throw new IllegalArgumentException("offset out of range");
        }

        // Raises before doPhase, from engineGenerateSecret above.
        byte[] derived = engineGenerateSecret();
        try
        {
            if (sharedSecret.length - offset < derived.length)
            {
                throw new ShortBufferException(
                        "XDH HKDF generateSecret: buffer needs " + derived.length
                                + " bytes from offset " + offset
                                + ", have " + (sharedSecret.length - offset));
            }
            System.arraycopy(derived, 0, sharedSecret, offset, derived.length);
            return derived.length;
        }
        finally
        {
            Arrays.clear(derived);
        }
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

        // super: the local override runs the KDF, which would derive twice.
        byte[] zz = super.engineGenerateSecret();
        if (zz == null)
        {
            // BouncyCastle reaches its HKDF parameter check first and refuses
            // the absent secret as an illegal argument, not a null pointer.
            throw new IllegalArgumentException(
                    "XDH HKDF generateSecret: doPhase has not been called");
        }
        byte[] kek = null;
        try
        {
            kek = hkdf(zz, keyLen);
            return new SecretKeySpec(kek, keyAlg);
        }
        finally
        {
            Arrays.clear(zz);
            // SecretKeySpec copied the bytes — scrub our working copy.
            Arrays.clear(kek);
        }
    }

    /**
     * HKDF-Extract-and-Expand through the bound NI. A null salt reaches the
     * bridge as null, which is RFC 5869's HashLen zero octets; a null UKM is an
     * empty info, as BouncyCastle defaults it at init.
     */
    private byte[] hkdf(byte[] zz, int outLen)
    {
        byte[] info = ukm == null ? new byte[0] : ukm;
        byte[] out = new byte[outLen];
        kdfNI.handleErrorCodes(kdfNI.hkdf(zz, salt, info, digest, out, 0, out.length));
        return out;
    }
}
