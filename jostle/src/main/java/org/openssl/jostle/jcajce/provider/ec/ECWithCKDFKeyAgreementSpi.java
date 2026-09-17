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

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.provider.kdf.KeyAgreementKDF;
import org.openssl.jostle.jcajce.util.DigestUtil;
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
 * ECDH key agreement followed by the NIST SP 800-56C one-step ("Concatenation")
 * KDF — RFC 6637 §7's {@code ECCDHwithSHA{256,384,512}CKDF}, which OpenPGP's
 * ECDH (RFC 6637 §8, RFC 9580) uses.
 *
 * <p>Builds on {@link ECDHKeyAgreementSpi} for the raw {@code EVP_PKEY_derive}
 * shared secret, then runs the native SP 800-56C one-step KDF (the same
 * {@code KdfNI#sskdf} entry point {@code SSKDFSecretKeyFactory} calls) —
 * counter (4 bytes, big-endian) then Z then {@code Param}: {@code H(counter ||
 * Z || Param)}. The counter is always {@code 1}: the largest wrap key this
 * class can produce is AES-256 (32 bytes), which never exceeds the smallest
 * permitted digest's output (SHA-256, also 32 bytes), so a second block is
 * never needed. This is NOT {@link KeyAgreementKDF#x963}, which the CMS
 * {@code ECDHWITHSHA*KDF} family uses — X9.63/KDF2 hashes {@code Z || counter
 * || SharedInfo}, Z first, a different byte order despite the superficially
 * similar shape.
 *
 * <p>RFC 6637 §7 fixes the KDF hash to SHA-256, SHA-384 or SHA-512 (§13
 * forbids SHA-1 with this KDF); the constructor takes the JCA digest name.
 * {@code Param} (RFC 6637 §8) is passed through verbatim as the UKM, exactly
 * as {@link ECWithKDFKeyAgreementSpi} takes {@code SharedInfo} — this class
 * builds no ASN.1 or PGP framing.
 */
public class ECWithCKDFKeyAgreementSpi extends ECDHKeyAgreementSpi
{
    /**
     * RFC 6637 §8 makes {@code Param} mandatory — it carries the curve OID,
     * algorithm IDs and recipient fingerprint that make the derived KEK a
     * real RFC 6637 KEK, not just a hash of Z. A KDF agreement with no UKM
     * has nothing to key that structure from, so it is refused here rather
     * than silently derived with empty info.
     */
    static final String UKM_REQUIRED_MESSAGE =
            "RFC 6637 requires the Param block as user keying material";

    private final KdfNI kdfNI;
    private final String digestAlgorithm;

    private byte[] ukm;

    public ECWithCKDFKeyAgreementSpi(String digest)
    {
        this(NISelector.ECServiceNI, new ECKeyFactorySpi(), NISelector.KdfNI, digest);
    }

    /**
     * NI-binding constructor. The KDF NI must come from the same selector as
     * the agreement NI, or the derivation would run in the other library's
     * lib ctx.
     */
    public ECWithCKDFKeyAgreementSpi(ECServiceNI ecServiceNI, ECKeyFactorySpi keyFactory,
            KdfNI kdfNI, String digest)
    {
        super(ecServiceNI, keyFactory);
        this.kdfNI = kdfNI;
        this.digestAlgorithm = DigestUtil.getCanonicalDigestName(digest);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // Extract the UKM (RFC 6637 Param) first — this also validates the
        // spec type — but only commit it once the standard ECDH init has
        // succeeded, so a failed init can't leave stale keying material
        // bound to the SPI.
        byte[] newUkm = KeyAgreementKDF.extractUkm(params);
        if (newUkm == null || newUkm.length == 0)
        {
            throw new InvalidAlgorithmParameterException(UKM_REQUIRED_MESSAGE);
        }
        super.engineInit(key, random);
        this.ukm = newUkm;
    }

    /**
     * {@code KeyAgreement.init(Key)} declares only {@link InvalidKeyException},
     * so the missing {@code Param} is refused as that type here rather than
     * the {@link InvalidAlgorithmParameterException} the spec-carrying
     * overload above uses — same requirement, the type the caller's overload
     * permits.
     */
    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException
    {
        throw new InvalidKeyException(UKM_REQUIRED_MESSAGE);
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
            kek = ckdf(zz, keyLen);
            return new SecretKeySpec(kek, keyAlg);
        }
        finally
        {
            Arrays.clear(zz);
            Arrays.clear(kek);
        }
    }

    /**
     * SP 800-56C one-step KDF through the bound NI — {@code H(counter || Z ||
     * Param)}, digest mode.
     */
    private byte[] ckdf(byte[] zz, int outLen)
    {
        byte[] out = new byte[outLen];
        kdfNI.handleErrorCodes(kdfNI.sskdf(digestAlgorithm, zz, ukm, out, 0, out.length));
        return out;
    }
}
