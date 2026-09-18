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
 * X25519 / X448 key agreement followed by the NIST SP 800-56C one-step
 * ("Concatenation") KDF — the RFC 6637 §7 construction applied to Montgomery
 * curves, under BouncyCastle's registered {@code X25519withSHA*CKDF} /
 * {@code X448withSHA*CKDF} names.
 *
 * <p>Builds on {@link XDHKeyAgreementSpi} for the raw {@code EVP_PKEY_derive}
 * shared secret, then runs the native SP 800-56C one-step KDF exactly as
 * {@link org.openssl.jostle.jcajce.provider.ec.ECWithCKDFKeyAgreementSpi}
 * does. Unlike {@link XDHWithHKDFKeyAgreementSpi} (one SPI serves both
 * curves — the key carries its type), this SPI is CURVE-BOUND: a local key
 * of the other curve is refused typed at init, BC parity; the base class
 * refuses a peer of the other curve at doPhase.
 *
 * <p>A KDF agreement yields keys only through
 * {@link #engineGenerateSecret(String)}; the raw forms refuse.
 *
 * <p>RFC 6637 §8's {@code Param} is mandatory here exactly as in
 * {@code ECWithCKDFKeyAgreementSpi}: a null or empty UKM is refused typed
 * rather than silently derived with empty info.
 */
public class XDHWithCKDFKeyAgreementSpi extends XDHKeyAgreementSpi
{
    static final String UKM_REQUIRED_MESSAGE =
            "RFC 6637 requires the Param block as user keying material";

    private final KdfNI kdfNI;
    private final String curve;
    private final String digestAlgorithm;

    private byte[] ukm;

    public XDHWithCKDFKeyAgreementSpi(String curve, String digest)
    {
        this(NISelector.ECServiceNI, new XECKeyFactorySpi(), NISelector.KdfNI, curve, digest);
    }

    /**
     * NI-binding constructor. The KDF NI must come from the same selector as
     * the agreement NI, or the derivation would run in the other library's
     * lib ctx.
     *
     * @param curve exactly "X25519" or "X448" — the curve this instance is
     *              bound to; a local private key of the other curve is
     *              refused at init.
     */
    public XDHWithCKDFKeyAgreementSpi(ECServiceNI ecServiceNI, XECKeyFactorySpi keyFactory,
            KdfNI kdfNI, String curve, String digest)
    {
        super(ecServiceNI, keyFactory);
        this.kdfNI = kdfNI;
        this.curve = curve;
        this.digestAlgorithm = DigestUtil.getCanonicalDigestName(digest);
    }

    /**
     * Imports the key (translating a foreign key exactly as the base class
     * would) and checks its curve against the one this instance is bound to.
     * Returns the imported key so the caller can hand it to
     * {@code super.engineInit} without importing it a second time — a
     * {@link JOXECPrivateKey} re-imports as a cheap cast-and-check, but the
     * saving matters for a foreign key, which would otherwise translate
     * twice.
     */
    private JOXECPrivateKey requireBoundCurve(Key key) throws InvalidKeyException
    {
        JOXECPrivateKey imported = XDHKeyImport.importPrivate(keyFactory, key,
                "XDH CKDF init: expected an XDH private key");
        if (!curve.equals(imported.getAlgorithm()))
        {
            throw new InvalidKeyException(
                    "inappropriate key: this agreement is bound to " + curve
                            + ", got a " + imported.getAlgorithm() + " key");
        }
        return imported;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // Extract the UKM (RFC 6637 Param) first — this also validates the
        // spec type — but only commit it once the standard XDH init has
        // succeeded, so a failed init can't leave stale keying material
        // bound to the SPI.
        byte[] newUkm = KeyAgreementKDF.extractUkm(params);
        if (newUkm == null || newUkm.length == 0)
        {
            throw new InvalidAlgorithmParameterException(UKM_REQUIRED_MESSAGE);
        }
        JOXECPrivateKey imported = requireBoundCurve(key);
        super.engineInit(imported, random);
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
     * A KDF agreement yields keys only through
     * {@link #engineGenerateSecret(String)}; the raw forms refuse.
     */
    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException
    {
        throw new UnsupportedOperationException("KDF can only be used when algorithm is known");
    }

    /**
     * A KDF agreement yields keys only through
     * {@link #engineGenerateSecret(String)}; the raw forms refuse.
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

        // super: the local raw-form override above is sealed.
        byte[] zz = super.engineGenerateSecret();
        if (zz == null)
        {
            // NullPointerException here matches BC's type.
            throw new NullPointerException(
                    "XDH CKDF generateSecret: doPhase has not been called");
        }
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
