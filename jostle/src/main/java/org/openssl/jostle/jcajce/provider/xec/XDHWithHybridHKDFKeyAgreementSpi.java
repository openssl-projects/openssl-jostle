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
import org.openssl.jostle.jcajce.spec.HybridValueParameterSpec;
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
 * RFC 9580 §5.1.6/§5.1.7's v6 ECDH construction for X25519 / X448 — the
 * curve fixes the digest (SHA-256 for X25519, SHA-512 for X448; no other
 * pairing is valid, unlike {@link XDHWithHKDFKeyAgreementSpi}'s RFC 8418
 * CMS names). Curve-bound like {@link XDHWithCKDFKeyAgreementSpi}: a local
 * key of the other curve is refused typed at init, and the base class
 * refuses a peer of the other curve at doPhase.
 *
 * <p>The KDF input is {@code T || Z}: {@code T} (the caller-supplied
 * {@link HybridValueParameterSpec#getT()}, the ephemeral and recipient
 * public keys concatenated per the RFC — this class builds no ASN.1 and
 * does not construct {@code T} itself) is spliced onto the raw agreed
 * secret {@code Z} before HKDF runs. RFC 9580 §5.1.6/§5.1.7 fixes this
 * order — the IKM is ephemeral-public-key {@code ||} recipient-public-key
 * {@code ||} shared-secret, i.e. {@code T} always precedes {@code Z} — so
 * a spec with {@link HybridValueParameterSpec#isPrependedT()} false (the
 * {@code Z || T} order, which no standard defines) is refused typed at
 * init rather than silently derived. {@code HybridValueParameterSpec} is
 * MANDATORY here — a plain {@code UserKeyingMaterialSpec}, BC's own
 * {@code HybridValueParameterSpec}, or no spec at all are all refused
 * typed, since this class's entire purpose is the T-prepend the RFC
 * requires. The wrapped {@code baseSpec} carries the HKDF info parameter
 * (the fixed string "OpenPGP X25519" / "OpenPGP X448" per the RFC — again
 * the caller's to supply, not this class's to hardcode) as a
 * {@code UserKeyingMaterialSpec}; RFC 9580 uses no salt.
 *
 * <p>A KDF agreement yields keys only through
 * {@link #engineGenerateSecret(String)}; the raw forms refuse.
 */
public class XDHWithHybridHKDFKeyAgreementSpi extends XDHKeyAgreementSpi
{
    static final String SPEC_REQUIRED_MESSAGE =
            "RFC 9580 requires a HybridValueParameterSpec carrying T and the HKDF info";
    static final String T_MUST_PRECEDE_Z_MESSAGE =
            "RFC 9580 places T before the shared secret";

    private final KdfNI kdfNI;
    private final String curve;
    private final String digest;

    private byte[] t;
    private byte[] info;

    public XDHWithHybridHKDFKeyAgreementSpi(String curve, String digest)
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
    public XDHWithHybridHKDFKeyAgreementSpi(ECServiceNI ecServiceNI, XECKeyFactorySpi keyFactory,
            KdfNI kdfNI, String curve, String digest)
    {
        super(ecServiceNI, keyFactory);
        this.kdfNI = kdfNI;
        this.curve = curve;
        this.digest = digest;
    }

    /**
     * Imports the key (translating a foreign key exactly as the base class
     * would) and checks its curve against the one this instance is bound to.
     * Returns the imported key so the caller can hand it to
     * {@code super.engineInit} without importing it a second time.
     */
    private JOXECPrivateKey requireBoundCurve(Key key) throws InvalidKeyException
    {
        JOXECPrivateKey imported = XDHKeyImport.importPrivate(keyFactory, key,
                "XDH hybrid HKDF init: expected an XDH private key");
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
        if (!(params instanceof HybridValueParameterSpec))
        {
            throw new InvalidAlgorithmParameterException(SPEC_REQUIRED_MESSAGE);
        }
        HybridValueParameterSpec hybridSpec = (HybridValueParameterSpec) params;
        byte[] newT = hybridSpec.getT();
        if (newT == null || newT.length == 0)
        {
            throw new InvalidAlgorithmParameterException(SPEC_REQUIRED_MESSAGE);
        }
        if (!hybridSpec.isPrependedT())
        {
            throw new InvalidAlgorithmParameterException(T_MUST_PRECEDE_Z_MESSAGE);
        }
        byte[] newInfo = KeyAgreementKDF.extractUkm(hybridSpec.getBaseParameterSpec());
        if (newInfo == null || newInfo.length == 0)
        {
            throw new InvalidAlgorithmParameterException(SPEC_REQUIRED_MESSAGE);
        }

        JOXECPrivateKey imported = requireBoundCurve(key);
        super.engineInit(imported, random);
        this.t = newT;
        this.info = newInfo;
    }

    /**
     * {@code KeyAgreement.init(Key)} declares only {@link InvalidKeyException},
     * so the missing spec is refused as that type here rather than the
     * {@link InvalidAlgorithmParameterException} the spec-carrying overload
     * above uses — same requirement, the type the caller's overload permits.
     */
    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException
    {
        throw new InvalidKeyException(SPEC_REQUIRED_MESSAGE);
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
            throw new NullPointerException(
                    "XDH hybrid HKDF generateSecret: doPhase has not been called");
        }
        byte[] hybrid = concat(t, zz);
        byte[] kek = null;
        try
        {
            kek = hkdf(hybrid, keyLen);
            return new SecretKeySpec(kek, keyAlg);
        }
        finally
        {
            Arrays.clear(zz);
            Arrays.clear(hybrid);
            Arrays.clear(kek);
        }
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * HKDF-Extract-and-Expand through the bound NI, {@code T || Z} as the
     * IKM, {@code info} as the RFC's fixed context string, no salt.
     */
    private byte[] hkdf(byte[] ikm, int outLen)
    {
        byte[] out = new byte[outLen];
        kdfNI.handleErrorCodes(kdfNI.hkdf(ikm, null, info, digest, out, 0, out.length));
        return out;
    }
}
