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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;

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
 * ECDH with X9.63 KDF — the family of JCE KeyAgreement transformations
 * named {@code ECDHwithSHA<N>KDF} (also {@code ECDHwithSHA3-<N>KDF}).
 * Used by CMS / CMP {@code KeyAgreeRecipientInfo} to derive a
 * key-wrapping key from the raw ECDH shared secret plus a context-
 * binding "shared info" (a.k.a. UserKeyingMaterial, UKM).
 *
 * <p>Built by composition: {@link ECDHKeyAgreementSpi} produces the raw
 * shared secret Z, then {@link KdfNI#x963kdf} runs the ANSI X9.63 KDF
 * over Z + shared info + digest to produce the final key material.
 * The {@code generateSecret(String)} entry point is what callers use
 * — the algorithm name passed in (e.g. "AES") drives the wrapper key's
 * length via the KDF output size and is set as the resulting
 * {@code SecretKeySpec}'s algorithm.
 *
 * <p>The SPI accepts a {@link UserKeyingMaterialSpec}-compatible
 * parameter at {@code init} time to set the shared info. We define
 * our own parameter spec class to avoid a hard dependency on BC's
 * type — callers can pass {@code null} for the empty-UKM case.
 *
 * <p>Output-key sizing: JCE's {@code generateSecret(String)} doesn't
 * carry a length parameter, but X9.63 KDF needs one. We resolve the
 * length from the algorithm name via the standard table
 * (AES → 16/24/32 chosen by KEK-bits init, otherwise default to the
 * digest output length). Callers needing a non-default size should
 * use {@link #engineGenerateSecret(byte[], int)} which derives at the
 * caller-supplied buffer length.
 */
public class ECDHwithKDFKeyAgreementSpi extends ECDHKeyAgreementSpi
{
    private static final KdfNI kdfNI = NISelector.KdfNI;

    /**
     * Digest pinned by the transformation (e.g. "SHA-256" for
     * {@code ECDHwithSHA256KDF}). {@code null} for the bare
     * {@code ECDHwithKDF} transformation, in which case the caller
     * MUST supply a digest via the {@link KDFParameterSpec} at init
     * time.
     */
    private final String pinnedDigest;

    /**
     * Digest resolved at init time — either pinned or taken from the
     * spec. Set in {@code engineInit}; consumed by derive.
     */
    private String activeDigest;

    /**
     * Default output length when generateSecret(String) is called. Set
     * by {@code engineInit} when the caller passes a KDFParameterSpec
     * with an explicit length, otherwise null (auto-resolve from
     * algorithm-name + digest).
     */
    private Integer requestedOutputBytes = null;

    /** Optional shared info / UKM. Null is treated as "absent". */
    private byte[] sharedInfo = null;

    public ECDHwithKDFKeyAgreementSpi(String digestName)
    {
        this.pinnedDigest = digestName;
    }


    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException
    {
        // No spec supplied — sharedInfo stays null and the digest must
        // be pinned by the transformation. Bare "ECDHwithKDF" requires
        // an explicit KDFParameterSpec at init time.
        this.sharedInfo = null;
        this.requestedOutputBytes = null;
        this.activeDigest = pinnedDigest;
        if (activeDigest == null)
        {
            throw new InvalidKeyException(
                    "bare ECDHwithKDF requires a digest via KDFParameterSpec at init time");
        }
        super.engineInit(key, random);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        // Accept our own KDFParameterSpec; for BC compatibility we
        // also accept any spec named "UserKeyingMaterialSpec" via
        // reflection (BC's class is in a different package).
        String specDigest = null;
        if (params == null)
        {
            this.sharedInfo = null;
            this.requestedOutputBytes = null;
        }
        else if (params instanceof KDFParameterSpec)
        {
            KDFParameterSpec spec = (KDFParameterSpec) params;
            this.sharedInfo = spec.getSharedInfo();
            this.requestedOutputBytes = spec.getKeySize() > 0
                    ? Integer.valueOf((spec.getKeySize() + 7) >> 3) : null;
            specDigest = spec.getDigestAlgorithm();
        }
        else
        {
            byte[] info = extractSharedInfoReflective(params);
            if (info != null)
            {
                this.sharedInfo = info;
                this.requestedOutputBytes = null;
            }
            else
            {
                throw new InvalidAlgorithmParameterException(
                        "expected KDFParameterSpec or BC UserKeyingMaterialSpec, got "
                                + params.getClass().getName());
            }
        }

        // Resolve the active digest: prefer the pinned digest if the
        // transformation has one; fall back to the spec; reject if
        // both are null. Reject a spec-supplied digest that conflicts
        // with a pinned one — the transformation name is the contract,
        // a mismatched spec is a caller error.
        if (pinnedDigest != null)
        {
            if (specDigest != null && !pinnedDigest.equalsIgnoreCase(specDigest))
            {
                throw new InvalidAlgorithmParameterException(
                        "digest in spec (" + specDigest + ") conflicts with "
                                + "transformation-pinned digest (" + pinnedDigest + ")");
            }
            this.activeDigest = pinnedDigest;
        }
        else if (specDigest != null)
        {
            this.activeDigest = specDigest;
        }
        else
        {
            throw new InvalidAlgorithmParameterException(
                    "bare ECDHwithKDF requires a digest via KDFParameterSpec.getDigestAlgorithm()");
        }

        // ECDH itself doesn't accept parameters; bypass the parent's
        // strict check by calling the no-spec init.
        super.engineInit(key, random);
    }


    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException
    {
        if (algorithm == null || algorithm.trim().isEmpty())
        {
            throw new NoSuchAlgorithmException("algorithm name must be non-null and non-blank");
        }
        // Step 1: raw ECDH shared secret Z.
        byte[] z = super.engineGenerateSecret();

        // Step 2: figure out the requested output size.
        int outBytes;
        if (requestedOutputBytes != null)
        {
            outBytes = requestedOutputBytes;
        }
        else
        {
            outBytes = defaultKeyBytesFor(algorithm);
        }

        byte[] derived = new byte[outBytes];
        kdfNI.handleErrorCodes(kdfNI.x963kdf(z, sharedInfo, activeDigest,
                derived, 0, outBytes));
        // Cleanse Z — it's intermediate keying material.
        java.util.Arrays.fill(z, (byte) 0);
        return new SecretKeySpec(derived, algorithm);
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException
    {
        // No algorithm name available — derive at the digest's natural
        // output length when requestedOutputBytes is null.
        byte[] z = super.engineGenerateSecret();
        int outBytes = requestedOutputBytes != null
                ? requestedOutputBytes : digestOutputBytes(activeDigest);
        byte[] derived = new byte[outBytes];
        kdfNI.handleErrorCodes(kdfNI.x963kdf(z, sharedInfo, activeDigest,
                derived, 0, outBytes));
        java.util.Arrays.fill(z, (byte) 0);
        return derived;
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
        int outBytes = requestedOutputBytes != null
                ? requestedOutputBytes : digestOutputBytes(activeDigest);
        if (sharedSecret.length - offset < outBytes)
        {
            throw new ShortBufferException(
                    "ECDHwithKDF generateSecret: buffer needs " + outBytes
                            + " bytes from offset " + offset
                            + ", have " + (sharedSecret.length - offset));
        }
        byte[] z = super.engineGenerateSecret();
        kdfNI.handleErrorCodes(kdfNI.x963kdf(z, sharedInfo, activeDigest,
                sharedSecret, offset, outBytes));
        java.util.Arrays.fill(z, (byte) 0);
        return outBytes;
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * Resolve an output-key length in bytes for a JCE algorithm name.
     * Used when the caller doesn't specify a length via the parameter
     * spec. Covers AES (defaults to 16) and falls back to the digest's
     * natural output size.
     */
    private int defaultKeyBytesFor(String algorithm)
    {
        String upper = algorithm.toUpperCase();
        if (upper.startsWith("AES"))
        {
            // Default to AES-128 — callers wanting 192/256 must pass a
            // KDFParameterSpec with the desired keySize.
            return 16;
        }
        return digestOutputBytes(activeDigest);
    }

    private static int digestOutputBytes(String digestName)
    {
        if (digestName == null)
        {
            return 32;
        }
        String upper = digestName.toUpperCase().replace("-", "");
        if (upper.contains("SHA224") || upper.contains("SHA3224"))
        {
            return 28;
        }
        if (upper.contains("SHA256") || upper.contains("SHA3256"))
        {
            return 32;
        }
        if (upper.contains("SHA384") || upper.contains("SHA3384"))
        {
            return 48;
        }
        if (upper.contains("SHA512") || upper.contains("SHA3512"))
        {
            return 64;
        }
        if (upper.contains("SHA1"))
        {
            return 20;
        }
        return 32;
    }

    /**
     * Try to pull a byte[] "sharedInfo" or "ukm" out of an arbitrary
     * AlgorithmParameterSpec using reflection. Returns null if the
     * spec doesn't expose one. Used to accept BC's
     * {@code org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec}
     * without taking a compile-time dependency.
     */
    private static byte[] extractSharedInfoReflective(AlgorithmParameterSpec params)
    {
        // BC's UserKeyingMaterialSpec exposes getUserKeyingMaterial();
        // some BC variants expose getSharedInfo() too.
        String[] candidates = {"getUserKeyingMaterial", "getSharedInfo", "getUkm"};
        for (String name : candidates)
        {
            try
            {
                java.lang.reflect.Method m = params.getClass().getMethod(name);
                Object v = m.invoke(params);
                if (v instanceof byte[])
                {
                    return ((byte[]) v).clone();
                }
            }
            catch (ReflectiveOperationException ignore)
            {
                // try next candidate
            }
        }
        return null;
    }
}
