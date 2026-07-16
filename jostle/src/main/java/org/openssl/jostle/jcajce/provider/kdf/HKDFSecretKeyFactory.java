/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */
package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.jcajce.util.DigestUtil;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * {@code SecretKeyFactory} surface for HKDF (RFC 5869), backed by the native
 * {@code EVP_KDF "HKDF"} (extract-and-expand) via {@link KdfNI#hkdf}. The digest
 * is fixed per registered algorithm ("HKDF-SHA256" / "HKDF-SHA384" / "HKDF-SHA512");
 * the {@link HKDFParameterSpec} supplies the IKM, optional salt, optional info and
 * the desired output length (in bytes).
 */
public class HKDFSecretKeyFactory extends SecretKeyFactorySpi
{
    // Digest output sizes, queried once per digest name and memoized so we don't
    // build (and immediately discard) a MessageDigest on every factory
    // construction just to read a fixed length. Query-and-cache, never transcribe
    // (see java-spi.md "OpenSSL is the single source of truth for fixed values").
    private static final NativeLengthCache<String> DIGEST_LENGTHS = new NativeLengthCache<String>();

    private final String digestAlgorithm;
    private final int maxOutputLength;

    // Instance field, not a NISelector static (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final KdfNI kdfNI;

    public HKDFSecretKeyFactory(String digestAlgorithm)
    {
        this(NISelector.KdfNI, digestAlgorithm);
    }

    public HKDFSecretKeyFactory(KdfNI kdfNI, String digestAlgorithm)
    {
        this.kdfNI = kdfNI;
        // RFC 5869: HKDF-Expand caps the output at 255 * HashLen. Enforced at
        // the JCE boundary so an over-long (or DoS-scale) request fails fast
        // with a typed exception instead of an allocation + opaque native error.
        // HashLen is queried from a MessageDigest, not transcribed as a size
        // table (see java-spi.md "OpenSSL is the single source of truth …").
        // The caller-supplied JCE name (e.g. "SHA-256") is used before it is
        // canonicalised for the native call, so it resolves via any provider.
        this.maxOutputLength = 255 * hashLengthBytes(digestAlgorithm);
        this.digestAlgorithm = DigestUtil.getCanonicalDigestName(digestAlgorithm);
    }

    private static int hashLengthBytes(String jceDigestName)
    {
        int len = DIGEST_LENGTHS.get(jceDigestName);
        if (len != NativeLengthCache.UNKNOWN)
        {
            return len;
        }
        try
        {
            len = MessageDigest.getInstance(jceDigestName).getDigestLength();
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalArgumentException("unsupported HKDF digest: " + jceDigestName, e);
        }
        if (len <= 0)
        {
            // A provider that reports 0 (unknown length) can't bound the output;
            // treat as unsupported rather than compute a bad limit.
            throw new IllegalArgumentException("digest reports no fixed length: " + jceDigestName);
        }
        DIGEST_LENGTHS.cache(jceDigestName, len);
        return len;
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        byte[] ikm;
        byte[] salt;
        byte[] info;
        int outputLength;

        if (keySpec instanceof HKDFParameterSpec)
        {
            HKDFParameterSpec spec = (HKDFParameterSpec) keySpec;
            ikm = spec.getIKM();
            salt = spec.getSalt();
            info = spec.getInfo();
            outputLength = spec.getOutputLength();
        }
        else if (keySpec != null)
        {
            // Accept any structurally-compatible HKDFParameterSpec (notably BouncyCastle's
            // org.bouncycastle.jcajce.spec.HKDFParameterSpec) without a compile-time dependency on
            // it, so high-level CMS/OpenPGP builders that construct that type can derive through this
            // native HKDF. Same accessor contract (getIKM/getSalt/getInfo/getOutputLength), same units
            // (output length in bytes). A spec missing any accessor surfaces as InvalidKeySpecException.
            Class<?> cls = keySpec.getClass();
            try
            {
                ikm = (byte[]) cls.getMethod("getIKM").invoke(keySpec);
                salt = (byte[]) cls.getMethod("getSalt").invoke(keySpec);
                info = (byte[]) cls.getMethod("getInfo").invoke(keySpec);
                outputLength = (Integer) cls.getMethod("getOutputLength").invoke(keySpec);
            }
            catch (ReflectiveOperationException | ClassCastException | NullPointerException e)
            {
                throw new InvalidKeySpecException("unsupported KeySpec " + cls.getName(), e);
            }
        }
        else
        {
            throw new InvalidKeySpecException("unsupported KeySpec null");
        }

        if (ikm == null)
        {
            // Reject here with the checked KeyFactory exception type rather than
            // letting the NI layer's unchecked IllegalArgumentException escape
            // SecretKeyFactory.generateSecret.
            throw new InvalidKeySpecException("ikm is null");
        }

        if (outputLength <= 0)
        {
            throw new InvalidKeySpecException("output length must be positive");
        }

        if (outputLength > maxOutputLength)
        {
            throw new InvalidKeySpecException("output length exceeds RFC 5869 limit of 255 * HashLen ("
                    + maxOutputLength + " bytes for " + digestAlgorithm + ")");
        }

        byte[] rawKey = new byte[outputLength];

        try
        {
            kdfNI.handleErrorCodes(kdfNI.hkdf(
                    ikm,
                    salt,
                    info,
                    digestAlgorithm,
                    rawKey, 0, rawKey.length));

            return new SecretKeySpec(rawKey, "HKDF");
        }
        finally
        {
            // The IKM and the derived bytes (SecretKeySpec took its own copy)
            // are secret material — scrub both, on failure paths too. Clearing
            // ikm is safe because getIKM() returns a fresh copy for both the
            // typed HKDFParameterSpec and BouncyCastle's spec (the only two the
            // reflective path accepts); a hypothetical spec that handed back its
            // live internal array would be damaged, an edge case we accept for
            // the same reason as the SecretKeySpec.getEncoded() zeroize rule
            // (see java-spi.md "Zeroize the byte[] from key.getEncoded()").
            Arrays.clear(ikm);
            Arrays.clear(rawKey);
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException
    {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException
    {
        throw new InvalidKeyException("not implemented");
    }
}
