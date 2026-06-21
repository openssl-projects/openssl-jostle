/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;

import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439).
 *
 * <p>Streams through the generic {@link BlockCipherSpi} AEAD path via the
 * synthetic {@code OSSLMode.POLY1305} — {@code update()} processes
 * incrementally with no buffering, reusing the same GCM tag-buffer, AAD, and
 * encrypt-nonce-reuse machinery. 256-bit key, 96-bit nonce, 128-bit tag.
 *
 * <p>Accepts {@link GCMParameterSpec}, BouncyCastle's {@code AEADParameterSpec}
 * (via {@link AEADParameterSpecAccessor}), and plain {@code IvParameterSpec}
 * (12-byte nonce, tag defaulted to 128 bits). RFC 8439 fixes the tag at 128
 * bits, so this SPI rejects any other tag length at the JCE boundary with
 * {@link InvalidAlgorithmParameterException} — the native layer would otherwise
 * surface a non-JCE {@link IllegalArgumentException} for it.
 */
public class ChaCha20Poly1305CipherSpi extends BlockCipherSpi
{
    public ChaCha20Poly1305CipherSpi()
    {
        super(OSSLCipher.CHACHA20_POLY1305, OSSLMode.POLY1305, "ChaCha20");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        requireTag128(params);
        super.engineInit(opmode, key, params, random);
    }

    /**
     * Enforce RFC 8439's fixed 128-bit tag at the JCE boundary for any spec that
     * carries an explicit tag length — {@link GCMParameterSpec} or BouncyCastle's
     * {@code AEADParameterSpec}. {@code IvParameterSpec} / {@code null} carry no
     * tag length and default to 128 bits in the base SPI, so they need no check.
     */
    private static void requireTag128(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        int tagBits = -1;
        if (params instanceof GCMParameterSpec)
        {
            tagBits = ((GCMParameterSpec) params).getTLen();
        }
        else if (params != null && AEADParameterSpecAccessor.matches(params))
        {
            tagBits = AEADParameterSpecAccessor.extract(params).getMacSizeInBits();
        }
        if (tagBits != -1 && tagBits != 128)
        {
            throw new InvalidAlgorithmParameterException("ChaCha20-Poly1305 tag length must be 128 bits");
        }
    }
}
