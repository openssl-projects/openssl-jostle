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

import org.openssl.jostle.jcajce.provider.NISelector;

import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;

/**
 * Raw ChaCha20 stream cipher (RFC 8439) — no authentication.
 *
 * <p>Streams through the generic {@link BlockCipherSpi} via the synthetic
 * {@code OSSLMode.STREAM} (block size 1): {@code update()} processes
 * incrementally with no buffering. 256-bit key; the native layer rejects any
 * other key length with {@link java.security.InvalidKeyException}.
 *
 * <p>This baseline copy (compiled at {@code release = 8}) accepts a 12-byte
 * nonce via {@link javax.crypto.spec.IvParameterSpec} — the BouncyCastle
 * "ChaCha20" / "CHACHA7539" convention — and generates a random 12-byte nonce
 * when initialised without parameters for encryption. The {@code src/main/java11}
 * copy additionally accepts {@code javax.crypto.spec.ChaCha20ParameterSpec}
 * (added in Java 11, the SunJCE convention); it cannot be referenced here.
 * Both copies present an identical public ABI.
 */
public class ChaCha20BlockCipherSpi extends BlockCipherSpi
{
    private static final int NONCE_LEN = 12;

    public ChaCha20BlockCipherSpi()
    {
        this((Provider) null);
    }

    //
    // Provider-binding constructor (MT-10) - see AESBlockCipherSpi.
    //
    public ChaCha20BlockCipherSpi(Provider providerInstance)
    {
        super(NISelector.BlockCipherNI, OSSLCipher.CHACHA20, OSSLMode.STREAM, "ChaCha20",
                providerInstance);
        // Fixed cipher (no key-size variant selection), so set osslCipher here:
        // the base 3-arg constructor seeds only osslMode, leaving osslCipher for
        // subclasses (AES/ARIA/...) that resolve it from key length at init.
        osslCipher = OSSLCipher.CHACHA20;
    }

    @Override
    protected byte[] nativeIv(byte[] iv) throws InvalidAlgorithmParameterException
    {
        // The native layer reads a 16-byte IV as counter || nonce; an IvParameterSpec carries the nonce only.
        if (iv != null && iv.length != NONCE_LEN)
        {
            throw new InvalidAlgorithmParameterException("invalid iv length");
        }
        return iv;
    }

    @Override
    protected OSSLCipher blockSizeReference()
    {
        // a stream cipher: OpenSSL says 1, the JCE surface reports 0
        return OSSLCipher.CHACHA20;
    }
}
