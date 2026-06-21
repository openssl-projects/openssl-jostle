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
    public ChaCha20BlockCipherSpi()
    {
        super(OSSLCipher.CHACHA20, OSSLMode.STREAM, "ChaCha20");
    }
}
