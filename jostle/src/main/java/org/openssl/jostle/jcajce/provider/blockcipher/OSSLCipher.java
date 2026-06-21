/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipherType.*;
import static org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode.*;


public enum OSSLCipher
{
    //
    // WARNING, these are passed by ordinal value, if you change the order
    // then you MUST also ensure the underlying native interface reflects that
    // change!!
    //

    // The second constructor argument is the cipher's block size in bytes —
    // an algorithm invariant matching OpenSSL's EVP_CIPHER_get_block_size and
    // the native cipher_block_size constants in interface/util/block_cipher_ctx.c
    // (BLOCK_SIZE_AES/ARIA/CAMELLIA/SM4 = 16, BLOCK_SIZE_DES_EDE3 = 8; 8 for the
    // 64-bit-block ciphers; 1 for the stream/AEAD ciphers OpenSSL reports as 1).
    // Holding it here lets the SPI size an auto-generated IV without an
    // initialised EVP_CIPHER_CTX (see CBC_AUTO_IV_COLD_CACHE_GAP.md).
    // OSSLCipherType.STREAM is fully qualified because OSSLMode now also
    // defines a STREAM constant (the raw-stream-cipher mode) — a bare STREAM
    // would be an ambiguous static-import reference.
    RC4(OSSLCipherType.STREAM, 1),
    RC4_40(OSSLCipherType.STREAM, 1),
    IDEA(BLOCK, 8, ECB, CFB64, OFB, CBC),
    RC2(BLOCK, 8, ECB, CBC, CFB64, OFB),
    RC2_40(BLOCK, 8, CBC),
    RC2_64(BLOCK, 8, CBC),
    BlowFish(BLOCK, 8, ECB, CBC, CFB64, OFB),
    CAST5(BLOCK, 8, ECB, CBC, CFB64, OFB),
    AES128(BLOCK, 16, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM, XTS, WRAP, WRAP_PAD, OCB),
    AES192(BLOCK, 16, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM, XTS, WRAP, WRAP_PAD, OCB),
    AES256(BLOCK, 16, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM, XTS, WRAP, WRAP_PAD, OCB),
    ARIA128(BLOCK, 16, ECB, CBC, CFB1, CFB8, CFB128, CTR, OFB, GCM, CCM),
    ARIA192(BLOCK, 16, ECB, CBC, CFB1, CFB8, CFB128, CTR, OFB, GCM, CCM),
    ARIA256(BLOCK, 16, ECB, CBC, CFB1, CFB8, CFB128, CTR, OFB, GCM, CCM),
    CAMELLIA128(BLOCK, 16, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR),
    CAMELLIA192(BLOCK, 16, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR),
    CAMELLIA256(BLOCK, 16, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR),
    // Raw ChaCha20 stream cipher (RFC 8439): 256-bit key, block size 1, served
    // through the synthetic OSSLMode.STREAM. OSSLMode.STREAM is qualified to
    // disambiguate from OSSLCipherType.STREAM (the first argument).
    CHACHA20(OSSLCipherType.STREAM, 1, OSSLMode.STREAM),
    // ChaCha20-Poly1305 AEAD (RFC 8439): 256-bit key, block size 1, served
    // through the synthetic OSSLMode.POLY1305 so it rides the generic AEAD
    // streaming path (no buffering). OSSLMode.POLY1305 is qualified for
    // symmetry with CHACHA20's OSSLMode.STREAM.
    CHACHA20_POLY1305(AEAD, 1, OSSLMode.POLY1305),
    SEED(BLOCK, 16, ECB, CBC, CFB128, OFB),
    SM4(BLOCK, 16, ECB, CBC, CFB128, OFB, CTR),
    DES_EDE3(BLOCK, 8, ECB, CBC); // 3-key Triple DES (24-byte key), default-provider modes only

    Set<OSSLMode> modes;
    OSSLCipherType type;
    final int blockSize;

    OSSLCipher(OSSLCipherType type, int blockSize)
    {
        this.type = type;
        this.blockSize = blockSize;
        modes = null;
    }

    OSSLCipher(OSSLCipherType type, int blockSize, OSSLMode... m)
    {
        this.type = type;
        this.blockSize = blockSize;
        modes = Collections.unmodifiableSet(new HashSet<OSSLMode>(Arrays.asList(m)));
    }


    public Set<OSSLMode> getModes()
    {
        return modes;
    }

    /**
     * The cipher's block size in bytes — an algorithm invariant, independent
     * of key/IV/init state. Matches OpenSSL's EVP_CIPHER_get_block_size and the
     * native cipher_block_size set per cipher in block_cipher_ctx.c.
     */
    public int getBlockSize()
    {
        return blockSize;
    }
}
