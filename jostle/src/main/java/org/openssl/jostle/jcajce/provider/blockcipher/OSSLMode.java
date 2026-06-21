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

public enum OSSLMode
{
    //
    // WARNING, these are passed by ordinal value, if you change the order
    // then you MUST also ensure the underlying native interface reflects that
    // change!!
    //
    // STREAM (ordinal 14) is the synthetic mode for raw stream ciphers
    // (ChaCha20): block size 1, no padding, no block alignment.
    // POLY1305 (ordinal 15) is the synthetic AEAD mode pairing ChaCha20 with
    // its Poly1305 authenticator (cipher CHACHA20_POLY1305) — it streams
    // through the generic AEAD path. Append-only — must match the #define
    // STREAM 14 / POLY1305 15 in interface/util/cipher_mode_pad.h.
    ECB, CBC, CFB1, CFB8, CFB64, CFB128, CTR, CCM, GCM, OFB, OCB, XTS, WRAP, WRAP_PAD, STREAM, POLY1305;
}
