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
    // STREAM 14 / POLY1305 15 in interface/nonfips/util/cipher_mode_pad.h.
    // CTS (ordinal 16) is CBC with ciphertext stealing, mapping to OpenSSL's
    // AES-<n>-CBC-CTS with cts_mode pinned to CS3 — the variant BouncyCastle's
    // AES/CTS/NoPadding implements (measured, not inherited: OpenSSL's own
    // default is CS1). Append-only — must match the #define CTS 16 in
    // interface/nonfips/util/cipher_mode_pad.h.
    // WRAP_INV (ordinal 17) is RFC 3394 key wrap on the INVERSE cipher
    // function (SP 800-38F 5.1) — OpenSSL's AES-<n>-WRAP-INV, measured
    // byte-identical to BouncyCastle's AESWrapEngine(true). Append-only —
    // must match the #define WRAP_INV 17 in
    // interface/nonfips/util/cipher_mode_pad.h.
    ECB, CBC, CFB1, CFB8, CFB64, CFB128, CTR, CCM, GCM, OFB, OCB, XTS, WRAP, WRAP_PAD, STREAM, POLY1305, CTS, WRAP_INV;
}
