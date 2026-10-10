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

    // OSSLCipherType.STREAM is fully qualified because OSSLMode now also
    // defines a STREAM constant (the raw-stream-cipher mode) - a bare STREAM
    // would be an ambiguous static-import reference. The block size is not
    // held here: BlockCipherNI.blockSize asks the library.
    RC4(OSSLCipherType.STREAM),
    RC4_40(OSSLCipherType.STREAM),
    IDEA(BLOCK, ECB, CFB64, OFB, CBC),
    RC2(BLOCK, ECB, CBC, CFB64, OFB),
    RC2_40(BLOCK, CBC),
    RC2_64(BLOCK, CBC),
    BlowFish(BLOCK, ECB, CBC, CFB64, OFB),
    CAST5(BLOCK, ECB, CBC, CFB64, OFB),
    AES128(BLOCK, ECB, CBC, CTS, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM, XTS, WRAP, WRAP_PAD, WRAP_INV, OCB),
    AES192(BLOCK, ECB, CBC, CTS, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM, XTS, WRAP, WRAP_PAD, WRAP_INV, OCB),
    AES256(BLOCK, ECB, CBC, CTS, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM, XTS, WRAP, WRAP_PAD, WRAP_INV, OCB),
    ARIA128(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, CTR, OFB, GCM, CCM),
    ARIA192(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, CTR, OFB, GCM, CCM),
    ARIA256(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, CTR, OFB, GCM, CCM),
    CAMELLIA128(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR),
    CAMELLIA192(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR),
    CAMELLIA256(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR),
    // Raw ChaCha20 stream cipher (RFC 8439): 256-bit key, block size 1, served
    // through the synthetic OSSLMode.STREAM. OSSLMode.STREAM is qualified to
    // disambiguate from OSSLCipherType.STREAM (the first argument).
    CHACHA20(OSSLCipherType.STREAM, OSSLMode.STREAM),
    // ChaCha20-Poly1305 AEAD (RFC 8439): 256-bit key, block size 1, served
    // through the synthetic OSSLMode.POLY1305 so it rides the generic AEAD
    // streaming path (no buffering). OSSLMode.POLY1305 is qualified for
    // symmetry with CHACHA20's OSSLMode.STREAM.
    CHACHA20_POLY1305(AEAD, OSSLMode.POLY1305),
    SEED(BLOCK, ECB, CBC, CFB128, OFB),
    SM4(BLOCK, ECB, CBC, CFB128, OFB, CTR),
    DES_EDE3(BLOCK, ECB, CBC); // 3-key Triple DES (24-byte key), default-provider modes only

    Set<OSSLMode> modes;
    OSSLCipherType type;

    OSSLCipher(OSSLCipherType type)
    {
        this.type = type;
        modes = null;
    }

    OSSLCipher(OSSLCipherType type, OSSLMode... m)
    {
        this.type = type;
        modes = Collections.unmodifiableSet(new HashSet<OSSLMode>(Arrays.asList(m)));
    }


    public Set<OSSLMode> getModes()
    {
        return modes;
    }
}
