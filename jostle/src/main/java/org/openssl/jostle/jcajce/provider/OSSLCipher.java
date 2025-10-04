/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.openssl.jostle.jcajce.provider.OSSLCipherType.*;
import static org.openssl.jostle.jcajce.provider.OSSLMode.*;


enum OSSLCipher
{
    //
    // WARNING, these are passed by ordinal value, if you change the order
    // then you MUST also ensure the underlying native interface reflects that
    // change!!
    //

    RC4(STREAM),
    RC4_40(STREAM),
    IDEA(BLOCK, ECB, CFB64, OFB, CBC),
    RC2(BLOCK, ECB, CBC, CFB64, OFB),
    RC2_40(BLOCK, CBC),
    RC2_64(BLOCK, CBC),
    BlowFish(BLOCK, ECB, CBC, CFB64, OFB),
    CAST5(BLOCK, ECB, CBC, CFB64, OFB),
    AES128(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM, XTS, WRAP, WRAP_PAD, OCB),
    AES192(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM, XTS, WRAP, WRAP_PAD, OCB),
    AES256(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR, CCM, GCM, XTS, WRAP, WRAP_PAD, OCB),
    ARIA128(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, CTR, OFB, GCM, CCM),
    ARIA192(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, CTR, OFB, GCM, CCM),
    ARIA256(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, CTR, OFB, GCM, CCM),
    CAMELLIA128(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR),
    CAMELLIA192(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR),
    CAMELLIA256(BLOCK, ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR),
    CHACHA20(STREAM),
    CHACHA20_POLY1305(AEAD),
    SEED(BLOCK, ECB, CBC, CFB128, OFB),
    SM4(BLOCK, ECB, CBC, CFB128, OFB, CTR);

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
