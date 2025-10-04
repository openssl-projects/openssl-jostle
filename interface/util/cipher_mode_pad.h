//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef CIPHER_MODE_PAD_H
#define CIPHER_MODE_PAD_H

/*
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
 */

#define RC4 0
#define RC4_40 1
#define IDEA 2
#define RC2 3
#define RC2_40 4
#define RC2_64 5
#define BlowFish 6
#define CAST5 7
#define AES128 8
#define AES192 9
#define AES256 10
#define ARIA128 11
#define ARIA192 12
#define ARIA256 13
#define CAMELLIA128 14
#define CAMELLIA192 15
#define CAMELLIA256 16
#define CHACHA20 17
#define CHACHA20_POLY1305 18
#define SEED 19
#define SM4 20


/* Modes */
#define ECB 0
#define CBC 1
#define CFB1 2
#define CFB8 3
#define CFB64 4
#define CFB128 5
#define CTR 6
#define CCM 7
#define GCM  8
#define OFB 9
#define OCB 10
#define XTS 11
#define WRAP 12
#define WRAP_PAD 13

#define PADDED 1
#define NO_PADDING 0


/* Direction */
/* Matches Cipher classes, integer defintions  */
#define ENCRYPT_MODE 1
#define DECRYPT_MODE 2
/*  WRAP etc */


#define BLOCK_SIZE_AES 16
#define BLOCK_SIZE_ARIA 16
#define BLOCK_SIZE_CAMELLIA 16
#define BLOCK_SIZE_SM4 16

#endif //CIPHER_MODE_PAD_H
