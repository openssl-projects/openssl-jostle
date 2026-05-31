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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class BlockCipherLengthsTest
{
    @Test
    public void testKnownBlockSizes()
    {
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.AES128));
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.AES192));
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.AES256));
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.ARIA128));
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.ARIA192));
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.ARIA256));
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.CAMELLIA128));
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.CAMELLIA192));
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.CAMELLIA256));
        Assertions.assertEquals(16, BlockCipherLengths.getBlockSize(OSSLCipher.SM4));
        Assertions.assertEquals(8, BlockCipherLengths.getBlockSize(OSSLCipher.DES_EDE3));
    }

    @Test
    public void testUnknownBlockSizesUseNativeFallback()
    {
        Assertions.assertEquals(BlockCipherLengths.UNKNOWN_BLOCK_SIZE, BlockCipherLengths.getBlockSize(null));
        Assertions.assertEquals(BlockCipherLengths.UNKNOWN_BLOCK_SIZE, BlockCipherLengths.getBlockSize(OSSLCipher.RC4));
        Assertions.assertEquals(BlockCipherLengths.UNKNOWN_BLOCK_SIZE,
                BlockCipherLengths.getBlockSize(OSSLCipher.CHACHA20_POLY1305));
    }
}
