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

final class BlockCipherLengths
{
    static final int UNKNOWN_BLOCK_SIZE = -1;

    private BlockCipherLengths()
    {
    }

    static int getBlockSize(OSSLCipher cipher)
    {
        if (cipher == null)
        {
            return UNKNOWN_BLOCK_SIZE;
        }

        switch (cipher)
        {
            case AES128:
            case AES192:
            case AES256:
            case ARIA128:
            case ARIA192:
            case ARIA256:
            case CAMELLIA128:
            case CAMELLIA192:
            case CAMELLIA256:
            case SM4:
                return 16;
            case DES_EDE3:
                return 8;
            default:
                return UNKNOWN_BLOCK_SIZE;
        }
    }
}
