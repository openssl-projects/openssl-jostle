/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.encoders;

/**
 * General interface for a translator.
 */
public interface Translator
{
    /**
     * size of the output block on encoding produced by getDecodedBlockSize()
     * bytes.
     */
    int getEncodedBlockSize();

    int encode(byte[] in, int inOff, int length, byte[] out, int outOff);

    /**
     * size of the output block on decoding produced by getEncodedBlockSize()
     * bytes.
     */
    int getDecodedBlockSize();

    int decode(byte[] in, int inOff, int length, byte[] out, int outOff);
}
