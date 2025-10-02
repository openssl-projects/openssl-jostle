/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Encode and decode byte arrays (typically from binary to 7-bit ASCII 
 * encodings).
 */
public interface Encoder
{
    /**
     * Return the expected output length of the encoding.
     *
     * @param inputLength the input length of the data.
     * @return the output length of an encoding.
     */
    int getEncodedLength(int inputLength);

    /**
     * Return the maximum expected output length of a decoding. If padding
     * is present the value returned will be greater than the decoded data length.
     *
     * @param inputLength the input length of the encoded data.
     * @return the upper bound of the output length of a decoding.
     */
    int getMaxDecodedLength(int inputLength);

    int encode(byte[] data, int off, int length, OutputStream out) throws IOException;
    
    int decode(byte[] data, int off, int length, OutputStream out) throws IOException;

    int decode(String data, OutputStream out) throws IOException;
}
