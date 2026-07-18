/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.rsa;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * A {@link ByteArrayOutputStream} whose contents can be zeroed. The RSA Cipher
 * SPIs accumulate the to-be-transformed input here; in {@code WRAP_MODE} that
 * input is the plaintext key material, so leaving it in the stream's backing
 * array until GC (as plain {@link ByteArrayOutputStream#reset()} does — it only
 * moves the count back to 0) is an unnecessary exposure window. {@link #wipe()}
 * zeroes the backing array before resetting the count.
 */
final class WipingByteArrayOutputStream extends ByteArrayOutputStream
{
    /**
     * Zero the backing buffer and reset the count to 0. Unlike
     * {@link #reset()}, this leaves no residual bytes behind in the heap array.
     */
    void wipe()
    {
        // buf / count are the protected fields of ByteArrayOutputStream; zero
        // the whole allocation, not just [0, count), so a previously-larger
        // write can't leave a tail behind.
        Arrays.fill(buf, (byte) 0);
        count = 0;
    }
}
