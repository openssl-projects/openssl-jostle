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
package org.openssl.jostle.rand;

import org.openssl.jostle.util.Arrays;

import java.lang.foreign.MemorySegment;
import java.security.SecureRandom;

/**
 * Consistent layout for access VIA FFI.
 * This version adds an accessible method for upcalls via FFI.
 */
public interface RandSource
{

    int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant);

    SecureRandom getRandom();

    /**
     * Reported security strength in bits of the underlying randomness
     * source, or {@code 0} if the strength cannot be determined.
     *
     * <p>Used by {@link DefaultRandSource#replaceWith(RandSource, SecureRandom, int)}
     * to decide whether the existing source already satisfies a
     * strength requirement without constructing a new instance.
     */
    int getStrength();

    default int getRandomSegment(MemorySegment memorySegment, long len, int strength, int predictionResistant)
    {
        // Signature matches the C upcall typedef ffi_get_rand:
        // int32_t (*)(uint8_t *, size_t, int32_t, int32_t) — see the entropy
        // FunctionDescriptor in the *ServiceFFI classes. `len` is a size_t and
        // `predictionResistant` an int32_t; the C bridge rejects any request
        // above INT32_MAX before calling, so len fits an int here, and
        // getRandomBytes takes an int length and a boolean flag.
        int intLen = (int) len;
        boolean predResist = predictionResistant != 0;

        byte[] buf = new byte[Integer.min(1024, intLen)];
        try
        {
            var ms = memorySegment.reinterpret(intLen).asByteBuffer();

            // Compare against the amount actually requested in this fetch
            // (buf.length, capped at 1024), NOT the total len: for len > 1024
            // the first fetch legitimately returns 1024, and `rc != len` would
            // abort a valid large draw as JO_RAND_UP_SHORT_RESULT, leaving the
            // chunking loop below dead. The JNI twin issues one full-size call
            // and succeeds; this keeps the FFI path consistent.
            int rc = this.getRandomBytes(buf, buf.length, strength, predResist);
            if (rc != buf.length)
            {
                return rc; // will trigger short size in native up call handler
            }
            ms.put(buf);

            while (ms.hasRemaining())
            {
                int fetchSize = Integer.min(buf.length, ms.remaining());
                // getRandomBytes requires out.length == len (DefaultRandSource
                // rejects a mismatch), so the final short chunk needs a
                // right-sized buffer, not buf whose length is the full
                // 1024/intLen. Reuse buf when the chunk is full-width.
                byte[] target = (fetchSize == buf.length) ? buf : new byte[fetchSize];
                rc = this.getRandomBytes(target, fetchSize, strength, predResist);
                if (rc != fetchSize)
                {
                    return rc; // will trigger short size in native up call handler
                }
                ms.put(target, 0, rc);
                if (target != buf)
                {
                    Arrays.fill(target, (byte) 0);
                }
            }

            return intLen;
        }
        finally
        {
            // buf held raw DRBG output across iterations; scrub it (defence in
            // depth — the JNI twin cleanses its staging array likewise).
            Arrays.fill(buf, (byte) 0);
        }
    }
}
