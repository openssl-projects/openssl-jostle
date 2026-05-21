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

    default int getRandomSegment(MemorySegment memorySegment, int len, int strength, boolean predictionResistant)
    {

        byte[] buf = new byte[Integer.min(1024, len)];
        var ms = memorySegment.reinterpret(len).asByteBuffer();

        int rc = this.getRandomBytes(buf, buf.length, strength, predictionResistant);
        if (rc != len)
        {
            return rc; // will trigger short size in native up call handler
        }


        ms.put(buf);

        while (ms.hasRemaining())
        {
            int fetchSize = Integer.min(buf.length, ms.remaining());
            rc = this.getRandomBytes(buf, fetchSize, strength, predictionResistant);
            if (rc != fetchSize)
            {
                return rc; // will trigger short size in native up call handler
            }
            ms.put(buf, 0, rc);
        }

        return len;
    }
}
