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

public interface RandSource
{
    int getEntropy(byte[] out, int len, int strength, boolean predictionResistant);

    SecureRandom getRandom();

    default int getEntropySegment(MemorySegment memorySegment, int len, int strength, boolean predictionResistant)
    {

        byte[] buf = new byte[Integer.min(1024, len)];
        var ms = memorySegment.reinterpret(len).asByteBuffer();

        int rc = this.getEntropy(buf, buf.length, strength, predictionResistant);
        if (rc < 0)
        {
            return rc;
        }
        ms.put(buf);

        while (ms.hasRemaining())
        {
            rc = this.getEntropy(buf, Integer.min(buf.length, ms.remaining()), strength, predictionResistant);
            if (rc < 0)
            {
                return rc;
            }
            ms.put(buf, 0, rc);
        }

        return len;
    }
}
