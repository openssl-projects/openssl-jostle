/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.cache;

/**
 * Bounds a key encoding length a library reported, before anything is allocated from it: the first positive answer
 * for a type and part is memoised in the caller's own cache (so the memo belongs to one library), and a later answer
 * that disagrees is IllegalStateException. The first answer itself is bounded only by the int range.
 */
public final class NativeLengthBound
{
    private NativeLengthBound()
    {
    }

    public static int bounded(NativeLengthCache<String> memo, String type, String part, long reported)
    {
        String key = type + "/" + part;
        if (memo.get(key) == NativeLengthCache.UNKNOWN && reported > 0 && reported <= Integer.MAX_VALUE)
        {
            memo.cache(key, (int) reported);
        }
        int length = memo.get(key);
        if (reported != length)
        {
            throw new IllegalStateException(
                    "the library reported a " + part + " length of " + reported + " for " + type + ", not " + length);
        }
        return length;
    }
}
