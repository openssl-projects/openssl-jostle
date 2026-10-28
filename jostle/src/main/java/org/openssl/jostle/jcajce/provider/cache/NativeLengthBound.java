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
        return bounded(memo, type + "/" + part, type, part, reported);
    }

    /** As above, for a memo keyed by {@code key}; {@code type} and {@code part} only name the length in a refusal. */
    public static <K> int bounded(NativeLengthCache<K> memo, K key, String type, String part, long reported)
    {
        if (memo.get(key) == NativeLengthCache.UNKNOWN && reported > 0 && reported <= Integer.MAX_VALUE)
        {
            memo.cache(key, (int) reported);
        }
        int length = memo.get(key);
        if (length == NativeLengthCache.UNKNOWN)
        {
            throw new IllegalStateException("the library reported a " + part + " length of " + reported + " for "
                    + type + ", which is not a length");
        }
        if (reported != length)
        {
            throw new IllegalStateException(
                    "the library reported a " + part + " length of " + reported + " for " + type + ", not " + length);
        }
        return length;
    }
}
