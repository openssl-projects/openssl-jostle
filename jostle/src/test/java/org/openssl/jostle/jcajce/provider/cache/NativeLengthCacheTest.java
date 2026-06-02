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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Guard-logic tests for {@link NativeLengthCache}. The real lengths come from
 * OpenSSL at runtime and are exercised end-to-end by the per-algorithm suites
 * (block-cipher / Ed / ML-DSA / SLH-DSA / ML-KEM / MAC tests) through their
 * SPIs; these tests only pin the cache contract. Each test uses its own fresh
 * instance, so they are fully order-independent.
 */
public class NativeLengthCacheTest
{
    @Test
    public void absentKeyReturnsUnknown()
    {
        NativeLengthCache<String> cache = new NativeLengthCache<String>();
        Assertions.assertEquals(NativeLengthCache.UNKNOWN, cache.get("absent"));
    }

    @Test
    public void nullKeyIsNotCacheableAndGetsUnknown()
    {
        NativeLengthCache<String> cache = new NativeLengthCache<String>();
        Assertions.assertEquals(NativeLengthCache.UNKNOWN, cache.get(null));
        cache.cache(null, 32); // null key: ignored, must not NPE
        Assertions.assertEquals(NativeLengthCache.UNKNOWN, cache.get(null));
    }

    @Test
    public void nonPositiveLengthsAreNotCached()
    {
        NativeLengthCache<String> cache = new NativeLengthCache<String>();
        cache.cache("k", -1);               // negative (probe error): ignored
        cache.cache("k", 0);                // zero (no zero-length output): ignored
        cache.cache("k", Integer.MIN_VALUE); // ignored
        Assertions.assertEquals(NativeLengthCache.UNKNOWN, cache.get("k"));
    }

    @Test
    public void memoizesPositiveLength()
    {
        NativeLengthCache<String> cache = new NativeLengthCache<String>();
        cache.cache("k", 32);
        Assertions.assertEquals(32, cache.get("k"));
    }

    @Test
    public void putIfAbsentDoesNotOverwrite()
    {
        NativeLengthCache<String> cache = new NativeLengthCache<String>();
        cache.cache("k", 32);
        cache.cache("k", 64); // first write wins (concurrent double-probe is benign)
        Assertions.assertEquals(32, cache.get("k"));
    }

    @Test
    public void distinctKeysAreIndependent()
    {
        NativeLengthCache<String> cache = new NativeLengthCache<String>();
        cache.cache("a", 16);
        cache.cache("b", 64);
        Assertions.assertEquals(16, cache.get("a"));
        Assertions.assertEquals(64, cache.get("b"));
        Assertions.assertEquals(NativeLengthCache.UNKNOWN, cache.get("c"));
    }

    @Test
    public void worksWithEnumKeys()
    {
        // Most consumers key on an enum (cipher / key type); confirm the generic
        // parameterisation handles a non-String key the same way.
        NativeLengthCache<KeyKind> cache = new NativeLengthCache<KeyKind>();
        cache.cache(KeyKind.ALPHA, 48);
        Assertions.assertEquals(48, cache.get(KeyKind.ALPHA));
        Assertions.assertEquals(NativeLengthCache.UNKNOWN, cache.get(KeyKind.BETA));
    }

    private enum KeyKind
    {
        ALPHA, BETA
    }
}
