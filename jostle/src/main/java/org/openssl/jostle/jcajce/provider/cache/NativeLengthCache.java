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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe memo of native-reported fixed output lengths (digest size,
 * signature length, KEM encapsulation length, MAC length, DRBG strength), keyed
 * by whatever identifies the variant.
 *
 * <p>OpenSSL is the single source of truth: a probe asks the native layer once
 * per variant and records the answer here, so nothing is transcribed.
 *
 * <p>One instance per NI implementation, held by that implementation and reached
 * through its interface. A fact is therefore bound to the interface library, and
 * so to the module, that reported it; a static cache would let one module answer
 * for another.
 *
 * <p>{@code putIfAbsent} makes a concurrent double-probe benign: both threads
 * compute the same fixed value.
 *
 * <p>Internal plumbing: {@code public} for sibling provider packages, its
 * package deliberately not exported from the module.
 *
 * @param <K> the key type, an enum or a composite identifier.
 */
public final class NativeLengthCache<K>
{
    /** Sentinel returned by {@link #get} for an absent / not-yet-probed key. */
    public static final int UNKNOWN = -1;

    private final ConcurrentHashMap<K, Integer> lengths = new ConcurrentHashMap<K, Integer>();
    private final AtomicInteger probes = new AtomicInteger();

    /**
     * Returns the memoized length for {@code key}, or {@link #UNKNOWN} when the
     * key is null or not (yet) cached. UNKNOWN tells the caller to probe native
     * and then {@link #cache} the result.
     */
    public int get(K key)
    {
        if (key == null)
        {
            return UNKNOWN;
        }
        Integer cached = lengths.get(key);
        return cached != null ? cached : UNKNOWN;
    }

    /**
     * Memoizes a native-reported length for {@code key}. A null key and
     * non-positive lengths are ignored: a probe failure returns a negative
     * error code, and no real algorithm has a zero-length output, so neither is
     * a value worth caching.
     */
    public void cache(K key, int length)
    {
        probes.incrementAndGet();
        if (key != null && length > 0)
        {
            lengths.putIfAbsent(key, length);
        }
    }

    /** Calls to {@link #cache}, one per miss that reached native. */
    public int probes()
    {
        return probes.get();
    }
}
