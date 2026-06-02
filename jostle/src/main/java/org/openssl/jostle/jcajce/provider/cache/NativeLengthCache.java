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

/**
 * Thread-safe memo of native-reported fixed output lengths — cipher block size,
 * signature length, KEM encapsulation length, MAC length — keyed by whatever
 * uniquely identifies the algorithm variant for a given consumer.
 *
 * <p>OpenSSL is the single source of truth. A consumer probes the native layer
 * once per variant, records the result via {@link #cache}, and thereafter reads
 * it back via {@link #get} to skip the probe. Nothing is hard-coded — the cached
 * value is whatever OpenSSL reported, so there is no transcribed table that can
 * drift from native truth.
 *
 * <p>Each consumer (e.g. a single SPI class) owns one {@code static final}
 * instance, so key spaces never collide across algorithm families. The cache
 * lives here, in one place, rather than inside the SPIs: the SPIs have
 * per-Java-version copies in the multi-release jar (Java 8 {@code synchronized}
 * vs. Java 9+ {@code reachabilityFence}), and duplicating the guard logic across
 * those copies would invite drift. Holding the {@code static final} reference is
 * the only thing each copy repeats; the guard logic is single-copy here.
 *
 * <p>{@code putIfAbsent} makes a concurrent double-probe benign: both threads
 * compute the same fixed value, so whichever wins stores the same answer.
 *
 * <p>Internal plumbing. This type is {@code public} only so sibling
 * {@code org.openssl.jostle.jcajce.provider.*} packages in this module can share
 * it; its package is deliberately NOT exported from the module, preserving the
 * encapsulation the per-family package-private helpers used to have.
 *
 * @param <K> the consumer's key type — an enum (cipher / key-type) or a
 *            composite identifier.
 */
public final class NativeLengthCache<K>
{
    /** Sentinel returned by {@link #get} for an absent / not-yet-probed key. */
    public static final int UNKNOWN = -1;

    private final ConcurrentHashMap<K, Integer> lengths = new ConcurrentHashMap<K, Integer>();

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
        if (key != null && length > 0)
        {
            lengths.putIfAbsent(key, length);
        }
    }
}
