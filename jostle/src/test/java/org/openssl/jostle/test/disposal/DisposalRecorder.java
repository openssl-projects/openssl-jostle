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

package org.openssl.jostle.test.disposal;

import org.openssl.jostle.disposal.DisposalListener;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Records disposal events as per-VALUE COUNTS: registrations, disposals and
 * failures for each handle value. A handle is missing when it was registered
 * more often than it was disposed or failed.
 *
 * <p>Counts rather than sets, because a freed address is reused: registered(H),
 * disposed(H), then a second handle at H registered and leaked would leave H in
 * a disposed set and hide the leak. Counts are order-independent.
 *
 * <p>{@code registered} arrives on the registering thread; the rest on the
 * daemon thread, the cleanup executor or the shutdown hook thread. Every
 * collection is concurrent.
 */
public final class DisposalRecorder implements DisposalListener
{
    private final Map<Long, AtomicInteger> registered = new ConcurrentHashMap<Long, AtomicInteger>();
    private final Map<Long, AtomicInteger> disposed = new ConcurrentHashMap<Long, AtomicInteger>();
    private final Map<Long, AtomicInteger> failed = new ConcurrentHashMap<Long, AtomicInteger>();
    private final Map<Long, String> labels = new ConcurrentHashMap<Long, String>();
    private final Map<Long, Throwable> causes = new ConcurrentHashMap<Long, Throwable>();

    public void registered(long ref, String label)
    {
        count(registered, ref);
        labels.put(ref, label == null ? "<unlabelled>" : label);
    }

    public void disposing(long ref)
    {
    }

    public void disposed(long ref)
    {
        count(disposed, ref);
    }

    public void failed(long ref, Throwable t)
    {
        count(failed, ref);
        causes.put(ref, t);
    }

    private static void count(Map<Long, AtomicInteger> map, long ref)
    {
        AtomicInteger c = map.get(ref);
        if (c == null)
        {
            AtomicInteger fresh = new AtomicInteger();
            c = map.putIfAbsent(ref, fresh);
            if (c == null)
            {
                c = fresh;
            }
        }
        c.incrementAndGet();
    }

    private static int at(Map<Long, AtomicInteger> map, long ref)
    {
        AtomicInteger c = map.get(ref);
        return c == null ? 0 : c.get();
    }

    private static int total(Map<Long, AtomicInteger> map)
    {
        int n = 0;
        for (AtomicInteger c : map.values())
        {
            n += c.get();
        }
        return n;
    }

    /** Every distinct handle value seen registered, for a control that must name the exact one. */
    public Set<Long> registeredHandles()
    {
        return new LinkedHashSet<Long>(registered.keySet());
    }

    /** Registrations, counting a reused value each time. */
    public int registeredCount()
    {
        return total(registered);
    }

    public int failedCount()
    {
        return total(failed);
    }

    /** Values registered more than once in the window, i.e. addresses the allocator handed back. */
    public int reusedCount()
    {
        int n = 0;
        for (AtomicInteger c : registered.values())
        {
            if (c.get() > 1)
            {
                n++;
            }
        }
        return n;
    }

    /** Handle values registered more often than disposed or failed. */
    public Set<Long> missing()
    {
        Set<Long> out = new LinkedHashSet<Long>();
        for (Map.Entry<Long, AtomicInteger> e : registered.entrySet())
        {
            long ref = e.getKey();
            if (e.getValue().get() > at(disposed, ref) + at(failed, ref))
            {
                out.add(ref);
            }
        }
        return out;
    }

    public boolean isDrained()
    {
        return missing().isEmpty();
    }

    /** Names the handles, because a bare hex value says nothing about which family leaked. */
    public String describe(Set<Long> refs)
    {
        List<String> out = new ArrayList<String>();
        for (Long ref : refs)
        {
            String label = labels.get(ref);
            out.add("0x" + Long.toHexString(ref) + " " + (label == null ? "<unlabelled>" : label)
                    + " registered=" + at(registered, ref) + " disposed=" + at(disposed, ref)
                    + " failed=" + at(failed, ref));
        }
        return out.toString();
    }

    public Map<Long, Throwable> failures()
    {
        return new LinkedHashMap<Long, Throwable>(causes);
    }
}
