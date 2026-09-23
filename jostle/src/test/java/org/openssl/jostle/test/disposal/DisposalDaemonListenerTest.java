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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.disposal.Disposable;
import org.openssl.jostle.disposal.DisposalDaemon;
import org.openssl.jostle.disposal.DisposalListener;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;

/**
 * The disposal daemon's event surface, driven with a fake {@link Disposable} so
 * no native handle is involved and the cells run on every unit leg.
 *
 * <p>The events are keyed by the handle VALUE because the referent is
 * unreachable by the time the phantom fires.
 */
public class DisposalDaemonListenerTest
{
    private final List<Recorder> added = new ArrayList<Recorder>();

    @AfterEach
    public void removeListeners()
    {
        for (Recorder r : added)
        {
            DisposalDaemon.removeListener(r);
        }
        added.clear();
    }

    private Recorder listen()
    {
        Recorder r = new Recorder();
        DisposalDaemon.addListener(r);
        added.add(r);
        return r;
    }

    /** A handle the daemon can key events on, with a disposer we control. */
    private static final class Fake implements Disposable
    {
        private final long reference;
        private final Runnable action;

        private Fake(long reference, Runnable action)
        {
            this.reference = reference;
            this.action = action;
        }

        @Override
        public Runnable getDisposeAction()
        {
            return action;
        }

        @Override
        public long getReference()
        {
            return reference;
        }

        @Override
        public String toString()
        {
            return "Fake(0x" + Long.toHexString(reference) + ")";
        }
    }

    private static final class Recorder implements DisposalListener
    {
        private final List<Long> registered = new CopyOnWriteArrayList<Long>();
        private final List<Long> disposing = new CopyOnWriteArrayList<Long>();
        private final List<Long> disposed = new CopyOnWriteArrayList<Long>();
        private final List<Long> failedRefs = new CopyOnWriteArrayList<Long>();
        private final List<Throwable> failures = new CopyOnWriteArrayList<Throwable>();

        public void registered(long ref, String label)
        {
            registered.add(ref);
        }

        public void disposing(long ref)
        {
            disposing.add(ref);
        }

        public void disposed(long ref)
        {
            disposed.add(ref);
        }

        public void failed(long ref, Throwable t)
        {
            failedRefs.add(ref);
            failures.add(t);
        }
    }

    private static boolean drain(final List<Long> seen, final long ref) throws InterruptedException
    {
        DisposalDrain.drain(new BooleanSupplier()
        {
            public boolean getAsBoolean()
            {
                return seen.contains(ref);
            }
        });
        return seen.contains(ref);
    }

    @Test
    public void aDroppedDisposableIsRegisteredThenDisposed() throws Exception
    {
        Recorder recorder = listen();
        long ref = 0x5150L;

        Disposable fake = new Fake(ref, new Runnable()
        {
            public void run()
            {
            }
        });
        DisposalDaemon.addDisposable(fake);

        Assertions.assertTrue(recorder.registered.contains(ref),
                "registered must fire before the referent is dropped");

        fake = null;
        Assertions.assertTrue(drain(recorder.disposed, ref),
                "the daemon did not dispose " + Long.toHexString(ref) + " within " + DisposalDrain.CAP
                        + " collection cycles");
        Assertions.assertTrue(recorder.disposing.contains(ref), "disposing did not fire");
        Assertions.assertTrue(recorder.failures.isEmpty(),
                "a clean disposer must produce no failed event");
    }

    /**
     * A disposer that throws must produce exactly one {@code failed} carrying the
     * Throwable, and must not stop the daemon: the second handle still disposes.
     * Before this, the daemon reduced the cause to {@code e.getMessage()}.
     */
    @Test
    public void aThrowingDisposerFailsOnceAndTheDaemonKeepsRunning() throws Exception
    {
        Recorder recorder = listen();
        long bad = 0xBADL;
        long good = 0x6000DL;
        final RuntimeException boom = new RuntimeException("disposer failed on purpose");

        Disposable thrower = new Fake(bad, new Runnable()
        {
            public void run()
            {
                throw boom;
            }
        });
        DisposalDaemon.addDisposable(thrower);
        thrower = null;

        Assertions.assertTrue(drain(recorder.failedRefs, bad),
                "no failed event for the throwing disposer");
        Assertions.assertEquals(1, Collections.frequency(recorder.failedRefs, bad),
                "expected exactly one failed event for " + Long.toHexString(bad));
        Assertions.assertSame(boom, recorder.failures.get(recorder.failedRefs.indexOf(bad)),
                "failed must carry the Throwable, not a message");
        Assertions.assertFalse(recorder.disposed.contains(bad),
                "a disposer that threw must not report disposed");

        Disposable survivor = new Fake(good, new Runnable()
        {
            public void run()
            {
            }
        });
        DisposalDaemon.addDisposable(survivor);
        survivor = null;

        Assertions.assertTrue(drain(recorder.disposed, good),
                "the daemon stopped after a disposer threw");
    }

    @Test
    public void aRemovedListenerStopsReceivingEvents() throws Exception
    {
        Recorder recorder = new Recorder();
        DisposalDaemon.addListener(recorder);
        DisposalDaemon.removeListener(recorder);

        Disposable fake = new Fake(0xDEADL, new Runnable()
        {
            public void run()
            {
            }
        });
        DisposalDaemon.addDisposable(fake);

        Assertions.assertTrue(recorder.registered.isEmpty(),
                "a removed listener still received registered");
    }

    /** Registering must move the pending count; a count that never moves measures nothing. */
    @Test
    public void pendingCountsRegistrationsNotYetFired() throws Exception
    {
        int before = DisposalDaemon.pending();

        Disposable fake = new Fake(0x9E4DL, new Runnable()
        {
            public void run()
            {
            }
        });
        DisposalDaemon.addDisposable(fake);

        Assertions.assertTrue(DisposalDaemon.pending() > before,
                "pending did not move when a disposable was registered");
        fake = null;
    }
}
