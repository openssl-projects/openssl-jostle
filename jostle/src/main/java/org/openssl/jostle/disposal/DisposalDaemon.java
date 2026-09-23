/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.disposal;

import org.openssl.jostle.util.Properties;

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DisposalDaemon
        implements Runnable
{
    private static final Logger LOG = Logger.getLogger(DisposalDaemon.class.getName());

    private static ReferenceQueue<Disposable> referenceQueue = new ReferenceQueue<Disposable>();

    private static Set<ReferenceWrapperWithDisposerRunnable> refs =
            Collections.synchronizedSet(new HashSet<ReferenceWrapperWithDisposerRunnable>());

    private static AtomicLong ctr = new AtomicLong(Long.MIN_VALUE);

    private static final ScheduledExecutorService cleanupExecutor;
    private static final DisposalDaemon disposalDaemon = new DisposalDaemon();
    private static final Thread disposalThread;

    /** With no listener registered the hot path pays one volatile read and nothing else. */
    private static final CopyOnWriteArrayList<DisposalListener> listeners =
            new CopyOnWriteArrayList<DisposalListener>();

    private static final long cleanupDelay;
    private static final String CLEANUP_DELAY_PROP = "org.openssl.jostle.native.cleanup_delay";


    static
    {
        cleanupDelay = Properties.asInteger(CLEANUP_DELAY_PROP, 0);

        //
        // Clean up executor accepts references that are no longer needed
        // and disposes of them in turn.
        //
        if (cleanupDelay > 0)
        {
            cleanupExecutor = Executors.newSingleThreadScheduledExecutor(new ThreadFactory()
            {
                @Override
                public Thread newThread(Runnable r)
                {
                    Thread t = new Thread(r, "JSL Cleanup Executor");
                    t.setDaemon(true);
                    return t;
                }
            });
        }
        else
        {
            cleanupExecutor = null;
        }

        //
        // Sets up the daemon thread that deals with items on the reference
        // queue that may have native code that needs disposing.
        //
        disposalThread = new Thread(disposalDaemon, "JSL Disposal Daemon");
        disposalThread.setDaemon(true);
        disposalThread.start();

        addShutdownHook();
    }

    private static void addShutdownHook()
    {
        //
        // On shutdown clean up the reference queue.
        //
        try
        {
            Runtime.getRuntime().addShutdownHook(new Thread()
            {
                @Override
                public void run()
                {
                    if (LOG.isLoggable(Level.FINE))
                    {
                        LOG.fine("Shutdown hook started");
                    }
                    ReferenceWrapperWithDisposerRunnable item =
                            (ReferenceWrapperWithDisposerRunnable) referenceQueue.poll();
                    while (item != null)
                    {
                        refs.remove(item);
                        disposeAndReport(item);

                        if (LOG.isLoggable(Level.FINE))
                        {
                            LOG.fine("Shutdown hook disposed: " + item);
                        }

                        item = (ReferenceWrapperWithDisposerRunnable) referenceQueue.poll();
                    }

                }
            });
        }
        catch (Throwable ex)
        {
            LOG.log(Level.WARNING, "Adding shutdown hook failed.", ex);
        }
    }

    /** Adds a listener. Duplicates are permitted; each is called once per add. */
    public static void addListener(DisposalListener listener)
    {
        if (listener == null)
        {
            throw new NullPointerException("listener cannot be null");
        }
        listeners.add(listener);
    }

    /** Removes one occurrence of the listener. Unknown listeners are ignored. */
    public static void removeListener(DisposalListener listener)
    {
        listeners.remove(listener);
    }

    /** Handles registered and not yet taken off the queue by the daemon. */
    public static int pending()
    {
        return refs.size();
    }

    // A listener that throws must not stop a handle being freed, nor kill the
    // daemon thread.
    private static void fireRegistered(long ref, String label)
    {
        for (DisposalListener l : listeners)
        {
            try
            {
                l.registered(ref, label);
            }
            catch (Throwable t)
            {
                LOG.log(Level.WARNING, "disposal listener threw on registered", t);
            }
        }
    }

    private static void fireDisposing(long ref)
    {
        for (DisposalListener l : listeners)
        {
            try
            {
                l.disposing(ref);
            }
            catch (Throwable t)
            {
                LOG.log(Level.WARNING, "disposal listener threw on disposing", t);
            }
        }
    }

    private static void fireDisposed(long ref)
    {
        for (DisposalListener l : listeners)
        {
            try
            {
                l.disposed(ref);
            }
            catch (Throwable t)
            {
                LOG.log(Level.WARNING, "disposal listener threw on disposed", t);
            }
        }
    }

    private static void fireFailed(long ref, Throwable cause)
    {
        for (DisposalListener l : listeners)
        {
            try
            {
                l.failed(ref, cause);
            }
            catch (Throwable t)
            {
                LOG.log(Level.WARNING, "disposal listener threw on failed", t);
            }
        }
    }

    /**
     * Runs the disposer and reports the outcome. A disposer that throws yields
     * exactly one {@code failed} and the daemon keeps running; the warning
     * carries the Throwable, so the cause is not reduced to a message.
     */
    private static void disposeAndReport(ReferenceWrapperWithDisposerRunnable item)
    {
        fireDisposing(item.getReference());
        try
        {
            item.dispose();
            fireDisposed(item.getReference());
        }
        catch (Throwable t)
        {
            LOG.log(Level.WARNING, "exception disposing " + item, t);
            fireFailed(item.getReference(), t);
        }
    }

    public static void addDisposable(Disposable disposable)
    {
        ReferenceWrapperWithDisposerRunnable ref = new ReferenceWrapperWithDisposerRunnable(disposable, referenceQueue);
        refs.add(ref);
        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine("Registered: " + disposable.toString());
        }
        fireRegistered(ref.reference, ref.label);
    }

    public void run()
    {
        for (; ; )
        {
            try
            {
                final ReferenceWrapperWithDisposerRunnable item =
                        (ReferenceWrapperWithDisposerRunnable) referenceQueue.remove();
                refs.remove(item);

                if (cleanupExecutor == null)
                {
                    if (LOG.isLoggable(Level.FINE))
                    {
                        LOG.fine("Disposed: " + item);
                    }
                    disposeAndReport(item);
                }
                else
                {
                    //
                    // Delay in order to avoid freeing a reference that the GC has
                    // decided is unreachable concurrently with its last use.
                    //
                    cleanupExecutor.schedule(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            if (LOG.isLoggable(Level.FINE))
                            {
                                LOG.fine("Disposed: " + item);
                            }
                            disposeAndReport(item);
                        }
                    }, cleanupDelay, TimeUnit.MILLISECONDS);
                }

            }
            catch (InterruptedException iex)
            {
                Thread.currentThread().interrupt();
            }
            catch (Throwable e)
            {
                LOG.log(Level.WARNING, "exception in disposal thread", e);
            }
        }
    }

    private static class ReferenceWrapperWithDisposerRunnable
            extends PhantomReference<Disposable>
    {

        private final Runnable disposer;
        private final String label;

        // The referent is unreachable when the phantom fires, so the handle is
        // captured here, like the label.
        private final long reference;

        /**
         * Creates a new phantom reference that refers to the given object and
         * is registered with the given queue.
         *
         * <p> It is possible to create a phantom reference with a <tt>null</tt>
         * queue, but such a reference is completely useless: Its <tt>get</tt>
         * method will always return null and, since it does not have a queue, it
         * will never be enqueued.
         *
         * @param referent the object the new phantom reference will refer to
         * @param q        the queue with which the reference is to be registered,
         *                 or <tt>null</tt> if registration is not required
         */
        public ReferenceWrapperWithDisposerRunnable(Disposable referent, ReferenceQueue<? super Disposable> q)
        {
            super(referent, q);
            this.label = referent.toString(); // capture label from referent
            this.reference = referent.getReference();
            this.disposer = referent.getDisposeAction();
        }

        public long getReference()
        {
            return reference;
        }

        public void dispose()
        {
            disposer.run();
        }

        public String toString()
        {
            return label;
        }
    }
}