/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.disposal;

/**
 * Observes the disposal of native handles.
 *
 * <p>Events are keyed by the HANDLE VALUE, captured at registration, because the
 * referent is unreachable by the time the phantom fires.
 *
 * <p>{@link #registered} is called on the thread that registers the handle, so
 * on any application thread constructing a native reference.
 * {@link #disposing}, {@link #disposed} and {@link #failed} are called on the
 * disposal daemon thread, on the cleanup executor when a cleanup delay is
 * configured, or on the shutdown hook thread at exit. An implementation must not
 * block and must not assume a thread. A listener that throws is logged and
 * ignored: it cannot stop a handle being freed.
 */
public interface DisposalListener
{
    /** The handle was registered for disposal. */
    void registered(long ref, String label);

    /** The disposer is about to run. */
    void disposing(long ref);

    /** The disposer returned normally. */
    void disposed(long ref);

    /** The disposer threw. The handle may not have been freed. */
    void failed(long ref, Throwable t);
}
