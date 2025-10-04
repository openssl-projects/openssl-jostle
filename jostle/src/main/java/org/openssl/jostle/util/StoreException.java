/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util;

/**
 * Exception thrown if there's an issue doing a match in store.
 */
public class StoreException
    extends RuntimeException
{
    private final Throwable _e;

    /**
     * Basic Constructor.
     *
     * @param msg message to be associated with this exception.
     * @param cause the throwable that caused this exception to be raised.
     */
    public StoreException(String msg, Throwable cause)
    {
        super(msg);
        _e = cause;
    }

    public Throwable getCause()
    {
        return _e;
    }
}
