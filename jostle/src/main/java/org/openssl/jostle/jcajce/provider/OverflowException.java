/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider;

/**
 * Thrown when the native layer reports that an internal value will exceed the max positive value
 * of a 32bit signed integer.
 */
public class OverflowException extends RuntimeException
{
    public OverflowException()
    {
    }

    public OverflowException(String message)
    {
        super(message);
    }

    public OverflowException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public OverflowException(Throwable cause)
    {
        super(cause);
    }

    public OverflowException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
