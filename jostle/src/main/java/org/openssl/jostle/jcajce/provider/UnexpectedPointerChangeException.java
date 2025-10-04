/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

/**
 * On the native side some functions accept pointers and will return the same pointer or null.
 * This exception is thrown then the native layer reports the returned pointer was not null but different
 * to the passed in pointer.
 *
 */
public class UnexpectedPointerChangeException extends RuntimeException
{
    public UnexpectedPointerChangeException()
    {
    }

    public UnexpectedPointerChangeException(String message)
    {
        super(message);
    }

    public UnexpectedPointerChangeException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public UnexpectedPointerChangeException(Throwable cause)
    {
        super(cause);
    }

    public UnexpectedPointerChangeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
