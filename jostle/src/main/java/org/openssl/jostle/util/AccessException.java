/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.util;

public class AccessException extends RuntimeException
{
    public AccessException()
    {
    }

    public AccessException(String message)
    {
        super(message);
    }

    public AccessException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public AccessException(Throwable cause)
    {
        super(cause);
    }

    public AccessException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
