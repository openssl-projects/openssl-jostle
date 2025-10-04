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
 * ArrayAccessException is thrown when the JNI layer was unable to obtain a valid pointer
 * to a java byte array even though that array was valid, that is not null.
 */
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
