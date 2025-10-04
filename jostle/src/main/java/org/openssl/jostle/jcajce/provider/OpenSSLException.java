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
 * Runtime exception wrapping an OpenSSL Error string
 */
public class OpenSSLException extends RuntimeException
{
    public OpenSSLException()
    {
    }

    public OpenSSLException(String message)
    {
        super(message);
    }

    public OpenSSLException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public OpenSSLException(Throwable cause)
    {
        super(cause);
    }

    public OpenSSLException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
