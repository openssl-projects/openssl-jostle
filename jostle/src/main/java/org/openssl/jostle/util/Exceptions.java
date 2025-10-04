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

import java.io.IOException;

public class Exceptions
{
    public static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new IllegalArgumentException(message, cause);
    }

    public static IllegalStateException illegalStateException(String message, Throwable cause)
    {
        return new IllegalStateException(message, cause);
    }

    public static IOException ioException(String message, Throwable cause)
    {
        return new IOException(message, cause);
    }

}
