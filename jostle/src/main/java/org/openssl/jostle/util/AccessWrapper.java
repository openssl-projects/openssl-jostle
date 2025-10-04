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

import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * After java 17 AccessController.doPrivileged is slated for removal.
 * This abstracts that away for 17 and later versions
 */
public class AccessWrapper
{
    public static <T> T doAction(AccessSupplier<T> pa) throws AccessException
    {

        try
        {
            return AccessController.doPrivileged(new PrivilegedAction<T>()
            {
                public T run()
                {
                    return pa.run();
                }
            });
        } catch (Throwable t)
        {
            throw new AccessException(t.getMessage(), t);
        }
    }
}
