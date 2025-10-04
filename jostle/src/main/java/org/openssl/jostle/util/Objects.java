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

public class Objects
{
    public static boolean areEqual(Object a, Object b)
    {
        return a == b || (null != a && a.equals(b));
    }

    public static int hashCode(Object obj)
    {
        return null == obj ? 0 : obj.hashCode();
    }
}
