/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.util.test;

/**
 * Parsing
 */
public final class NumberParsing
{
    private NumberParsing() 
    {
        // Hide constructor
    }
    
    public static long decodeLongFromHex(String longAsString) 
    {
        if ((longAsString.charAt(1) == 'x')
            || (longAsString.charAt(1) == 'X'))
        {
            return Long.parseLong(longAsString.substring(2), 16);
        }

        return Long.parseLong(longAsString, 16);
    }
    
    public static int decodeIntFromHex(String intAsString)
    {
        if ((intAsString.charAt(1) == 'x')
            || (intAsString.charAt(1) == 'X'))
        {
            return Integer.parseInt(intAsString.substring(2), 16);
        }

        return Integer.parseInt(intAsString, 16);
    }
}
