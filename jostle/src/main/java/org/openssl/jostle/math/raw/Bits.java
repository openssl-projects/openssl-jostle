/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.math.raw;

public abstract class Bits
{
    public static int bitPermuteStep(int x, int m, int s)
    {
        int t = (x ^ (x >>> s)) & m;
        return  (t ^ (t <<  s)) ^ x;
    }

    public static long bitPermuteStep(long x, long m, int s)
    {
        long t = (x ^ (x >>> s)) & m;
        return   (t ^ (t <<  s)) ^ x;
    }

    public static int bitPermuteStepSimple(int x, int m, int s)
    {
        return ((x & m) << s) | ((x >>> s) & m);
    }

    public static long bitPermuteStepSimple(long x, long m, int s)
    {
        return ((x & m) << s) | ((x >>> s) & m);
    }
}
