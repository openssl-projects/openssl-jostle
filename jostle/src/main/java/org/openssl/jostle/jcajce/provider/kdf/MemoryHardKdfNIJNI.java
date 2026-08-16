/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.kdf;

/**
 * JNI bridge for the memory-hard KDFs. Its exports live only in the base
 * (non-FIPS) interface library — see {@link MemoryHardKdfNI}. There is no
 * FIPS counterpart class, so no {@code _fips_jni} rename wrapper exists for
 * these entry points.
 */
public class MemoryHardKdfNIJNI implements MemoryHardKdfNI
{
    @Override
    public native int scrypt(byte[] password, byte[] salt, int n, int r, int p, byte[] out, int outOffset, int outLen);

    @Override
    public native int argon2(byte[] password, byte[] salt, int type, int version, int iterations,
                             int memoryKiB, int lanes, byte[] out, int outOffset, int outLen);
}
