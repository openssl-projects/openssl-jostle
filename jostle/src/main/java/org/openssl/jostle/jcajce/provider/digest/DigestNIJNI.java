/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.digest;

/**
 * JNI-backed implementation of {@link DigestNI}.
 * <p>
 * This class declares native methods only; the actual implementations live in
 * the JNI native library (e.g. libinterface_jni). Use this on runtimes or
 * platforms where the FFM/FFI path is unavailable.
 */
public class DigestNIJNI implements DigestNI
{
    /** Create a native digest context; see {@link DigestNI#makeInstance(String)}. */
    @Override
    public native long makeInstance(String canonicalAlgName);

    /** Update digest; see {@link DigestNI#update(long, byte[], int, int)}. */
    @Override
    public native int update(long ref, byte[] in, int inOff, int inLen);

    /** Finalize digest; see {@link DigestNI#doFinal(long, byte[], int)}. */
    @Override
    public native int doFinal(long ref, byte[] out, int outOff);

    /** Get digest length; see {@link DigestNI#getDigestLength(long)}. */
    @Override
    public native int getDigestLength(long ref);

    /** Reset context; see {@link DigestNI#reset(long)}. */
    @Override
    public native void reset(long ref);

    /** Free context; see {@link DigestNI#dispose(long)}. */
    @Override
    public native void dispose(long ref);

    @Override
    public native long copy(long ref);
}
