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

package org.openssl.jostle.jcajce.provider.certpath;

/**
 * JNI binding for {@link CertPathNI}. Native methods link to
 * {@code interface/nonfips/jni/certpath_ni_jni.c} by name.
 */
public class CertPathServiceJNI implements CertPathNI
{
    @Override
    public native int ni_verify(byte[] der, int[] sizes, int count, int anchorCount,
                                long timeSecs, int strict, byte[] chainOut, int[] outInfo);
}
