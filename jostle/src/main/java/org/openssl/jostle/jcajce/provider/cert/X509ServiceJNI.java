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

package org.openssl.jostle.jcajce.provider.cert;

/**
 * JNI binding for {@link X509NI}. Native methods link to
 * {@code interface/nonfips/jni/x509_ni_jni.c} by name.
 */
public class X509ServiceJNI implements X509NI
{
    @Override
    public native long ni_allocate(byte[] der, int off, int len, int maxBytes, int[] consumed, int[] err);

    @Override
    public native int ni_fieldsLen(long ref);

    @Override
    public native int ni_fields(long ref, byte[] blob, int[] sizes, int[] info);

    @Override
    public native int ni_extensionsLen(long ref);

    @Override
    public native int ni_extensions(long ref, byte[] blob, int[] oidSizes, int[] valSizes, int[] critical);

    @Override
    public native void ni_dispose(long ref);

    @Override
    public native long ni_allocateCrl(byte[] der, int off, int len, int maxBytes, int[] consumed, int[] err);

    @Override
    public native int ni_crlFieldsLen(long ref);

    @Override
    public native int ni_crlFields(long ref, byte[] blob, int[] sizes, int[] info);

    @Override
    public native int ni_crlExtensionsLen(long ref);

    @Override
    public native int ni_crlExtensions(long ref, byte[] blob, int[] oidSizes, int[] valSizes, int[] critical);

    @Override
    public native int ni_crlEntriesLen(long ref);

    @Override
    public native int ni_crlEntries(long ref, byte[] blob, int[] sizes, int[] dates);

    @Override
    public native void ni_disposeCrl(long ref);
}
