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

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.cert.X509NI;

/**
 * JNI binding for {@link X509NI} in the FIPS interface library.
 *
 * <p>JNI binds by a symbol derived from the CLASS name, so this class and
 * {@code X509ServiceJNI} reach different exports: the FIPS glue
 * ({@code interface/fips/jni/x509_fips_jni.c}) is the base
 * {@code x509_ni_jni.c} re-included under renamed exports, over a
 * {@code fips/util/x509.c} whose lib ctx accessor is spelled apart. Without
 * this class the FIPS provider drove the BASE library — which is how it was
 * first written, and it aborted the JVM on a FIPS-only run rather than
 * silently parsing in the wrong place.
 */
public class X509ServiceFIPSJNI implements X509NI
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

    /** FIPS library, so FIPS provider - see {@code DefaultServiceNI.providerName()}. */
    @Override
    public String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }
}
